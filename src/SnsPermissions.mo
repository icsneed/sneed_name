import Principal "mo:base/Principal";
import Result "mo:base/Result";
import Map "mo:map/Map";
import Text "mo:base/Text";
import Nat64 "mo:base/Nat64";
import Nat32 "mo:base/Nat32";
import Time "mo:base/Time";
import Permissions "./Permissions";
import Dedup "mo:dedup";

module {
    public type SnsPermissionSettings = {
        // Minimum voting power required for this permission
        min_voting_power : Nat64;
        // Maximum expiration duration for dynamically granted permissions
        max_duration : ?Nat64;
        // Default duration for dynamically granted permissions
        default_duration : ?Nat64;
    };

    // Stable state for SNS-specific settings
    public type StableSnsState = {
        var permission_settings : Map.Map<Nat32, SnsPermissionSettings>;  // Permission index -> Settings
    };

    public type SnsState = {
        permission_settings : Map.Map<Nat32, SnsPermissionSettings>;
        permissions : Permissions.PermissionsManager;
        dedup : Dedup.Dedup;
    };

    public func empty_stable() : StableSnsState {
        {
            var permission_settings = Map.new<Nat32, SnsPermissionSettings>();
        }
    };

    public func from_stable(
        stable_state : StableSnsState,
        permissions : Permissions.PermissionsManager,
        dedup : Dedup.Dedup
    ) : SnsState {
        {
            permission_settings = stable_state.permission_settings;
            permissions = permissions;
            dedup = dedup;
        }
    };

    // Interface for interacting with SNS governance canister
    public type Neuron = {
        id : ?Nat64;
        controller : ?Principal;
        hot_keys : [Principal];
        voting_power : Nat64;
    };

    public type SnsGovernanceCanister = actor {
        list_neurons : shared query (caller : Principal) -> async [Neuron];
    };

    // Helper function to convert text to index
    private func text_to_index(text : Text, dedup : Dedup.Dedup) : Nat32 {
        let blob = Text.encodeUtf8(text);
        dedup.getOrCreateIndex(blob);
    };

    public class SnsPermissions(state : SnsState) {
        // Helper to get total voting power for a principal's hotkey access in an SNS
        private func get_voting_power(
            principal : Principal,
            sns_governance : SnsGovernanceCanister
        ) : async Nat64 {
            var total_power : Nat64 = 0;
            let neurons = await sns_governance.list_neurons(principal);
            
            for (neuron in neurons.vals()) {
                // Only include voting power if principal is a hotkey
                for (hot_key in neuron.hot_keys.vals()) {
                    if (Principal.equal(hot_key, principal)) {
                        total_power += neuron.voting_power;
                    };
                };
            };
            total_power
        };

        // Check if principal has sufficient voting power for a permission
        public func check_sns_permission(
            principal : Principal,
            permission : Text,
            sns_governance : SnsGovernanceCanister
        ) : async Bool {
            // First check explicit permissions
            if (state.permissions.check_permission(principal, permission)) {
                return true;
            };

            // Then check SNS voting power
            let permission_index = text_to_index(permission, state.dedup);
            switch (Map.get(state.permission_settings, (func (n : Nat32) : Nat32 { n }, Nat32.equal), permission_index)) {
                case (?settings) {
                    let voting_power = await get_voting_power(principal, sns_governance);
                    voting_power >= settings.min_voting_power
                };
                case null { false };
            };
        };

        // Set permission settings for SNS-based access
        public func set_permission_settings(
            caller : Principal,
            permission : Text,
            settings : SnsPermissionSettings
        ) : Result.Result<(), Text> {
            if (not state.permissions.is_admin(caller)) {
                return #err("Not authorized");
            };

            let permission_index = text_to_index(permission, state.dedup);
            Map.set(
                state.permission_settings,
                (func (n : Nat32) : Nat32 { n }, Nat32.equal),
                permission_index,
                settings
            );
            #ok(());
        };

        // Get current settings for a permission
        public func get_permission_settings(permission : Text) : ?SnsPermissionSettings {
            let permission_index = text_to_index(permission, state.dedup);
            Map.get(
                state.permission_settings,
                (func (n : Nat32) : Nat32 { n }, Nat32.equal),
                permission_index
            );
        };

        // Delegate other permission management to base class
        public func grant_permission(
            caller : Principal,
            target : Principal,
            permission : Text,
            expires_at : ?Nat64
        ) : Result.Result<(), Text> {
            state.permissions.grant_permission(caller, target, permission, expires_at);
        };

        public func revoke_permission(
            caller : Principal,
            target : Principal,
            permission : Text
        ) : Result.Result<(), Text> {
            state.permissions.revoke_permission(caller, target, permission);
        };

        public func cleanup_expired() {
            state.permissions.cleanup_expired();
        };
    };
}
