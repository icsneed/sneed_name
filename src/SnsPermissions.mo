import Principal "mo:base/Principal";
import Result "mo:base/Result";
import Map "mo:map/Map";
import Text "mo:base/Text";
import Nat64 "mo:base/Nat64";
import Nat32 "mo:base/Nat32";
import Nat8 "mo:base/Nat8";
import Time "mo:base/Time";
import Permissions "./Permissions";
import Dedup "mo:dedup";
import Blob "mo:base/Blob";
import T "Types";

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
        var neuron_names : Map.Map<Nat32, T.Name>;  // Neuron ID index -> Name
    };

    public type SnsState = {
        permission_settings : Map.Map<Nat32, SnsPermissionSettings>;
        neuron_names : Map.Map<Nat32, T.Name>;
        permissions : Permissions.PermissionsManager;
        dedup : Dedup.Dedup;
    };

    public func empty_stable() : StableSnsState {
        {
            var permission_settings = Map.new<Nat32, SnsPermissionSettings>();
            var neuron_names = Map.new<Nat32, T.Name>();
        }
    };

    public func from_stable(
        stable_state : StableSnsState,
        permissions : Permissions.PermissionsManager,
        dedup : Dedup.Dedup
    ) : SnsState {
        {
            permission_settings = stable_state.permission_settings;
            neuron_names = stable_state.neuron_names;
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

        // Helper to check if caller has access to neuron
        private func has_neuron_access(
            caller : Principal,
            neuron_id : Nat64,
            sns_governance : SnsGovernanceCanister
        ) : async Bool {
            let neurons = await sns_governance.list_neurons(caller);
            for (neuron in neurons.vals()) {
                switch (neuron.id) {
                    case (?id) {
                        if (id == neuron_id) {
                            // Check if caller is a hotkey
                            for (hot_key in neuron.hot_keys.vals()) {
                                if (Principal.equal(hot_key, caller)) {
                                    return true;
                                };
                            };
                        };
                    };
                    case null {};
                };
            };
            false
        };

        // Set name for a neuron
        public func set_sns_neuron_name(
            caller : Principal,
            neuron_id : Nat64,
            name : Text,
            sns_governance : SnsGovernanceCanister
        ) : async Result.Result<(), Text> {
            // Check if caller has access to the neuron
            if (not (await has_neuron_access(caller, neuron_id, sns_governance))) {
                return #err("Not authorized: caller is not a hotkey for this neuron");
            };

            let now = Nat64.fromIntWrap(Time.now());
            let neuron_index = state.dedup.getOrCreateIndex(Blob.fromArray(nat64ToBytes(neuron_id)));
            
            // Create or update name record
            let name_record = switch (Map.get(state.neuron_names, (func (n : Nat32) : Nat32 { n }, Nat32.equal), neuron_index)) {
                case (?existing) {
                    {
                        name = name;
                        verified = existing.verified;  // Preserve verified status
                        created = existing.created;
                        updated = now;
                        created_by = existing.created_by;
                        updated_by = caller;
                    }
                };
                case null {
                    {
                        name = name;
                        verified = false;  // New names start unverified
                        created = now;
                        updated = now;
                        created_by = caller;
                        updated_by = caller;
                    }
                };
            };

            Map.set(state.neuron_names, (func (n : Nat32) : Nat32 { n }, Nat32.equal), neuron_index, name_record);
            #ok(());
        };

        // Get name for a neuron
        public func get_sns_neuron_name(neuron_id : Nat64) : ?T.Name {
            let neuron_index = state.dedup.getOrCreateIndex(Blob.fromArray(nat64ToBytes(neuron_id)));
            Map.get(state.neuron_names, (func (n : Nat32) : Nat32 { n }, Nat32.equal), neuron_index);
        };

        // Remove name for a neuron
        public func remove_sns_neuron_name(
            caller : Principal,
            neuron_id : Nat64,
            sns_governance : SnsGovernanceCanister
        ) : async Result.Result<(), Text> {
            // Check if caller has access to the neuron
            if (not (await has_neuron_access(caller, neuron_id, sns_governance))) {
                return #err("Not authorized: caller is not a hotkey for this neuron");
            };

            let neuron_index = state.dedup.getOrCreateIndex(Blob.fromArray(nat64ToBytes(neuron_id)));
            Map.delete(state.neuron_names, (func (n : Nat32) : Nat32 { n }, Nat32.equal), neuron_index);
            #ok(());
        };

        // Helper function to convert Nat64 to [Nat8]
        private func nat64ToBytes(n : Nat64) : [Nat8] {
            [
                Nat8.fromNat(Nat64.toNat((n >> 56) & 0xFF)),
                Nat8.fromNat(Nat64.toNat((n >> 48) & 0xFF)),
                Nat8.fromNat(Nat64.toNat((n >> 40) & 0xFF)),
                Nat8.fromNat(Nat64.toNat((n >> 32) & 0xFF)),
                Nat8.fromNat(Nat64.toNat((n >> 24) & 0xFF)),
                Nat8.fromNat(Nat64.toNat((n >> 16) & 0xFF)),
                Nat8.fromNat(Nat64.toNat((n >> 8) & 0xFF)),
                Nat8.fromNat(Nat64.toNat(n & 0xFF))
            ]
        };
    };
}
