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
import Buffer "mo:base/Buffer";

module {
    // Permission type constants
    public let SET_SNS_NEURON_NAME_PERMISSION = "set_sns_neuron_name";
    public let REMOVE_SNS_NEURON_NAME_PERMISSION = "remove_sns_neuron_name";

    public type NeuronId = { id : Blob };

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
        var permission_settings : Map.Map<Nat32, Map.Map<Nat32, SnsPermissionSettings>>;  // SNS governance index -> (Permission index -> Settings)
        var neuron_names : Map.Map<Nat32, T.Name>;  // Neuron ID index -> Name
    };

    public type SnsState = {
        permission_settings : Map.Map<Nat32, Map.Map<Nat32, SnsPermissionSettings>>;
        neuron_names : Map.Map<Nat32, T.Name>;
        permissions : Permissions.PermissionsManager;
        dedup : Dedup.Dedup;
    };

    public func empty_stable() : StableSnsState {
        {
            var permission_settings = Map.new<Nat32, Map.Map<Nat32, SnsPermissionSettings>>();
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

    public type DissolveState = {
        #DissolveDelaySeconds : Nat64;
        #WhenDissolvedTimestampSeconds : Nat64;
    };

    public type NeuronPermission = {
        principal : ?Principal;
        permission_type : [Int32];
    };

    public type DisburseMaturityInProgress = {
        timestamp_of_disbursement_seconds : Nat64;
        amount_e8s : Nat64;
        account_to_disburse_to : ?Account;
        finalize_disbursement_timestamp_seconds : ?Nat64;
    };

    public type Account = {
        owner : Principal;
        subaccount : ?Blob;
    };

    public type Followees = { followees : [NeuronId] };

    public type Neuron = {
        id : ?NeuronId;
        staked_maturity_e8s_equivalent : ?Nat64;
        permissions : [NeuronPermission];
        maturity_e8s_equivalent : Nat64;
        cached_neuron_stake_e8s : Nat64;
        created_timestamp_seconds : Nat64;
        source_nns_neuron_id : ?Nat64;
        auto_stake_maturity : ?Bool;
        aging_since_timestamp_seconds : Nat64;
        dissolve_state : ?DissolveState;
        voting_power_percentage_multiplier : Nat64;
        vesting_period_seconds : ?Nat64;
        disburse_maturity_in_progress : [DisburseMaturityInProgress];
        followees : [(Nat64, Followees)];
        neuron_fees_e8s : Nat64;
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
                // Only include voting power if principal has permission
                for (permission in neuron.permissions.vals()) {
                    switch (permission.principal) {
                        case (?p) {
                            if (Principal.equal(p, principal)) {
                                // Voting power is stake * multiplier
                                total_power += neuron.cached_neuron_stake_e8s * neuron.voting_power_percentage_multiplier / 100;
                            };
                        };
                        case null {};
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
            let sns_index = state.dedup.getOrCreateIndexForPrincipal(Principal.fromActor(sns_governance));
            let permission_index = text_to_index(permission, state.dedup);

            switch (Map.get(state.permission_settings, (func (n : Nat32) : Nat32 { n }, Nat32.equal), sns_index)) {
                case (?sns_settings) {
                    switch (Map.get(sns_settings, (func (n : Nat32) : Nat32 { n }, Nat32.equal), permission_index)) {
                        case (?settings) {
                            let voting_power = await get_voting_power(principal, sns_governance);
                            voting_power >= settings.min_voting_power
                        };
                        case null { false };
                    };
                };
                case null { false };
            };
        };

        // Set permission settings for SNS-based access
        public func set_permission_settings(
            caller : Principal,
            sns_governance : Principal,
            permission : Text,
            settings : SnsPermissionSettings
        ) : Result.Result<(), Text> {
            if (not state.permissions.is_admin(caller)) {
                return #err("Not authorized");
            };

            let sns_index = state.dedup.getOrCreateIndexForPrincipal(sns_governance);
            let permission_index = text_to_index(permission, state.dedup);

            // Get or create settings map for this SNS
            let sns_settings = switch (Map.get(state.permission_settings, (func (n : Nat32) : Nat32 { n }, Nat32.equal), sns_index)) {
                case (?existing) { existing };
                case null {
                    let new_map = Map.new<Nat32, SnsPermissionSettings>();
                    Map.set(
                        state.permission_settings,
                        (func (n : Nat32) : Nat32 { n }, Nat32.equal),
                        sns_index,
                        new_map
                    );
                    new_map;
                };
            };

            // Set settings for this permission type
            Map.set(
                sns_settings,
                (func (n : Nat32) : Nat32 { n }, Nat32.equal),
                permission_index,
                settings
            );
            #ok(());
        };

        // Get current settings for a permission
        public func get_permission_settings(
            sns_governance : Principal,
            permission : Text
        ) : ?SnsPermissionSettings {
            let sns_index = state.dedup.getOrCreateIndexForPrincipal(sns_governance);
            let permission_index = text_to_index(permission, state.dedup);

            switch (Map.get(state.permission_settings, (func (n : Nat32) : Nat32 { n }, Nat32.equal), sns_index)) {
                case (?sns_settings) {
                    Map.get(
                        sns_settings,
                        (func (n : Nat32) : Nat32 { n }, Nat32.equal),
                        permission_index
                    );
                };
                case null { null };
            };
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
            neuron_id : NeuronId,
            sns_governance : SnsGovernanceCanister
        ) : async Bool {
            let neurons = await sns_governance.list_neurons(caller);
            for (neuron in neurons.vals()) {
                switch (neuron.id) {
                    case (?id) {
                        if (Blob.equal(id.id, neuron_id.id)) {
                            // Check if caller has permission in this neuron
                            for (permission in neuron.permissions.vals()) {
                                switch (permission.principal) {
                                    case (?p) {
                                        if (Principal.equal(p, caller)) {
                                            return true;
                                        };
                                    };
                                    case null {};
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
            neuron_id : NeuronId,
            name : Text,
            sns_governance : SnsGovernanceCanister
        ) : async Result.Result<(), Text> {
            // First check if caller has general set permission
            if (not state.permissions.check_permission(caller, SET_SNS_NEURON_NAME_PERMISSION)) {
                // Fall back to checking specific neuron access
                if (not (await has_neuron_access(caller, neuron_id, sns_governance))) {
                    return #err("Not authorized: caller must have set_sns_neuron_name permission or be a hotkey for this neuron");
                };
            };

            let now = Nat64.fromIntWrap(Time.now());
            let neuron_index = state.dedup.getOrCreateIndex(neuron_id.id);
            
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
        public func get_sns_neuron_name(neuron_id : NeuronId) : ?T.Name {
            let neuron_index = state.dedup.getOrCreateIndex(neuron_id.id);
            Map.get(state.neuron_names, (func (n : Nat32) : Nat32 { n }, Nat32.equal), neuron_index);
        };

        // Remove name for a neuron
        public func remove_sns_neuron_name(
            caller : Principal,
            neuron_id : NeuronId,
            sns_governance : SnsGovernanceCanister
        ) : async Result.Result<(), Text> {
            // First check if caller has general remove permission
            if (not state.permissions.check_permission(caller, REMOVE_SNS_NEURON_NAME_PERMISSION)) {
                // Fall back to checking specific neuron access
                if (not (await has_neuron_access(caller, neuron_id, sns_governance))) {
                    return #err("Not authorized: caller must have remove_sns_neuron_name permission or be a hotkey for this neuron");
                };
            };

            let neuron_index = state.dedup.getOrCreateIndex(neuron_id.id);
            Map.delete(state.neuron_names, (func (n : Nat32) : Nat32 { n }, Nat32.equal), neuron_index);
            #ok(());
        };

        // Helper to find all neurons where caller has hotkey access
        public func find_hotkeyed_neurons(
            caller : Principal,
            sns_governance : SnsGovernanceCanister
        ) : async [Neuron] {
            await sns_governance.list_neurons(caller);
        };

        // Helper to find owner principals from a list of neurons
        public func find_reachable_principals(neurons : [Neuron]) : [Principal] {
            let owners = Buffer.Buffer<Principal>(neurons.size());
            let seen = Map.new<Principal, ()>();
            let utils = (Principal.hash, Principal.equal);

            for (neuron in neurons.vals()) {
                // Find principal with most permissions in this neuron
                var max_permissions = 0;
                var owner : ?Principal = null;
                
                for (permission in neuron.permissions.vals()) {
                    switch (permission.principal) {
                        case (?p) {
                            let perm_count = permission.permission_type.size();
                            if (perm_count > max_permissions) {
                                max_permissions := perm_count;
                                owner := ?p;
                            };
                        };
                        case null {};
                    };
                };

                // Add owner to result if not seen before
                switch (owner) {
                    case (?p) {
                        switch (Map.get(seen, utils, p)) {
                            case null {
                                Map.set(seen, utils, p, ());
                                owners.add(p);
                            };
                            case (?_) {};
                        };
                    };
                    case null {};
                };
            };
            
            Buffer.toArray(owners)
        };

        // Helper to find all neurons reachable through a list of principals
        public func find_reachable_neurons(
            principals : [Principal],
            sns_governance : SnsGovernanceCanister
        ) : async [Neuron] {
            let all_neurons = Buffer.Buffer<Neuron>(0);
            let seen_ids = Map.new<Blob, ()>();
            let utils = (Blob.hash, Blob.equal);
            
            for (principal in principals.vals()) {
                let neurons = await sns_governance.list_neurons(principal);
                
                for (neuron in neurons.vals()) {
                    switch (neuron.id) {
                        case (?id) {
                            // Only add if we haven't seen this neuron ID before
                            switch (Map.get(seen_ids, utils, id.id)) {
                                case null {
                                    Map.set(seen_ids, utils, id.id, ());
                                    all_neurons.add(neuron);
                                };
                                case (?_) {};
                            };
                        };
                        case null {};
                    };
                };
            };
            
            Buffer.toArray(all_neurons)
        };
    };
}
