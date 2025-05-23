import Map "mo:map/Map";
import Dedup "mo:dedup";
import T "Types";
import Nat32 "mo:base/Nat32";
import Text "mo:base/Text";
import Principal "mo:base/Principal";
import Result "mo:base/Result";
import Time "mo:base/Time";
import Nat64 "mo:base/Nat64";
import Permissions "./Permissions";
import NamePermissions "./sneed_name/NamePermissions";
import SnsPermissions "./SnsPermissions";

module {
    // Permission type constants for SNS name management
    public let SET_SNS_NEURON_NAME_PERMISSION = "set_sns_neuron_name";
    public let REMOVE_SNS_NEURON_NAME_PERMISSION = "remove_sns_neuron_name";
    public let SET_SNS_PRINCIPAL_NAME_PERMISSION = "set_sns_principal_name";
    public let REMOVE_SNS_PRINCIPAL_NAME_PERMISSION = "remove_sns_principal_name";

    public func empty_stable() : T.NameIndexState {
        {
            name_to_index = Map.new<Nat32, T.Name>();
            index_to_name = Map.new<Text, Nat32>();
            blacklisted_words = Map.new<Text, T.Name>();
        };
    };

    public class NameIndex(
        from: T.NameIndexState, 
        sns_permissions: ?SnsPermissions.SnsPermissions
    ) {
        private let state = from;
        private let permissions = switch (sns_permissions) {
            case (?sp) { ?sp.get_permissions() };
            case null { null };
        };
        private let dedup = switch (permissions) {
            case (?p) { p.get_dedup() };
            case null { Dedup.Dedup(?Dedup.empty()) };  // Create new dedup instance if no permissions
        };

        let nat32Utils = (func (n : Nat32) : Nat32 { n }, Nat32.equal);
        let textUtils = (Text.hash, Text.equal);

        public func get_dedup() : Dedup.Dedup {
            dedup
        };

        public func get_principal_name(principal : Principal) : ?T.Name {
            let index = dedup.getOrCreateIndexForPrincipal(principal);
            Map.get(state.name_to_index, nat32Utils, index);
        };

        public func set_principal_name(caller : Principal, principal : Principal, name : Text) : async* T.NameResult<()> {
            if (Principal.isAnonymous(caller)) {
                return #Err(#AnonymousCaller);
            };

            // First check permissions
            let has_permission = switch (permissions) {
                case (?p) {
                    // Check admin and edit_any_name first, as these go through ban checks
                    if (p.is_admin(caller) or p.check_permission(caller, NamePermissions.EDIT_ANY_NAME)) {
                        true
                    } else {
                        // Only allow self-editing if not banned
                        Principal.equal(caller, principal) and not p.is_banned(caller)
                    }
                };
                case null {
                    Principal.equal(caller, principal)  // Without permissions, only allow self-editing
                };
            };

            if (not has_permission) {
                // Check if user is banned to provide specific error
                switch (permissions) {
                    case (?p) {
                        if (p.is_banned(caller)) {
                            return #Err(#Banned({ reason = "User is currently banned"; expires_at = null }));
                        };
                    };
                    case null {};
                };
                return #Err(#NotAuthorized({ required_permission = ?NamePermissions.EDIT_ANY_NAME }));
            };
            
            let name_lower = Text.toLowercase(name);
            
            // Check if name is already taken by someone else
            switch (Map.get(state.index_to_name, textUtils, name_lower)) {
                case (?existing_index) {
                    let target_index = dedup.getOrCreateIndexForPrincipal(principal);
                    if (existing_index != target_index) {
                        let taken_by = dedup.getPrincipalForIndex(existing_index);
                        return #Err(#NameAlreadyTaken({ name = name; taken_by = taken_by }));
                    };
                };
                case null {};
            };

            let index = dedup.getOrCreateIndexForPrincipal(principal);
            let now = Nat64.fromIntWrap(Time.now());
            
            // Get existing record if any
            let name_record = switch (Map.get(state.name_to_index, nat32Utils, index)) {
                case (?existing) {
                    // Keep original creation info, update the rest
                    {
                        name = name;
                        verified = existing.verified;
                        created = existing.created;
                        updated = now;
                        created_by = existing.created_by;
                        updated_by = caller;
                    };
                };
                case null {
                    // Create new record
                    {
                        name = name;
                        verified = false;
                        created = now;
                        updated = now;
                        created_by = caller;
                        updated_by = caller;
                    };
                };
            };
            
            // Remove old name from inverse map if it exists
            switch (Map.get(state.name_to_index, nat32Utils, index)) {
                case (?old_record) {
                    Map.delete(state.index_to_name, textUtils, Text.toLowercase(old_record.name));
                };
                case null {};
            };

            // Set new mappings
            Map.set(state.name_to_index, nat32Utils, index, name_record);
            Map.set(state.index_to_name, textUtils, name_lower, index);
            return #Ok(());
        };

        public func get_caller_name(caller : Principal) : ?T.Name {
            get_principal_name(caller);
        };

        public func set_caller_name(caller : Principal, name : Text) : async* T.NameResult<()> {
            await* set_principal_name(caller, caller, name);
        };

        // Helper functions for reverse lookups
        public func get_name_principal(name : Text) : ?Principal {
            switch (Map.get(state.index_to_name, textUtils, Text.toLowercase(name))) {
                case (?index) {
                    dedup.getPrincipalForIndex(index);
                };
                case null { null };
            };
        };

        public func is_name_taken(name : Text) : Bool {
            switch (Map.get(state.index_to_name, textUtils, Text.toLowercase(name))) {
                case (?_) { true };
                case null { false };
            };
        };

        // Helper function to get full name record by name
        public func get_name_record(name : Text) : ?T.Name {
            switch (Map.get(state.index_to_name, textUtils, Text.toLowercase(name))) {
                case (?index) {
                    Map.get(state.name_to_index, nat32Utils, index);
                };
                case null { null };
            };
        };

        // Check if caller can set a neuron's name
        public func can_set_neuron_name(
            caller : Principal,
            neuron_id : { id : Blob },
            sns_governance : SnsPermissions.SnsGovernanceCanister
        ) : async* Permissions.PermissionResult {
            // First check if caller has general permission using detailed check
            switch (permissions) {
                case (?p) {
                    switch (p.check_permission_detailed(caller, SET_SNS_NEURON_NAME_PERMISSION)) {
                        case (#Allowed) { return #Allowed };
                        case (#Banned(reason)) { return #Banned(reason) };  // Banned users cannot proceed to fallback checks
                        case (#PermissionNotGranted) {};  // Continue to fallback checks
                        case (#PermissionExpired(_)) {};  // Continue to fallback checks
                        case (#PermissionTypeNotFound(_)) {};  // Continue to fallback checks
                        case (#NoPrincipalPermissions) {};  // Continue to fallback checks
                        case (#PermissionTypeExists(_)) {};  // Continue to fallback checks
                    };
                };
                case null {};
            };
            
            // Fall back to checking if neuron is in caller's reachable set
            switch (sns_permissions) {
                case (?sp) {
                    let has_access = await sp.has_neuron_access(caller, neuron_id, sns_governance);
                    if (has_access) {
                        #Allowed
                    } else {
                        #PermissionNotGranted
                    }
                };
                case null { #PermissionNotGranted };
            };
        };

        // Check if caller can set a principal's name
        public func can_set_principal_name(
            caller : Principal,
            target : Principal,
            sns_governance : SnsPermissions.SnsGovernanceCanister
        ) : async* Permissions.PermissionResult {
            // First check if caller has general permission using detailed check
            switch (permissions) {
                case (?p) {
                    switch (p.check_permission_detailed(caller, SET_SNS_PRINCIPAL_NAME_PERMISSION)) {
                        case (#Allowed) { return #Allowed };
                        case (#Banned(reason)) { return #Banned(reason) };  // Banned users cannot proceed to fallback checks
                        case (#PermissionNotGranted) {};  // Continue to fallback checks
                        case (#PermissionExpired(_)) {};  // Continue to fallback checks
                        case (#PermissionTypeNotFound(_)) {};  // Continue to fallback checks
                        case (#NoPrincipalPermissions) {};  // Continue to fallback checks
                        case (#PermissionTypeExists(_)) {};  // Continue to fallback checks
                    };
                };
                case null {};
            };

            // Check if caller is the target principal (but only if not banned)
            if (Principal.equal(caller, target)) {
                switch (permissions) {
                    case (?p) {
                        // Even for self-editing, check if user is banned
                        switch (p.check_permission_detailed(caller, "dummy_permission")) {
                            case (#Banned(reason)) { return #Banned(reason) };
                            case _ { return #Allowed };
                        };
                    };
                    case null { return #Allowed };
                };
            };
            
            // Fall back to checking if principal is in caller's reachable set
            switch (sns_permissions) {
                case (?sp) {
                    let has_access = await sp.has_principal_access(caller, target, sns_governance);
                    if (has_access) {
                        #Allowed
                    } else {
                        #PermissionNotGranted
                    }
                };
                case null { #PermissionNotGranted };
            };
        };

        // SNS Neuron Name Management
        public func set_sns_neuron_name(
            caller : Principal,
            neuron_id : { id : Blob },
            name : Text,
            sns_governance : SnsPermissions.SnsGovernanceCanister
        ) : async* T.NameResult<()> {
            // Check permissions
            switch (await* can_set_neuron_name(caller, neuron_id, sns_governance)) {
                case (#Allowed) {};
                case (#Banned(reason)) {
                    return #Err(#Banned({ reason = reason.reason; expires_at = null }));
                };
                case (#PermissionNotGranted) {
                    return #Err(#NotAuthorized({ required_permission = ?SET_SNS_NEURON_NAME_PERMISSION }));
                };
                case (#PermissionExpired(info)) {
                    return #Err(#PermissionExpired({ permission = SET_SNS_NEURON_NAME_PERMISSION; expired_at = info.expired_at }));
                };
                case (#PermissionTypeNotFound(info)) {
                    return #Err(#PermissionNotFound({ permission = info.permission }));
                };
                case (#NoPrincipalPermissions) {
                    return #Err(#NotAuthorized({ required_permission = ?SET_SNS_NEURON_NAME_PERMISSION }));
                };
                case (#PermissionTypeExists(_)) {
                    return #Err(#NotAuthorized({ required_permission = ?SET_SNS_NEURON_NAME_PERMISSION }));
                };
            };

            let name_lower = Text.toLowercase(name);
            
            // Check if name is already taken by someone else
            switch (Map.get(state.index_to_name, textUtils, name_lower)) {
                case (?existing_index) {
                    let target_index = dedup.getOrCreateIndex(neuron_id.id);
                    if (existing_index != target_index) {
                        return #Err(#NameAlreadyTaken({ name = name; taken_by = null }));
                    };
                };
                case null {};
            };

            let neuron_index = dedup.getOrCreateIndex(neuron_id.id);
            let now = Nat64.fromIntWrap(Time.now());
            
            // Create or update name record
            let name_record = switch (Map.get(state.name_to_index, nat32Utils, neuron_index)) {
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

            // Remove old name from inverse map if it exists
            switch (Map.get(state.name_to_index, nat32Utils, neuron_index)) {
                case (?old_record) {
                    Map.delete(state.index_to_name, textUtils, Text.toLowercase(old_record.name));
                };
                case null {};
            };

            // Set new mappings
            Map.set(state.name_to_index, nat32Utils, neuron_index, name_record);
            Map.set(state.index_to_name, textUtils, name_lower, neuron_index);
            #Ok(());
        };

        public func get_sns_neuron_name(neuron_id : { id : Blob }) : ?T.Name {
            let neuron_index = dedup.getOrCreateIndex(neuron_id.id);
            Map.get(state.name_to_index, nat32Utils, neuron_index);
        };

        public func remove_sns_neuron_name(
            caller : Principal,
            neuron_id : { id : Blob },
            sns_governance : SnsPermissions.SnsGovernanceCanister
        ) : async* T.NameResult<()> {
            // Check permissions
            switch (await* can_set_neuron_name(caller, neuron_id, sns_governance)) {
                case (#Allowed) {};
                case (#Banned(reason)) {
                    return #Err(#Banned({ reason = reason.reason; expires_at = null }));
                };
                case (#PermissionNotGranted) {
                    return #Err(#NotAuthorized({ required_permission = ?REMOVE_SNS_NEURON_NAME_PERMISSION }));
                };
                case (#PermissionExpired(info)) {
                    return #Err(#PermissionExpired({ permission = REMOVE_SNS_NEURON_NAME_PERMISSION; expired_at = info.expired_at }));
                };
                case (#PermissionTypeNotFound(info)) {
                    return #Err(#PermissionNotFound({ permission = info.permission }));
                };
                case (#NoPrincipalPermissions) {
                    return #Err(#NotAuthorized({ required_permission = ?REMOVE_SNS_NEURON_NAME_PERMISSION }));
                };
                case (#PermissionTypeExists(_)) {
                    return #Err(#NotAuthorized({ required_permission = ?REMOVE_SNS_NEURON_NAME_PERMISSION }));
                };
            };

            let neuron_index = dedup.getOrCreateIndex(neuron_id.id);
            
            // Remove old name from inverse map if it exists
            switch (Map.get(state.name_to_index, nat32Utils, neuron_index)) {
                case (?old_record) {
                    Map.delete(state.index_to_name, textUtils, Text.toLowercase(old_record.name));
                };
                case null {};
            };

            Map.delete(state.name_to_index, nat32Utils, neuron_index);
            #Ok(());
        };
    };
}