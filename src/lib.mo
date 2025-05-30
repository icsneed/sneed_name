import Map "mo:map/Map";
import Dedup "mo:dedup";
import T "Types";
import Nat32 "mo:base/Nat32";
import Text "mo:base/Text";
import Principal "mo:base/Principal";
import Result "mo:base/Result";
import Time "mo:base/Time";
import Nat64 "mo:base/Nat64";
import Nat8 "mo:base/Nat8";
import Debug "mo:base/Debug";
import Permissions "./Permissions";
import NamePermissions "./sneed_name/NamePermissions";
import SnsPermissions "./SnsPermissions";
import Array "mo:base/Array";
import Blob "mo:base/Blob";
import Iter "mo:base/Iter";
import Char "mo:base/Char";

module {
    // Re-export permission constants from NamePermissions for convenience
    public let SET_SNS_NEURON_NAME_PERMISSION = NamePermissions.SET_SNS_NEURON_NAME_PERMISSION;
    public let REMOVE_SNS_NEURON_NAME_PERMISSION = NamePermissions.REMOVE_SNS_NEURON_NAME_PERMISSION;
    public let SET_SNS_PRINCIPAL_NAME_PERMISSION = NamePermissions.SET_SNS_PRINCIPAL_NAME_PERMISSION;
    public let REMOVE_SNS_PRINCIPAL_NAME_PERMISSION = NamePermissions.REMOVE_SNS_PRINCIPAL_NAME_PERMISSION;
    public let VERIFY_SNS_NEURON_NAME_PERMISSION = NamePermissions.VERIFY_SNS_NEURON_NAME_PERMISSION;
    public let UNVERIFY_SNS_NEURON_NAME_PERMISSION = NamePermissions.UNVERIFY_SNS_NEURON_NAME_PERMISSION;
    public let SET_ACCOUNT_NAME_PERMISSION = NamePermissions.SET_ACCOUNT_NAME_PERMISSION;
    public let REMOVE_ACCOUNT_NAME_PERMISSION = NamePermissions.REMOVE_ACCOUNT_NAME_PERMISSION;
    public let ADD_BANNED_WORD_PERMISSION = NamePermissions.ADD_BANNED_WORD_PERMISSION;
    public let REMOVE_BANNED_WORD_PERMISSION = NamePermissions.REMOVE_BANNED_WORD_PERMISSION;
    public let VIEW_BANNED_WORDS_PERMISSION = NamePermissions.VIEW_BANNED_WORDS_PERMISSION;
    public let MANAGE_NAME_SETTINGS_PERMISSION = NamePermissions.MANAGE_NAME_SETTINGS_PERMISSION;

    public func empty_stable() : T.NameIndexState {
        {
            index_to_name = Map.new<Nat32, T.Name>();
            blacklisted_words = Map.new<Text, T.Name>();
            var name_settings = {
                min_length = 1;
                max_length = 64;
                allow_special_chars = true;
                allow_unicode = false;
            };
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

        // Reconstruct the inverse map from stable data
        private var name_to_index = Map.new<Text, Nat32>();
        do {
            for ((index, name_record) in Map.entries(state.index_to_name)) {
                let name_lower = Text.toLowercase(name_record.name);
                Map.set(name_to_index, textUtils, name_lower, index);
            };
        };

        public func get_dedup() : Dedup.Dedup {
            dedup
        };

        // Helper functions for ICRC1 Account handling
        private func is_all_zeros_subaccount(subaccount : Blob) : Bool {
            if (subaccount.size() != 32) {
                return false;
            };
            for (byte in subaccount.vals()) {
                if (byte != 0) {
                    return false;
                };
            };
            true
        };

        private func is_default_subaccount(subaccount : ?Blob) : Bool {
            switch (subaccount) {
                case null { true };
                case (?blob) { is_all_zeros_subaccount(blob) };
            };
        };

        private func get_account_index(account : T.Account) : Nat32 {
            // If it's a default subaccount, route to principal handling
            if (is_default_subaccount(account.subaccount)) {
                return dedup.getOrCreateIndexForPrincipal(account.owner);
            };

            // Get owner index
            let owner_index = dedup.getOrCreateIndexForPrincipal(account.owner);
            
            // Get subaccount index
            let subaccount_blob = switch (account.subaccount) {
                case (?blob) { blob };
                case null { 
                    // This shouldn't happen due to is_default_subaccount check above
                    // But handle it gracefully by creating a 32-byte zero blob
                    let zero_bytes = Array.tabulate<Nat8>(32, func(_) = 0);
                    Blob.fromArray(zero_bytes);
                };
            };
            let subaccount_index = dedup.getOrCreateIndex(subaccount_blob);
            
            // Combine into 8-byte blob (big-endian: owner first 4 bytes, subaccount last 4 bytes)
            let combined_bytes = Array.tabulate<Nat8>(8, func(i) {
                if (i < 4) {
                    // Owner index bytes (big-endian)
                    let shift = (3 - i) * 8;
                    let shifted = Nat32.toNat(owner_index) / (2 ** shift);
                    Nat8.fromNat(shifted % 256);
                } else {
                    // Subaccount index bytes (big-endian)
                    let shift = (7 - i) * 8;
                    let shifted = Nat32.toNat(subaccount_index) / (2 ** shift);
                    Nat8.fromNat(shifted % 256);
                };
            });
            let combined_blob = Blob.fromArray(combined_bytes);
            
            dedup.getOrCreateIndex(combined_blob)
        };

        public func get_principal_name(principal : Principal) : ?T.Name {
            let index = dedup.getOrCreateIndexForPrincipal(principal);
            Map.get(state.index_to_name, nat32Utils, index);
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
                        switch (p.check_permission_detailed(caller, NamePermissions.EDIT_ANY_NAME)) {
                            case (#Banned(reason)) {
                                return #Err(#Banned({ reason = reason.reason; expires_at = reason.expires_at }));
                            };
                            case _ {};
                        };
                    };
                    case null {};
                };
                return #Err(#NotAuthorized({ required_permission = ?NamePermissions.EDIT_ANY_NAME }));
            };
            
            // Validate name format and length
            switch (validate_name(name)) {
                case (#Err(e)) { return #Err(e) };
                case (#Ok()) {};
            };
            
            // Check for banned words and auto-ban if needed
            switch (await* check_and_handle_banned_words(caller, name)) {
                case (#Err(e)) { return #Err(e) };
                case (#Ok()) {};
            };
            
            let name_lower = Text.toLowercase(name);
            
            // Check if name is already taken by someone else
            switch (Map.get(name_to_index, textUtils, name_lower)) {
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
            let name_record = switch (Map.get(state.index_to_name, nat32Utils, index)) {
                case (?existing) {
                    // If the name is changing, unverify it
                    let should_unverify = existing.name != name;
                    {
                        name = name;
                        verified = if (should_unverify) { false } else { existing.verified };
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
            switch (Map.get(state.index_to_name, nat32Utils, index)) {
                case (?old_record) {
                    Map.delete(name_to_index, textUtils, Text.toLowercase(old_record.name));
                };
                case null {};
            };

            // Set new mappings
            Map.set(state.index_to_name, nat32Utils, index, name_record);
            Map.set(name_to_index, textUtils, name_lower, index);
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
            switch (Map.get(name_to_index, textUtils, Text.toLowercase(name))) {
                case (?index) {
                    dedup.getPrincipalForIndex(index);
                };
                case null { null };
            };
        };

        public func is_name_taken(name : Text) : Bool {
            switch (Map.get(name_to_index, textUtils, Text.toLowercase(name))) {
                case (?_) { true };
                case null { false };
            };
        };

        // Helper function to get full name record by name
        public func get_name_record(name : Text) : ?T.Name {
            switch (Map.get(name_to_index, textUtils, Text.toLowercase(name))) {
                case (?index) {
                    Map.get(state.index_to_name, nat32Utils, index);
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
                    return #Err(#Banned({ reason = reason.reason; expires_at = reason.expires_at }));
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

            // Check for banned words and auto-ban if needed
            switch (await* check_and_handle_banned_words(caller, name)) {
                case (#Err(e)) { return #Err(e) };
                case (#Ok()) {};
            };

            let name_lower = Text.toLowercase(name);
            
            // Check if name is already taken by someone else
            switch (Map.get(name_to_index, textUtils, name_lower)) {
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
            let name_record = switch (Map.get(state.index_to_name, nat32Utils, neuron_index)) {
                case (?existing) {
                    // If the name is changing, unverify it
                    let should_unverify = existing.name != name;
                    {
                        name = name;
                        verified = if (should_unverify) { false } else { existing.verified };
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
            switch (Map.get(state.index_to_name, nat32Utils, neuron_index)) {
                case (?old_record) {
                    Map.delete(name_to_index, textUtils, Text.toLowercase(old_record.name));
                };
                case null {};
            };

            // Set new mappings
            Map.set(state.index_to_name, nat32Utils, neuron_index, name_record);
            Map.set(name_to_index, textUtils, name_lower, neuron_index);
            #Ok(());
        };

        public func get_sns_neuron_name(neuron_id : { id : Blob }) : ?T.Name {
            let neuron_index = dedup.getOrCreateIndex(neuron_id.id);
            Map.get(state.index_to_name, nat32Utils, neuron_index);
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
                    return #Err(#Banned({ reason = reason.reason; expires_at = reason.expires_at }));
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
            switch (Map.get(state.index_to_name, nat32Utils, neuron_index)) {
                case (?old_record) {
                    Map.delete(name_to_index, textUtils, Text.toLowercase(old_record.name));
                };
                case null {};
            };

            Map.delete(state.index_to_name, nat32Utils, neuron_index);
            #Ok(());
        };

        // SNS Principal Name Management
        public func set_sns_principal_name(
            caller : Principal,
            target : Principal,
            name : Text,
            sns_governance : SnsPermissions.SnsGovernanceCanister
        ) : async* T.NameResult<()> {
            // Check permissions
            switch (await* can_set_principal_name(caller, target, sns_governance)) {
                case (#Allowed) {};
                case (#Banned(reason)) {
                    return #Err(#Banned({ reason = reason.reason; expires_at = reason.expires_at }));
                };
                case (#PermissionNotGranted) {
                    return #Err(#NotAuthorized({ required_permission = ?SET_SNS_PRINCIPAL_NAME_PERMISSION }));
                };
                case (#PermissionExpired(info)) {
                    return #Err(#PermissionExpired({ permission = SET_SNS_PRINCIPAL_NAME_PERMISSION; expired_at = info.expired_at }));
                };
                case (#PermissionTypeNotFound(info)) {
                    return #Err(#PermissionNotFound({ permission = info.permission }));
                };
                case (#NoPrincipalPermissions) {
                    return #Err(#NotAuthorized({ required_permission = ?SET_SNS_PRINCIPAL_NAME_PERMISSION }));
                };
                case (#PermissionTypeExists(_)) {
                    return #Err(#NotAuthorized({ required_permission = ?SET_SNS_PRINCIPAL_NAME_PERMISSION }));
                };
            };

            // Check for banned words and auto-ban if needed
            switch (await* check_and_handle_banned_words(caller, name)) {
                case (#Err(e)) { return #Err(e) };
                case (#Ok()) {};
            };

            let name_lower = Text.toLowercase(name);
            
            // Check if name is already taken by someone else
            switch (Map.get(name_to_index, textUtils, name_lower)) {
                case (?existing_index) {
                    let target_index = dedup.getOrCreateIndexForPrincipal(target);
                    if (existing_index != target_index) {
                        let taken_by = dedup.getPrincipalForIndex(existing_index);
                        return #Err(#NameAlreadyTaken({ name = name; taken_by = taken_by }));
                    };
                };
                case null {};
            };

            let target_index = dedup.getOrCreateIndexForPrincipal(target);
            let now = Nat64.fromIntWrap(Time.now());
            
            // Create or update name record
            let name_record = switch (Map.get(state.index_to_name, nat32Utils, target_index)) {
                case (?existing) {
                    // If the name is changing, unverify it
                    let should_unverify = existing.name != name;
                    {
                        name = name;
                        verified = if (should_unverify) { false } else { existing.verified };
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
            switch (Map.get(state.index_to_name, nat32Utils, target_index)) {
                case (?old_record) {
                    Map.delete(name_to_index, textUtils, Text.toLowercase(old_record.name));
                };
                case null {};
            };

            // Set new mappings
            Map.set(state.index_to_name, nat32Utils, target_index, name_record);
            Map.set(name_to_index, textUtils, name_lower, target_index);
            #Ok(());
        };

        public func remove_sns_principal_name(
            caller : Principal,
            target : Principal,
            sns_governance : SnsPermissions.SnsGovernanceCanister
        ) : async* T.NameResult<()> {
            // Check permissions
            switch (await* can_set_principal_name(caller, target, sns_governance)) {
                case (#Allowed) {};
                case (#Banned(reason)) {
                    return #Err(#Banned({ reason = reason.reason; expires_at = reason.expires_at }));
                };
                case (#PermissionNotGranted) {
                    return #Err(#NotAuthorized({ required_permission = ?REMOVE_SNS_PRINCIPAL_NAME_PERMISSION }));
                };
                case (#PermissionExpired(info)) {
                    return #Err(#PermissionExpired({ permission = REMOVE_SNS_PRINCIPAL_NAME_PERMISSION; expired_at = info.expired_at }));
                };
                case (#PermissionTypeNotFound(info)) {
                    return #Err(#PermissionNotFound({ permission = info.permission }));
                };
                case (#NoPrincipalPermissions) {
                    return #Err(#NotAuthorized({ required_permission = ?REMOVE_SNS_PRINCIPAL_NAME_PERMISSION }));
                };
                case (#PermissionTypeExists(_)) {
                    return #Err(#NotAuthorized({ required_permission = ?REMOVE_SNS_PRINCIPAL_NAME_PERMISSION }));
                };
            };

            let target_index = dedup.getOrCreateIndexForPrincipal(target);
            
            // Remove old name from inverse map if it exists
            switch (Map.get(state.index_to_name, nat32Utils, target_index)) {
                case (?old_record) {
                    Map.delete(name_to_index, textUtils, Text.toLowercase(old_record.name));
                };
                case null {};
            };

            Map.delete(state.index_to_name, nat32Utils, target_index);
            #Ok(());
        };

        // Verification methods
        public func verify_name(caller : Principal, target_name : Text) : async* T.NameResult<()> {
            // Check if caller has verification permission
            switch (permissions) {
                case (?p) {
                    switch (p.check_permission_detailed(caller, NamePermissions.VERIFY_NAME)) {
                        case (#Allowed) {};
                        case (#Banned(reason)) {
                            return #Err(#Banned({ reason = reason.reason; expires_at = reason.expires_at }));
                        };
                        case _ {
                            return #Err(#NotAuthorized({ required_permission = ?NamePermissions.VERIFY_NAME }));
                        };
                    };
                };
                case null {
                    return #Err(#NotAuthorized({ required_permission = ?NamePermissions.VERIFY_NAME }));
                };
            };

            let name_lower = Text.toLowercase(target_name);
            
            // Find the name record
            switch (Map.get(name_to_index, textUtils, name_lower)) {
                case (?index) {
                    switch (Map.get(state.index_to_name, nat32Utils, index)) {
                        case (?existing_record) {
                            let now = Nat64.fromIntWrap(Time.now());
                            let updated_record = {
                                name = existing_record.name;
                                verified = true;
                                created = existing_record.created;
                                updated = now;
                                created_by = existing_record.created_by;
                                updated_by = caller;
                            };
                            Map.set(state.index_to_name, nat32Utils, index, updated_record);
                            #Ok(());
                        };
                        case null {
                            #Err(#NameNotFound({ name = target_name }));
                        };
                    };
                };
                case null {
                    #Err(#NameNotFound({ name = target_name }));
                };
            };
        };

        public func unverify_name(caller : Principal, target_name : Text) : async* T.NameResult<()> {
            // Check if caller has unverification permission
            switch (permissions) {
                case (?p) {
                    switch (p.check_permission_detailed(caller, NamePermissions.UNVERIFY_NAME)) {
                        case (#Allowed) {};
                        case (#Banned(reason)) {
                            return #Err(#Banned({ reason = reason.reason; expires_at = reason.expires_at }));
                        };
                        case _ {
                            return #Err(#NotAuthorized({ required_permission = ?NamePermissions.UNVERIFY_NAME }));
                        };
                    };
                };
                case null {
                    return #Err(#NotAuthorized({ required_permission = ?NamePermissions.UNVERIFY_NAME }));
                };
            };

            let name_lower = Text.toLowercase(target_name);
            
            // Find the name record
            switch (Map.get(name_to_index, textUtils, name_lower)) {
                case (?index) {
                    switch (Map.get(state.index_to_name, nat32Utils, index)) {
                        case (?existing_record) {
                            let now = Nat64.fromIntWrap(Time.now());
                            let updated_record = {
                                name = existing_record.name;
                                verified = false;
                                created = existing_record.created;
                                updated = now;
                                created_by = existing_record.created_by;
                                updated_by = caller;
                            };
                            Map.set(state.index_to_name, nat32Utils, index, updated_record);
                            #Ok(());
                        };
                        case null {
                            #Err(#NameNotFound({ name = target_name }));
                        };
                    };
                };
                case null {
                    #Err(#NameNotFound({ name = target_name }));
                };
            };
        };

        // SNS Neuron Name Verification methods
        public func verify_sns_neuron_name(
            caller : Principal,
            neuron_id : { id : Blob },
            sns_governance : SnsPermissions.SnsGovernanceCanister
        ) : async* T.NameResult<()> {
            // Check if caller has verification permission
            let has_permission = switch (permissions) {
                case (?p) {
                    switch (p.check_permission_detailed(caller, VERIFY_SNS_NEURON_NAME_PERMISSION)) {
                        case (#Allowed) { true };
                        case (#Banned(reason)) {
                            return #Err(#Banned({ reason = reason.reason; expires_at = reason.expires_at }));
                        };
                        case _ { false };
                    };
                };
                case null { false };
            };

            // If no explicit permission, check if caller is SNS governance and neuron exists
            if (not has_permission) {
                let governance_principal = Principal.fromActor(sns_governance);
                if (Principal.equal(caller, governance_principal)) {
                    // Verify neuron exists in this SNS by calling get_neuron
                    switch (await sns_governance.get_neuron(neuron_id)) {
                        case (?_) {}; // Neuron exists, proceed
                        case null {
                            return #Err(#NeuronNotFound({ neuron_id = neuron_id.id }));
                        };
                    };
                } else {
                    return #Err(#NotAuthorized({ required_permission = ?VERIFY_SNS_NEURON_NAME_PERMISSION }));
                };
            };

            let neuron_index = dedup.getOrCreateIndex(neuron_id.id);
            
            // Find the neuron name record
            switch (Map.get(state.index_to_name, nat32Utils, neuron_index)) {
                case (?existing_record) {
                    let now = Nat64.fromIntWrap(Time.now());
                    let updated_record = {
                        name = existing_record.name;
                        verified = true;
                        created = existing_record.created;
                        updated = now;
                        created_by = existing_record.created_by;
                        updated_by = caller;
                    };
                    Map.set(state.index_to_name, nat32Utils, neuron_index, updated_record);
                    #Ok(());
                };
                case null {
                    #Err(#NameNotFound({ name = "neuron:" # debug_show(neuron_id.id) }));
                };
            };
        };

        public func unverify_sns_neuron_name(
            caller : Principal,
            neuron_id : { id : Blob },
            sns_governance : SnsPermissions.SnsGovernanceCanister
        ) : async* T.NameResult<()> {
            // Check if caller has unverification permission
            let has_permission = switch (permissions) {
                case (?p) {
                    switch (p.check_permission_detailed(caller, UNVERIFY_SNS_NEURON_NAME_PERMISSION)) {
                        case (#Allowed) { true };
                        case (#Banned(reason)) {
                            return #Err(#Banned({ reason = reason.reason; expires_at = reason.expires_at }));
                        };
                        case _ { false };
                    };
                };
                case null { false };
            };

            // If no explicit permission, check if caller is SNS governance and neuron exists
            if (not has_permission) {
                let governance_principal = Principal.fromActor(sns_governance);
                if (Principal.equal(caller, governance_principal)) {
                    // Verify neuron exists in this SNS by calling get_neuron
                    switch (await sns_governance.get_neuron(neuron_id)) {
                        case (?_) {}; // Neuron exists, proceed
                        case null {
                            return #Err(#NeuronNotFound({ neuron_id = neuron_id.id }));
                        };
                    };
                } else {
                    return #Err(#NotAuthorized({ required_permission = ?UNVERIFY_SNS_NEURON_NAME_PERMISSION }));
                };
            };

            let neuron_index = dedup.getOrCreateIndex(neuron_id.id);
            
            // Find the neuron name record
            switch (Map.get(state.index_to_name, nat32Utils, neuron_index)) {
                case (?existing_record) {
                    let now = Nat64.fromIntWrap(Time.now());
                    let updated_record = {
                        name = existing_record.name;
                        verified = false;
                        created = existing_record.created;
                        updated = now;
                        created_by = existing_record.created_by;
                        updated_by = caller;
                    };
                    Map.set(state.index_to_name, nat32Utils, neuron_index, updated_record);
                    #Ok(());
                };
                case null {
                    #Err(#NameNotFound({ name = "neuron:" # debug_show(neuron_id.id) }));
                };
            };
        };

        // ICRC1 Account Name Management
        public func set_account_name(
            caller : Principal,
            account : T.Account,
            name : Text
        ) : async* T.NameResult<()> {
            // If it's a default subaccount, route to principal name handling
            if (is_default_subaccount(account.subaccount)) {
                return await* set_principal_name(caller, account.owner, name);
            };

            if (Principal.isAnonymous(caller)) {
                return #Err(#AnonymousCaller);
            };

            // Check permissions for account name setting
            let has_permission = switch (permissions) {
                case (?p) {
                    // Check admin and set_account_name permission first, as these go through ban checks
                    if (p.is_admin(caller) or p.check_permission(caller, SET_ACCOUNT_NAME_PERMISSION)) {
                        true
                    } else {
                        // Only allow owner to set their own account names if not banned
                        Principal.equal(caller, account.owner) and not p.is_banned(caller)
                    }
                };
                case null {
                    Principal.equal(caller, account.owner)  // Without permissions, only allow owner
                };
            };

            if (not has_permission) {
                // Check if user is banned to provide specific error
                switch (permissions) {
                    case (?p) {
                        switch (p.check_permission_detailed(caller, SET_ACCOUNT_NAME_PERMISSION)) {
                            case (#Banned(reason)) {
                                return #Err(#Banned({ reason = reason.reason; expires_at = reason.expires_at }));
                            };
                            case _ {};
                        };
                    };
                    case null {};
                };
                return #Err(#NotAuthorized({ required_permission = ?SET_ACCOUNT_NAME_PERMISSION }));
            };

            // Check for banned words and auto-ban if needed
            switch (await* check_and_handle_banned_words(caller, name)) {
                case (#Err(e)) { return #Err(e) };
                case (#Ok()) {};
            };

            let name_lower = Text.toLowercase(name);
            
            // Check if name is already taken by someone else
            switch (Map.get(name_to_index, textUtils, name_lower)) {
                case (?existing_index) {
                    let target_index = get_account_index(account);
                    if (existing_index != target_index) {
                        return #Err(#NameAlreadyTaken({ name = name; taken_by = null }));
                    };
                };
                case null {};
            };

            let account_index = get_account_index(account);
            let now = Nat64.fromIntWrap(Time.now());
            
            // Create or update name record
            let name_record = switch (Map.get(state.index_to_name, nat32Utils, account_index)) {
                case (?existing) {
                    // If the name is changing, unverify it
                    let should_unverify = existing.name != name;
                    {
                        name = name;
                        verified = if (should_unverify) { false } else { existing.verified };
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
            switch (Map.get(state.index_to_name, nat32Utils, account_index)) {
                case (?old_record) {
                    Map.delete(name_to_index, textUtils, Text.toLowercase(old_record.name));
                };
                case null {};
            };

            // Set new mappings
            Map.set(state.index_to_name, nat32Utils, account_index, name_record);
            Map.set(name_to_index, textUtils, name_lower, account_index);
            #Ok(());
        };

        public func get_account_name(account : T.Account) : ?T.Name {
            // If it's a default subaccount, route to principal name handling
            if (is_default_subaccount(account.subaccount)) {
                return get_principal_name(account.owner);
            };

            let account_index = get_account_index(account);
            Map.get(state.index_to_name, nat32Utils, account_index);
        };

        public func remove_account_name(
            caller : Principal,
            account : T.Account
        ) : async* T.NameResult<()> {
            // If it's a default subaccount, route to principal name handling
            if (is_default_subaccount(account.subaccount)) {
                // For principal names, we don't have a remove method, so return an error
                return #Err(#NotAuthorized({ required_permission = ?REMOVE_ACCOUNT_NAME_PERMISSION }));
            };

            if (Principal.isAnonymous(caller)) {
                return #Err(#AnonymousCaller);
            };

            // Check permissions for account name removal
            let has_permission = switch (permissions) {
                case (?p) {
                    // Check admin and remove_account_name permission first, as these go through ban checks
                    if (p.is_admin(caller) or p.check_permission(caller, REMOVE_ACCOUNT_NAME_PERMISSION)) {
                        true
                    } else {
                        // Only allow owner to remove their own account names if not banned
                        Principal.equal(caller, account.owner) and not p.is_banned(caller)
                    }
                };
                case null {
                    Principal.equal(caller, account.owner)  // Without permissions, only allow owner
                };
            };

            if (not has_permission) {
                // Check if user is banned to provide specific error
                switch (permissions) {
                    case (?p) {
                        switch (p.check_permission_detailed(caller, REMOVE_ACCOUNT_NAME_PERMISSION)) {
                            case (#Banned(reason)) {
                                return #Err(#Banned({ reason = reason.reason; expires_at = reason.expires_at }));
                            };
                            case _ {};
                        };
                    };
                    case null {};
                };
                return #Err(#NotAuthorized({ required_permission = ?REMOVE_ACCOUNT_NAME_PERMISSION }));
            };

            let account_index = get_account_index(account);
            
            // Remove old name from inverse map if it exists
            switch (Map.get(state.index_to_name, nat32Utils, account_index)) {
                case (?old_record) {
                    Map.delete(name_to_index, textUtils, Text.toLowercase(old_record.name));
                };
                case null {};
            };

            Map.delete(state.index_to_name, nat32Utils, account_index);
            #Ok(());
        };

        // Helper functions for account name lookups
        public func get_name_account(name : Text) : ?T.Account {
            switch (Map.get(name_to_index, textUtils, Text.toLowercase(name))) {
                case (?index) {
                    // Try to reconstruct the account from the index
                    // First check if it's a simple principal index
                    switch (dedup.getPrincipalForIndex(index)) {
                        case (?principal) {
                            // This is a principal (default subaccount)
                            ?{ owner = principal; subaccount = null };
                        };
                        case null {
                            // This might be a compound account index
                            // For now, we can't easily reverse-engineer the account from the combined index
                            // This would require storing additional metadata or a reverse lookup
                            // For the initial implementation, we'll return null for compound accounts
                            null
                        };
                    };
                };
                case null { null };
            };
        };

        public func is_account_name_taken(name : Text) : Bool {
            switch (Map.get(name_to_index, textUtils, Text.toLowercase(name))) {
                case (?_) { true };
                case null { false };
            };
        };

        // Banned word management
        public func add_banned_word(caller : Principal, word : Text) : async* T.NameResult<()> {
            // Check if caller has permission to add banned words
            switch (permissions) {
                case (?p) {
                    switch (p.check_permission_detailed(caller, ADD_BANNED_WORD_PERMISSION)) {
                        case (#Allowed) {};
                        case (#Banned(reason)) {
                            return #Err(#Banned({ reason = reason.reason; expires_at = reason.expires_at }));
                        };
                        case _ {
                            return #Err(#NotAuthorized({ required_permission = ?ADD_BANNED_WORD_PERMISSION }));
                        };
                    };
                };
                case null {
                    return #Err(#NotAuthorized({ required_permission = ?ADD_BANNED_WORD_PERMISSION }));
                };
            };

            let word_lower = Text.toLowercase(word);
            let now = Nat64.fromIntWrap(Time.now());
            
            let banned_word_record : T.Name = {
                name = word_lower;
                verified = true;  // Banned words are always "verified" as banned
                created = now;
                updated = now;
                created_by = caller;
                updated_by = caller;
            };

            Map.set(state.blacklisted_words, textUtils, word_lower, banned_word_record);
            #Ok(());
        };

        public func remove_banned_word(caller : Principal, word : Text) : async* T.NameResult<()> {
            // Check if caller has permission to remove banned words
            switch (permissions) {
                case (?p) {
                    switch (p.check_permission_detailed(caller, REMOVE_BANNED_WORD_PERMISSION)) {
                        case (#Allowed) {};
                        case (#Banned(reason)) {
                            return #Err(#Banned({ reason = reason.reason; expires_at = reason.expires_at }));
                        };
                        case _ {
                            return #Err(#NotAuthorized({ required_permission = ?REMOVE_BANNED_WORD_PERMISSION }));
                        };
                    };
                };
                case null {
                    return #Err(#NotAuthorized({ required_permission = ?REMOVE_BANNED_WORD_PERMISSION }));
                };
            };

            let word_lower = Text.toLowercase(word);
            Map.delete(state.blacklisted_words, textUtils, word_lower);
            #Ok(());
        };

        public func get_banned_words(caller : Principal) : async* T.NameResult<[Text]> {
            // Check if caller has permission to view banned words
            switch (permissions) {
                case (?p) {
                    switch (p.check_permission_detailed(caller, VIEW_BANNED_WORDS_PERMISSION)) {
                        case (#Allowed) {};
                        case (#Banned(reason)) {
                            return #Err(#Banned({ reason = reason.reason; expires_at = reason.expires_at }));
                        };
                        case _ {
                            return #Err(#NotAuthorized({ required_permission = ?VIEW_BANNED_WORDS_PERMISSION }));
                        };
                    };
                };
                case null {
                    return #Err(#NotAuthorized({ required_permission = ?VIEW_BANNED_WORDS_PERMISSION }));
                };
            };

            let words = Map.keys(state.blacklisted_words);
            #Ok(Iter.toArray(words));
        };

        // Private helper function to check if a word is banned (used internally)
        private func is_word_banned(word : Text) : Bool {
            let word_lower = Text.toLowercase(word);
            switch (Map.get(state.blacklisted_words, textUtils, word_lower)) {
                case (?_) { true };
                case null { false };
            };
        };

        // Helper function to check if a name contains banned words and auto-ban if needed
        private func check_and_handle_banned_words(caller : Principal, name : Text) : async* T.NameResult<()> {
            let name_lower = Text.toLowercase(name);
            
            // Check if the name itself is a banned word
            if (is_word_banned(name_lower)) {
                // Auto-ban the user
                switch (permissions) {
                    case (?p) {
                        // Calculate ban duration based on previous bans (this would need to be implemented in the ban system)
                        // For now, we'll use a default escalating ban system
                        let ban_reason = "Used banned word: " # name;
                        switch (p.ban_user(caller, caller, ban_reason, null)) {
                            case (#Err(_)) {
                                // If banning fails, still return the banned word error
                                return #Err(#BannedWord({ word = name }));
                            };
                            case (#Ok()) {
                                return #Err(#BannedWord({ word = name }));
                            };
                        };
                    };
                    case null {
                        return #Err(#BannedWord({ word = name }));
                    };
                };
            };

            // Check if the name contains any banned words as substrings
            for ((banned_word, _) in Map.entries(state.blacklisted_words)) {
                if (Text.contains(name_lower, #text banned_word)) {
                    // Auto-ban the user
                    switch (permissions) {
                        case (?p) {
                            let ban_reason = "Used banned word '" # banned_word # "' in name: " # name;
                            switch (p.ban_user(caller, caller, ban_reason, null)) {
                                case (#Err(_)) {
                                    // If banning fails, still return the banned word error
                                    return #Err(#BannedWord({ word = banned_word }));
                                };
                                case (#Ok()) {
                                    return #Err(#BannedWord({ word = banned_word }));
                                };
                            };
                        };
                        case null {
                            return #Err(#BannedWord({ word = banned_word }));
                        };
                    };
                };
            };

            #Ok(());
        };

        // Name validation functions
        private func validate_name_length(name : Text) : T.NameResult<()> {
            let name_length = Text.size(name);
            if (name_length < state.name_settings.min_length) {
                return #Err(#InvalidName({ 
                    name = name; 
                    reason = "Name too short. Minimum length: " # debug_show(state.name_settings.min_length) 
                }));
            };
            if (name_length > state.name_settings.max_length) {
                return #Err(#InvalidName({ 
                    name = name; 
                    reason = "Name too long. Maximum length: " # debug_show(state.name_settings.max_length) 
                }));
            };
            #Ok(());
        };

        private func validate_name_characters(name : Text) : T.NameResult<()> {
            // Check for special characters if not allowed
            if (not state.name_settings.allow_special_chars) {
                for (char in name.chars()) {
                    let char_code = Char.toNat32(char);
                    // Allow alphanumeric characters (A-Z, a-z, 0-9)
                    let is_alpha = (char_code >= 65 and char_code <= 90) or (char_code >= 97 and char_code <= 122);
                    let is_numeric = char_code >= 48 and char_code <= 57;
                    if (not (is_alpha or is_numeric)) {
                        return #Err(#InvalidName({ 
                            name = name; 
                            reason = "Special characters not allowed" 
                        }));
                    };
                };
            };

            // Check for unicode characters if not allowed
            if (not state.name_settings.allow_unicode) {
                for (char in name.chars()) {
                    let char_code = Char.toNat32(char);
                    // Only allow ASCII characters (0-127)
                    if (char_code > 127) {
                        return #Err(#InvalidName({ 
                            name = name; 
                            reason = "Unicode characters not allowed" 
                        }));
                    };
                };
            };

            #Ok(());
        };

        private func validate_name(name : Text) : T.NameResult<()> {
            // Check length
            switch (validate_name_length(name)) {
                case (#Err(e)) { return #Err(e) };
                case (#Ok()) {};
            };

            // Check characters
            switch (validate_name_characters(name)) {
                case (#Err(e)) { return #Err(e) };
                case (#Ok()) {};
            };

            #Ok(());
        };

        // Name settings management
        public func get_name_settings() : T.NameSettings {
            state.name_settings
        };

        public func set_name_settings(caller : Principal, settings : T.NameSettings) : async* T.NameResult<()> {
            if (Principal.isAnonymous(caller)) {
                return #Err(#AnonymousCaller);
            };

            // Check permissions
            switch (permissions) {
                case (?p) {
                    switch (p.check_permission_detailed(caller, NamePermissions.MANAGE_NAME_SETTINGS_PERMISSION)) {
                        case (#Banned(reason)) {
                            return #Err(#Banned({ reason = reason.reason; expires_at = reason.expires_at }));
                        };
                        case (#PermissionNotGranted or #PermissionExpired(_) or #PermissionTypeNotFound(_) or #NoPrincipalPermissions) {
                            return #Err(#NotAuthorized({ required_permission = ?NamePermissions.MANAGE_NAME_SETTINGS_PERMISSION }));
                        };
                        case (#Allowed) {};
                        case (#PermissionTypeExists(_)) {
                            // This shouldn't happen in permission checking, but handle it gracefully
                            return #Err(#NotAuthorized({ required_permission = ?NamePermissions.MANAGE_NAME_SETTINGS_PERMISSION }));
                        };
                    };
                };
                case null {
                    return #Err(#NotAuthorized({ required_permission = ?NamePermissions.MANAGE_NAME_SETTINGS_PERMISSION }));
                };
            };

            // Validate settings
            if (settings.min_length == 0) {
                return #Err(#InvalidNameSettings({ reason = "Minimum length must be at least 1" }));
            };
            if (settings.min_length > settings.max_length) {
                return #Err(#InvalidNameSettings({ reason = "Minimum length cannot be greater than maximum length" }));
            };
            if (settings.max_length > 1000) {
                return #Err(#InvalidNameSettings({ reason = "Maximum length cannot exceed 1000 characters" }));
            };

            // Update settings
            state.name_settings := settings;
            #Ok(());
        };
    };
}