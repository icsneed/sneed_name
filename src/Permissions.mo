import Principal "mo:base/Principal";
import Map "mo:map/Map";
import Result "mo:base/Result";
import Text "mo:base/Text";
import Time "mo:base/Time";
import Nat64 "mo:base/Nat64";
import Nat32 "mo:base/Nat32";
import Array "mo:base/Array";
import Dedup "mo:dedup";
import Bans "./Bans";

// We need module name "Permissions" to allow class methods to refer to them when they would otherwise have a name conflict.
module Permissions {
    public type BanChecker = Principal -> Bool;

    public type PermissionMetadata = {
        created_by : Principal;
        created_at : Nat64;
        expires_at : ?Nat64;
    };

    public type PermissionType = {
        description : Text;
        max_duration : ?Nat64;  // Maximum allowed expiration duration in nanoseconds
        default_duration : ?Nat64;  // Default expiration duration in nanoseconds if none specified
    };

    // Stable state - contains only data that needs to persist
    public type StablePermissionState = {
        var admins : Map.Map<Nat32, PermissionMetadata>;  // Admin index -> Metadata
        var principal_permissions : Map.Map<Nat32, Map.Map<Nat32, PermissionMetadata>>;  // Principal index -> Permission index -> Metadata
    };

    // Non-stable state includes permission types that are registered on start
    public type PermissionState = {
        admins : Map.Map<Nat32, PermissionMetadata>;  // Admin index -> Metadata
        principal_permissions : Map.Map<Nat32, Map.Map<Nat32, PermissionMetadata>>;  // Principal index -> Permission index -> Metadata
        var permission_types : Map.Map<Nat32, PermissionType>;  // Permission index -> Type info
        dedup : Dedup.Dedup;  // For principal -> index and text -> index conversion
        var ban_checker : ?BanChecker;  // Optional function to check if users are banned
    };

    // Built-in permission type keys
    public let ADD_ADMIN_PERMISSION = "add_admin";
    public let REMOVE_ADMIN_PERMISSION = "remove_admin";

    // Helper function to convert text to index
    private func text_to_index(text : Text, dedup : Dedup.Dedup) : Nat32 {
        let blob = Text.encodeUtf8(text);
        dedup.getOrCreateIndex(blob);
    };

    public func empty() : PermissionState {
        let dedup = Dedup.Dedup(?Dedup.empty());
        let state = {
            admins = Map.new<Nat32, PermissionMetadata>();
            principal_permissions = Map.new<Nat32, Map.Map<Nat32, PermissionMetadata>>();
            var permission_types = Map.new<Nat32, PermissionType>();
            dedup = dedup;
            var ban_checker = (null : ?BanChecker);
        };

        // Add built-in permission types
        let add_admin_index = text_to_index(ADD_ADMIN_PERMISSION, dedup);
        let remove_admin_index = text_to_index(REMOVE_ADMIN_PERMISSION, dedup);
        
        let add_admin_type : PermissionType = {
            description = "Can add new admins";
            max_duration = ?(365 * 24 * 60 * 60 * 1_000_000_000);  // 1 year max
            default_duration = ?(30 * 24 * 60 * 60 * 1_000_000_000);  // 30 days default
        };
        let remove_admin_type : PermissionType = {
            description = "Can remove admins";
            max_duration = ?(365 * 24 * 60 * 60 * 1_000_000_000);  // 1 year max
            default_duration = ?(30 * 24 * 60 * 60 * 1_000_000_000);  // 30 days default
        };

        Map.set(state.permission_types, (func (n : Nat32) : Nat32 { n }, Nat32.equal), add_admin_index, add_admin_type);
        Map.set(state.permission_types, (func (n : Nat32) : Nat32 { n }, Nat32.equal), remove_admin_index, remove_admin_type);

        state
    };

    public func empty_stable() : StablePermissionState {
        {
            var admins = Map.new<Nat32, PermissionMetadata>();
            var principal_permissions = Map.new<Nat32, Map.Map<Nat32, PermissionMetadata>>();
        }
    };

    // Create new state with existing dedup
    public func from_dedup(dedup : Dedup.Dedup) : PermissionState {
        let state = {
            admins = Map.new<Nat32, PermissionMetadata>();
            principal_permissions = Map.new<Nat32, Map.Map<Nat32, PermissionMetadata>>();
            var permission_types = Map.new<Nat32, PermissionType>();
            dedup = dedup;
            var ban_checker = (null : ?BanChecker);
        };

        // Add built-in permission types
        let add_admin_index = text_to_index(ADD_ADMIN_PERMISSION, dedup);
        let remove_admin_index = text_to_index(REMOVE_ADMIN_PERMISSION, dedup);
        
        let add_admin_type : PermissionType = {
            description = "Can add new admins";
            max_duration = ?(365 * 24 * 60 * 60 * 1_000_000_000);  // 1 year max
            default_duration = ?(30 * 24 * 60 * 60 * 1_000_000_000);  // 30 days default
        };
        let remove_admin_type : PermissionType = {
            description = "Can remove admins";
            max_duration = ?(365 * 24 * 60 * 60 * 1_000_000_000);  // 1 year max
            default_duration = ?(30 * 24 * 60 * 60 * 1_000_000_000);  // 30 days default
        };

        Map.set(state.permission_types, (func (n : Nat32) : Nat32 { n }, Nat32.equal), add_admin_index, add_admin_type);
        Map.set(state.permission_types, (func (n : Nat32) : Nat32 { n }, Nat32.equal), remove_admin_index, remove_admin_type);

        state
    };

    // Create a new PermissionState from stable state, using provided dedup
    public func from_stable(stable_state : StablePermissionState, dedup : Dedup.Dedup) : PermissionState {
        let state = {
            admins = stable_state.admins;
            principal_permissions = stable_state.principal_permissions;
            var permission_types = Map.new<Nat32, PermissionType>();
            dedup = dedup;
            var ban_checker = (null : ?BanChecker);
        };

        // Re-add built-in permission types
        let add_admin_index = text_to_index(ADD_ADMIN_PERMISSION, dedup);
        let remove_admin_index = text_to_index(REMOVE_ADMIN_PERMISSION, dedup);
        
        let add_admin_type : PermissionType = {
            description = "Can add new admins";
            max_duration = ?(365 * 24 * 60 * 60 * 1_000_000_000);  // 1 year max
            default_duration = ?(30 * 24 * 60 * 60 * 1_000_000_000);  // 30 days default
        };
        let remove_admin_type : PermissionType = {
            description = "Can remove admins";
            max_duration = ?(365 * 24 * 60 * 60 * 1_000_000_000);  // 1 year max
            default_duration = ?(30 * 24 * 60 * 60 * 1_000_000_000);  // 30 days default
        };

        Map.set(state.permission_types, (func (n : Nat32) : Nat32 { n }, Nat32.equal), add_admin_index, add_admin_type);
        Map.set(state.permission_types, (func (n : Nat32) : Nat32 { n }, Nat32.equal), remove_admin_index, remove_admin_type);

        state
    };

    public func is_admin(principal : Principal, state : PermissionState) : Bool {
        if (Principal.isController(principal)) {
            return true;
        };

        // Check if user is banned first if we have a ban checker
        switch (state.ban_checker) {
            case (?check_banned) {
                if (check_banned(principal)) {
                    return false;
                };
            };
            case null {};
        };

        let index = state.dedup.getOrCreateIndexForPrincipal(principal);
        switch (Map.get(state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), index)) {
            case (?metadata) {
                // Check if admin permission has expired
                switch (metadata.expires_at) {
                    case (?expiry) {
                        let now = Nat64.fromIntWrap(Time.now());
                        now < expiry
                    };
                    case null { true };
                };
            };
            case null { false };
        };
    };

    public func check_permission(principal : Principal, permission : Text, state : PermissionState) : Bool {
        // Check if user is banned first if we have a ban checker
        switch (state.ban_checker) {
            case (?check_banned) {
                if (check_banned(principal)) {
                    return false;
                };
            };
            case null {};
        };

        // Admins have all permissions
        if (is_admin(principal, state)) {
            return true;
        };

        let permission_index = text_to_index(permission, state.dedup);
        // First check if permission type exists
        switch (Map.get(state.permission_types, (func (n : Nat32) : Nat32 { n }, Nat32.equal), permission_index)) {
            case null { return false };
            case (?_) {};
        };

        let index = state.dedup.getOrCreateIndexForPrincipal(principal);
        // Check if principal has the permission and it hasn't expired
        switch (Map.get(state.principal_permissions, (func (n : Nat32) : Nat32 { n }, Nat32.equal), index)) {
            case (?perm_map) {
                switch (Map.get(perm_map, (func (n : Nat32) : Nat32 { n }, Nat32.equal), permission_index)) {
                    case (?metadata) {
                        // Check expiration
                        switch (metadata.expires_at) {
                            case (?expiry) {
                                let now = Nat64.fromIntWrap(Time.now());
                                now < expiry
                            };
                            case null { true };
                        };
                    };
                    case null { false };
                };
            };
            case null { false };
        };
    };

    public func add_permission_type(
        name : Text,
        permission_type : PermissionType,
        state : PermissionState
    ) : Result.Result<(), Text> {
        let name_index = text_to_index(name, state.dedup);
        // Check if permission type already exists
        switch (Map.get(state.permission_types, (func (n : Nat32) : Nat32 { n }, Nat32.equal), name_index)) {
            case (?_) { #err("Permission type already exists") };
            case null {
                Map.set(state.permission_types, (func (n : Nat32) : Nat32 { n }, Nat32.equal), name_index, permission_type);
                #ok(());
            };
        };
    };

    public func grant_permission(
        caller : Principal,
        target : Principal,
        permission : Text,
        expires_at : ?Nat64,
        state : PermissionState
    ) : Result.Result<(), Text> {
        // Only admins can grant permissions
        if (not is_admin(caller, state)) {
            return #err("Not authorized");
        };

        let permission_index = text_to_index(permission, state.dedup);
        // Check if permission type exists and validate expiration
        switch (Map.get(state.permission_types, (func (n : Nat32) : Nat32 { n }, Nat32.equal), permission_index)) {
            case null { return #err("Invalid permission type") };
            case (?ptype) {
                let now = Nat64.fromIntWrap(Time.now());
                let effective_expiry = switch(expires_at) {
                    case (?exp) {
                        // Check if expiry exceeds max duration
                        switch(ptype.max_duration) {
                            case (?max) {
                                if (exp > now + max) {
                                    return #err("Expiration exceeds maximum allowed duration");
                                };
                            };
                            case null {};
                        };
                        ?exp
                    };
                    case null {
                        // Use default duration if specified
                        switch(ptype.default_duration) {
                            case (?default) { ?(now + default) };
                            case null { null };
                        };
                    };
                };

                let target_index = state.dedup.getOrCreateIndexForPrincipal(target);
                // Get or create permission map for principal
                let perm_map = switch (Map.get(state.principal_permissions, (func (n : Nat32) : Nat32 { n }, Nat32.equal), target_index)) {
                    case (?existing) { existing };
                    case null {
                        let new_map = Map.new<Nat32, PermissionMetadata>();
                        Map.set(state.principal_permissions, (func (n : Nat32) : Nat32 { n }, Nat32.equal), target_index, new_map);
                        new_map;
                    };
                };

                // Create permission metadata
                let metadata : PermissionMetadata = {
                    created_by = caller;
                    created_at = now;
                    expires_at = effective_expiry;
                };

                // Grant permission
                Map.set(perm_map, (func (n : Nat32) : Nat32 { n }, Nat32.equal), permission_index, metadata);
                #ok(());
            };
        };
    };

    public func revoke_permission(
        caller : Principal,
        target : Principal,
        permission : Text,
        state : PermissionState
    ) : Result.Result<(), Text> {
        // Only admins can revoke permissions
        if (not is_admin(caller, state)) {
            return #err("Not authorized");
        };

        let target_index = state.dedup.getOrCreateIndexForPrincipal(target);
        let permission_index = text_to_index(permission, state.dedup);
        switch (Map.get(state.principal_permissions, (func (n : Nat32) : Nat32 { n }, Nat32.equal), target_index)) {
            case (?perm_map) {
                Map.delete(perm_map, (func (n : Nat32) : Nat32 { n }, Nat32.equal), permission_index);
                #ok(());
            };
            case null { #err("Principal has no permissions") };
        };
    };

    public func cleanup_expired_permissions(state : PermissionState) : () {
        let now = Nat64.fromIntWrap(Time.now());
        
        // Cleanup expired admins
        let admin_entries = Map.entries(state.admins);
        for ((index, metadata) in admin_entries) {
            switch (metadata.expires_at) {
                case (?expiry) {
                    if (now >= expiry) {
                        Map.delete(state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), index);
                    };
                };
                case null {};
            };
        };

        // Cleanup expired permissions for each principal
        let principal_entries = Map.entries(state.principal_permissions);
        for ((principal_index, perm_map) in principal_entries) {
            let perm_entries = Map.entries(perm_map);
            for ((perm_index, metadata) in perm_entries) {
                switch (metadata.expires_at) {
                    case (?expiry) {
                        if (now >= expiry) {
                            Map.delete(perm_map, (func (n : Nat32) : Nat32 { n }, Nat32.equal), perm_index);
                        };
                    };
                    case null {};
                };
            };
            // Remove principal's map if empty
            if (Map.size(perm_map) == 0) {
                Map.delete(state.principal_permissions, (func (n : Nat32) : Nat32 { n }, Nat32.equal), principal_index);
            };
        };
    };

    public class PermissionsManager(state : PermissionState) {
        public func set_ban_checker(checker : BanChecker) {
            state.ban_checker := ?checker;
        };

        public func check_permission(principal : Principal, permission : Text) : Bool {
            Permissions.check_permission(principal, permission, state);
        };

        public func is_admin(principal : Principal) : Bool {
            Permissions.is_admin(principal, state);
        };

        public func add_admin(
            caller : Principal, 
            new_admin : Principal, 
            expires_at : ?Nat64
        ) : async Result.Result<(), Text> {
            if (not check_permission(caller, ADD_ADMIN_PERMISSION)) {
                return #err("Not authorized");
            };
            
            if (is_admin(new_admin)) {
                return #err("Already an admin");
            };

            let metadata : PermissionMetadata = {
                created_by = caller;
                created_at = Nat64.fromIntWrap(Time.now());
                expires_at = expires_at;
            };

            let new_admin_index = state.dedup.getOrCreateIndexForPrincipal(new_admin);
            Map.set(state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), new_admin_index, metadata);
            #ok(());
        };

        public func remove_admin(caller : Principal, admin : Principal) : async Result.Result<(), Text> {
            if (not check_permission(caller, REMOVE_ADMIN_PERMISSION)) {
                return #err("Not authorized");
            };

            if (Principal.equal(caller, admin)) {
                return #err("Cannot remove self from admin");
            };

            if (Principal.isController(admin)) {
                return #err("Cannot remove controller from admin");
            };

            let admin_index = state.dedup.getOrCreateIndexForPrincipal(admin);
            Map.delete(state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin_index);
            #ok(());
        };

        public func add_permission_type(
            name : Text,
            description : Text,
            max_duration : ?Nat64,
            default_duration : ?Nat64
        ) : Result.Result<(), Text> {
            let permission_type : PermissionType = {
                description = description;
                max_duration = max_duration;
                default_duration = default_duration;
            };
            Permissions.add_permission_type(name, permission_type, state);
        };

        public func grant_permission(
            caller : Principal, 
            target : Principal, 
            permission : Text,
            expires_at : ?Nat64
        ) : Result.Result<(), Text> {
            Permissions.grant_permission(caller, target, permission, expires_at, state);
        };

        public func revoke_permission(caller : Principal, target : Principal, permission : Text) : Result.Result<(), Text> {
            Permissions.revoke_permission(caller, target, permission, state);
        };

        public func cleanup_expired() {
            cleanup_expired_permissions(state);
        };
    };
}