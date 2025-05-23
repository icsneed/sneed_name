import Principal "mo:base/Principal";
import Map "mo:map/Map";
import Result "mo:base/Result";
import Text "mo:base/Text";
import Time "mo:base/Time";
import Nat64 "mo:base/Nat64";
import Array "mo:base/Array";

// We need module name "Permissions" to allow class methods to refer to them when they would otherwise have a name conflict.
module Permissions {
    public type PermissionMetadata = {
        created_by : Principal;
        created_at : Nat64;
        expires_at : ?Nat64;
    };

    // Stable state - contains only data that needs to persist
    public type StablePermissionState = {
        var admins : Map.Map<Principal, PermissionMetadata>;  // Admin -> Metadata
        var principal_permissions : Map.Map<Principal, Map.Map<Text, PermissionMetadata>>;  // Principal -> Permission -> Metadata
    };

    // Non-stable state includes permission types that are registered on start
    public type PermissionState = {
        admins : Map.Map<Principal, PermissionMetadata>;  // Admin -> Metadata
        principal_permissions : Map.Map<Principal, Map.Map<Text, PermissionMetadata>>;  // Principal -> Permission -> Metadata
        var permission_types : Map.Map<Text, Bool>;  // Set of valid permission types (non-stable)
    };

    // Built-in permission type keys
    public let ADD_ADMIN_PERMISSION = "add_admin";
    public let REMOVE_ADMIN_PERMISSION = "remove_admin";

    public func empty() : PermissionState {
        let stable_state = {
            var admins = Map.new<Principal, PermissionMetadata>();
            var principal_permissions = Map.new<Principal, Map.Map<Text, PermissionMetadata>>();
        };

        let state = {
            admins = stable_state.admins;
            principal_permissions = stable_state.principal_permissions;
            var permission_types = Map.new<Text, Bool>();
        };

        // Add built-in permission types
        Map.set(state.permission_types, (Text.hash, Text.equal), ADD_ADMIN_PERMISSION, true);
        Map.set(state.permission_types, (Text.hash, Text.equal), REMOVE_ADMIN_PERMISSION, true);

        state
    };

    public func empty_stable() : StablePermissionState {
        {
            var admins = Map.new<Principal, PermissionMetadata>();
            var principal_permissions = Map.new<Principal, Map.Map<Text, PermissionMetadata>>();
        }
    };

    // Create a new PermissionState from stable state
    public func from_stable(stable_state : StablePermissionState) : PermissionState {
        let state = {
            admins = stable_state.admins;
            principal_permissions = stable_state.principal_permissions;
            var permission_types = Map.new<Text, Bool>();
        };

        // Re-add built-in permission types
        Map.set(state.permission_types, (Text.hash, Text.equal), ADD_ADMIN_PERMISSION, true);
        Map.set(state.permission_types, (Text.hash, Text.equal), REMOVE_ADMIN_PERMISSION, true);

        state
    };

    public func is_admin(principal : Principal, state : PermissionState) : Bool {
        if (Principal.isController(principal)) {
            return true;
        };

        switch (Map.get(state.admins, (Principal.hash, Principal.equal), principal)) {
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
        // Admins have all permissions
        if (is_admin(principal, state)) {
            return true;
        };

        // First check if permission type exists
        switch (Map.get(state.permission_types, (Text.hash, Text.equal), permission)) {
            case null { return false };
            case (?_) {};
        };

        // Check if principal has the permission and it hasn't expired
        switch (Map.get(state.principal_permissions, (Principal.hash, Principal.equal), principal)) {
            case (?perm_map) {
                switch (Map.get(perm_map, (Text.hash, Text.equal), permission)) {
                    case (?metadata) {
                        // Check expiration
                        switch (metadata.expires_at) {
                            case (?expiry) {
                                let now = Nat64.fromIntWrap(Time.now());
                                now < expiry  // Permission is valid if current time is strictly less than expiry
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
        state : PermissionState
    ) : Result.Result<(), Text> {
        // Check if permission type already exists
        switch (Map.get(state.permission_types, (Text.hash, Text.equal), name)) {
            case (?_) { #err("Permission type already exists") };
            case null {
                Map.set(state.permission_types, (Text.hash, Text.equal), name, true);
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

        // Check if permission type exists
        switch (Map.get(state.permission_types, (Text.hash, Text.equal), permission)) {
            case null { return #err("Invalid permission type") };
            case (?_) {};
        };

        // Get or create permission map for principal
        let perm_map = switch (Map.get(state.principal_permissions, (Principal.hash, Principal.equal), target)) {
            case (?existing) { existing };
            case null {
                let new_map = Map.new<Text, PermissionMetadata>();
                Map.set(state.principal_permissions, (Principal.hash, Principal.equal), target, new_map);
                new_map;
            };
        };

        // Create permission metadata
        let metadata : PermissionMetadata = {
            created_by = caller;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = expires_at;
        };

        // Grant permission
        Map.set(perm_map, (Text.hash, Text.equal), permission, metadata);
        #ok(());
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

        switch (Map.get(state.principal_permissions, (Principal.hash, Principal.equal), target)) {
            case (?perm_map) {
                Map.delete(perm_map, (Text.hash, Text.equal), permission);
                #ok(());
            };
            case null { #err("Principal has no permissions") };
        };
    };

    public class PermissionsManager(state : PermissionState) {
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

            Map.set(state.admins, (Principal.hash, Principal.equal), new_admin, metadata);
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

            Map.delete(state.admins, (Principal.hash, Principal.equal), admin);
            #ok(());
        };

        public func add_permission_type(name : Text) : Result.Result<(), Text> {
            Permissions.add_permission_type(name, state);
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
    };
}