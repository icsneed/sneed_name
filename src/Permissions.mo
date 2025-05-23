import Principal "mo:base/Principal";
import Map "mo:map/Map";
import Result "mo:base/Result";
import Text "mo:base/Text";
import Time "mo:base/Time";
import Nat64 "mo:base/Nat64";
import Array "mo:base/Array";

// We need module name "Permissions" to allow class methods to refer to them when they would otherwise have a name conflict.
module Permissions {
    public type PermissionType = {
        description : Text;
        check : (Principal) -> Bool;
        check_async : ?(Principal -> async Bool);
    };

    // Stable state - only contains principals
    public type StablePermissionState = {
        var admins : [Principal];
    };

    // Non-stable state - contains function pointers
    public type PermissionState = {
        stable_state : StablePermissionState;
        var permission_types : Map.Map<Text, PermissionType>;
    };

    // Built-in permission type keys
    public let ADD_ADMIN_PERMISSION = "add_admin";
    public let REMOVE_ADMIN_PERMISSION = "remove_admin";

    public func empty() : PermissionState {
        let stable_state : StablePermissionState = {
            var admins = [];
        };
        let state = {
            stable_state = stable_state;
            var permission_types = Map.new<Text, PermissionType>();
        };

        // Add built-in permission types
        ignore add_permission_type(
            ADD_ADMIN_PERMISSION,
            "Can add new admins",
            func (p : Principal) : Bool { is_admin(p, state) },
            null,
            state
        );

        ignore add_permission_type(
            REMOVE_ADMIN_PERMISSION,
            "Can remove admins",
            func (p : Principal) : Bool { is_admin(p, state) },
            null,
            state
        );

        state
    };

    public func empty_stable() : StablePermissionState {
        {
            var admins = [];
        }
    };

    // Create a new PermissionState from stable state
    public func from_stable(stable_state : StablePermissionState) : PermissionState {
        {
            stable_state = stable_state;
            var permission_types = Map.new<Text, PermissionType>();
        }
    };

    public func is_admin(principal : Principal, state : PermissionState) : Bool {
        if (Principal.isController(principal)) {
            return true;
        };
        for (admin in state.stable_state.admins.vals()) {
            if (Principal.equal(admin, principal)) {
                return true;
            };
        };
        false
    };

    public func check_permission(principal : Principal, permission : Text, state : PermissionState) : async Bool {
        // Admins have all permissions
        if (is_admin(principal, state)) {
            return true;
        };

        // Look up permission type
        switch(Map.get(state.permission_types, (Text.hash, Text.equal), permission)) {
            case (?perm_type) {
                // Try sync check first
                if (perm_type.check(principal)) {
                    return true;
                };
                // Try async check if available
                switch(perm_type.check_async) {
                    case (?async_check) { 
                        return await async_check(principal);
                    };
                    case null { false };
                };
            };
            case null { false };
        };
    };

    public func add_permission_type(
        name : Text,
        description : Text,
        check : (Principal) -> Bool,
        check_async : ?(Principal -> async Bool),
        state : PermissionState
    ) : Result.Result<(), Text> {
        let perm_type : PermissionType = {
            description;
            check;
            check_async;
        };

        Map.set(state.permission_types, (Text.hash, Text.equal), name, perm_type);
        #ok(());
    };

    public func remove_permission_type(
        caller : Principal, 
        name : Text, 
        state : PermissionState
    ) : Result.Result<(), Text> {
        if (not is_admin(caller, state)) {
            return #err("Not authorized");
        };

        Map.delete(state.permission_types, (Text.hash, Text.equal), name);
        #ok(());
    };

    public func add_admin(
        caller : Principal, 
        new_admin : Principal, 
        state : PermissionState
    ) : async Result.Result<(), Text> {
        if (not is_admin(caller, state)) {
            let has_permission = await check_permission(caller, ADD_ADMIN_PERMISSION, state);
            if (not has_permission) {
                return #err("Not authorized");
            };
        };
        
        // Check if already admin
        if (is_admin(new_admin, state)) {
            return #err("Already an admin");
        };

        state.stable_state.admins := Array.append(state.stable_state.admins, [new_admin]);
        #ok(());
    };

    public func remove_admin(
        caller : Principal, 
        admin : Principal, 
        state : PermissionState
    ) : async Result.Result<(), Text> {
        if (not is_admin(caller, state)) {
            let has_permission = await check_permission(caller, REMOVE_ADMIN_PERMISSION, state);
            if (not has_permission) {
                return #err("Not authorized");
            };
        };

        // Can't remove self
        if (Principal.equal(caller, admin)) {
            return #err("Cannot remove self from admin");
        };

        // Can't remove controller
        if (Principal.isController(admin)) {
            return #err("Cannot remove controller from admin");
        };

        state.stable_state.admins := Array.filter(state.stable_state.admins, func(p : Principal) : Bool {
            not Principal.equal(p, admin)
        });
        #ok(());
    };

    public class PermissionsManager(state : PermissionState) {
        public func check_permission(principal : Principal, permission : Text) : async Bool {
            await Permissions.check_permission(principal, permission, state);
        };

        public func is_admin(principal : Principal) : Bool {
            Permissions.is_admin(principal, state);
        };
        public func add_admin(
            caller : Principal, 
            new_admin : Principal
        ) : async Result.Result<(), Text> {
            await Permissions.add_admin(caller, new_admin, state);
        };

        public func remove_admin(
            caller : Principal, 
            admin : Principal
        ) : async Result.Result<(), Text> {
            await Permissions.remove_admin(caller, admin, state);
        };

        public func add_permission_type(
            name : Text,
            description : Text,
            check : (Principal) -> Bool,
            check_async : ?(Principal -> async Bool)
        ) : Result.Result<(), Text> {
            Permissions.add_permission_type(name, description, check, check_async, state);
        };

        public func remove_permission_type(
            caller : Principal, 
            name : Text
        ) : Result.Result<(), Text> {
            Permissions.remove_permission_type(caller, name, state);
        };
    };
}