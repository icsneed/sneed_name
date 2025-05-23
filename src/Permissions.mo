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
        created : Nat64;
        created_by : Principal;
        check : (Principal) -> Bool;
        check_async : ?(Principal -> async Bool);
    };

    public type PermissionState = {
        var admins : [Principal];
        var permission_types : Map.Map<Text, PermissionType>;
    };

    public func empty() : PermissionState {
        {
            var admins = [];
            var permission_types = Map.new<Text, PermissionType>();
        }
    };

    public func check_admin(principal : Principal, state : PermissionState) : Bool {
        if (Principal.isController(principal)) {
            return true;
        };
        for (admin in state.admins.vals()) {
            if (Principal.equal(admin, principal)) {
                return true;
            };
        };
        false
    };

    public func check_permission(principal : Principal, permission : Text, state : PermissionState) : async Bool {
        // Admins have all permissions
        if (check_admin(principal, state)) {
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
        caller : Principal,
        name : Text,
        description : Text,
        check : (Principal) -> Bool,
        check_async : ?(Principal -> async Bool),
        state : PermissionState
    ) : Result.Result<(), Text> {
        if (not check_admin(caller, state)) {
            return #err("Not authorized");
        };

        let perm_type : PermissionType = {
            description = description;
            created = Nat64.fromIntWrap(Time.now());
            created_by = caller;
            check = check;
            check_async = check_async;
        };

        Map.set(state.permission_types, (Text.hash, Text.equal), name, perm_type);
        #ok(());
    };

    public func remove_permission_type(
        caller : Principal, 
        name : Text, 
        state : PermissionState
    ) : Result.Result<(), Text> {
        if (not check_admin(caller, state)) {
            return #err("Not authorized");
        };

        Map.delete(state.permission_types, (Text.hash, Text.equal), name);
        #ok(());
    };

    public func add_admin(
        caller : Principal, 
        new_admin : Principal, 
        state : PermissionState
    ) : Result.Result<(), Text> {
        if (not check_admin(caller, state)) {
            return #err("Not authorized");
        };
        
        // Check if already admin
        if (check_admin(new_admin, state)) {
            return #err("Already an admin");
        };

        state.admins := Array.append(state.admins, [new_admin]);
        #ok(());
    };

    public func remove_admin(
        caller : Principal, 
        admin : Principal, 
        state : PermissionState
    ) : Result.Result<(), Text> {
        if (not check_admin(caller, state)) {
            return #err("Not authorized");
        };

        // Can't remove self
        if (Principal.equal(caller, admin)) {
            return #err("Cannot remove self from admin");
        };

        // Can't remove controller
        if (Principal.isController(admin)) {
            return #err("Cannot remove controller from admin");
        };

        state.admins := Array.filter(state.admins, func(p : Principal) : Bool {
            not Principal.equal(p, admin)
        });
        #ok(());
    };

    public class PermissionsManager(state : PermissionState) {
        public func check_permission(principal : Principal, permission : Text) : async Bool {
            await Permissions.check_permission(principal, permission, state);
        };

        public func add_permission_type(
            caller : Principal,
            name : Text,
            description : Text,
            check : (Principal) -> Bool,
            check_async : ?(Principal -> async Bool)
        ) : Result.Result<(), Text> {
            Permissions.add_permission_type(caller, name, description, check, check_async, state);
        };

        public func remove_permission_type(caller : Principal, name : Text) : Result.Result<(), Text> {
            Permissions.remove_permission_type(caller, name, state);
        };

        public func add_admin(caller : Principal, new_admin : Principal) : Result.Result<(), Text> {
            Permissions.add_admin(caller, new_admin, state);
        };

        public func remove_admin(caller : Principal, admin : Principal) : Result.Result<(), Text> {
            Permissions.remove_admin(caller, admin, state);
        };
    };
}