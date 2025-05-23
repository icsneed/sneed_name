import Principal "mo:base/Principal";
import Array "mo:base/Array";
import Result "mo:base/Result";
import Text "mo:base/Text";
module Permissions {

    type PermissionsState = {
        var admins : [Principal];
    };

    public func empty() : PermissionsState {
        {
            var admins = [];
        };
    };

    public func is_admin(principal : Principal, state : PermissionsState) : Bool {
        if (Principal.isController(principal)) {
            return true;
        };
        Array.find<Principal>(state.admins, func(p) { Principal.equal(p, principal) }) != null;
    };

    public func add_admin(caller: Principal, principal : Principal, state : PermissionsState) : Result.Result<(), Text> {
        if (is_admin(caller, state)) {
            return #err("Caller is not an admin: " # Principal.toText(caller));
        };
        if (is_admin(principal, state)) {
            return #err("Principal is already an admin: " # Principal.toText(principal));
        };
        state.admins := Array.append(state.admins, [principal]);
        #ok(());
    };

    public func remove_admin(caller: Principal, principal : Principal, state : PermissionsState) : Result.Result<(), Text> {
        if (is_admin(caller, state)) {
            return #err("Caller is not an admin: " # Principal.toText(caller));
        };
        if (is_admin(principal, state)) {
            return #err("Principal is not an admin: " # Principal.toText(principal));
        };
        state.admins := Array.filter(state.admins, func(p) { Principal.equal(p, principal) });
        #ok(());
    };

    public class PermissionsManager(from: PermissionsState) {
        private let state = from;

        public func is_admin(principal : Principal) : Bool {
            Permissions.is_admin(principal, state);
        };

        public func add_admin(caller: Principal, principal : Principal) : Result.Result<(), Text> {
            Permissions.add_admin(caller, principal, state);
        };

        public func remove_admin(caller: Principal, principal : Principal) : Result.Result<(), Text> {
            Permissions.remove_admin(caller, principal, state);
        };
    };
}