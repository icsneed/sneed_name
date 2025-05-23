import Result "mo:base/Result";
import Nat32 "mo:base/Nat32";
import Principal "mo:base/Principal";
import Text "mo:base/Text";
import T "../Types";
import NameIndex "../lib";
import Permissions "../Permissions";
import NamePermissions "./NamePermissions";

actor {
  // Only store admin list in stable memory
  stable var stable_permission_state : Permissions.StablePermissionState = Permissions.empty_stable();
  stable var name_index_state : T.NameIndexState = NameIndex.empty();

  // Create name index first since we need its dedup
  var name_index : NameIndex.NameIndex = NameIndex.NameIndex(name_index_state, null);  // Pass null for permissions initially
  
  // Now create permissions using the same dedup instance
  var permission_state : Permissions.PermissionState = Permissions.from_stable(stable_permission_state, name_index.get_dedup());
  var permissions : Permissions.PermissionsManager = Permissions.PermissionsManager(permission_state);

  // Now update name index with the permissions
  name_index := NameIndex.NameIndex(name_index_state, ?permissions);

  // Add name-specific permission types
  ignore NamePermissions.add_name_permissions(permissions);

  // Admin management
  public shared ({ caller }) func add_admin(admin : Principal, expires_at : ?Nat64) : async Result.Result<(), Text> {
    await permissions.add_admin(caller, admin, expires_at);
  };

  public shared ({ caller }) func remove_admin(admin : Principal) : async Result.Result<(), Text> {
    await permissions.remove_admin(caller, admin);
  };

  public query func is_admin(principal : Principal) : async Bool {
    permissions.is_admin(principal);
  };

  public query ({ caller }) func caller_is_admin() : async Bool {
    permissions.is_admin(caller);
  };

  // Permission management
  public shared ({ caller }) func grant_permission(
    target : Principal,
    permission : Text,
    expires_at : ?Nat64
  ) : async Result.Result<(), Text> {
    permissions.grant_permission(caller, target, permission, expires_at);
  };

  public shared ({ caller }) func revoke_permission(
    target : Principal,
    permission : Text
  ) : async Result.Result<(), Text> {
    permissions.revoke_permission(caller, target, permission);
  };

  public query func check_permission(
    principal : Principal,
    permission : Text
  ) : async Bool {
    permissions.check_permission(principal, permission);
  };

  public query ({ caller }) func check_caller_permission(
    permission : Text
  ) : async Bool {
    permissions.check_permission(caller, permission);
  };

  // Permission type management
  public shared ({ caller }) func add_permission_type(name : Text, description : Text, max_duration : ?Nat64, default_duration : ?Nat64) : async Result.Result<(), Text> {
    if (not permissions.is_admin(caller)) {
      return #err("Not authorized");
    };
    permissions.add_permission_type(name, description, max_duration, default_duration);
  };

  system func preupgrade() {
    // Save stable state
    stable_permission_state := {
      var admins = permission_state.admins;
      var principal_permissions = permission_state.principal_permissions;
    };
    // No need to update dedup_state as it's already in name_index_state
  };

  system func postupgrade() {
    // Re-initialize in the correct order
    name_index := NameIndex.NameIndex(name_index_state, null);
    permission_state := Permissions.from_stable(stable_permission_state, name_index.get_dedup());
    permissions := Permissions.PermissionsManager(permission_state);
    name_index := NameIndex.NameIndex(name_index_state, ?permissions);
    
    // Re-add permission types after upgrade
    ignore NamePermissions.add_name_permissions(permissions);
  };

  let nat32Utils = (func (n : Nat32) : Nat32 { n }, Nat32.equal);
  let textUtils = (Text.hash, Text.equal);

  public query func get_principal_name(principal : Principal) : async ?T.Name {
    name_index.get_principal_name(principal);
  };

  public shared ({ caller }) func set_principal_name(principal : Principal, name : Text) : async Result.Result<(), Text> {
    await* name_index.set_principal_name(caller, principal, name);
  };

  public query ({ caller }) func get_caller_name() : async ?T.Name {
    name_index.get_caller_name(caller);
  };

  public shared ({ caller }) func set_caller_name(name : Text) : async Result.Result<(), Text> {
    await* name_index.set_caller_name(caller, name);
  };

  // Helper functions for reverse lookups
  public query func get_name_principal(name : Text) : async ?Principal {
    name_index.get_name_principal(name);
  };

  public query func is_name_taken(name : Text) : async Bool {
    name_index.is_name_taken(name);
  };

  // Helper function to get full name record by name
  public query func get_name_record(name : Text) : async ?T.Name {
    name_index.get_name_record(name);
  };

};
