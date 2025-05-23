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
  var permission_state : Permissions.PermissionState = Permissions.from_stable(stable_permission_state);
  let permissions = Permissions.PermissionsManager(permission_state);

  stable var name_index_state : T.NameIndexState = NameIndex.empty();
  var name_index : NameIndex.NameIndex = NameIndex.NameIndex(name_index_state, permissions);

  // Initialize permission types - call this after deployment and upgrades
  public shared ({ caller }) func init_permissions() : async Result.Result<(), Text> {
    if (not permissions.is_admin(caller)) {
      return #err("Only admins can initialize permissions");
    };
    await NamePermissions.add_name_permissions(permissions, caller);
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

  // Recreate name_index after upgrade to ensure permissions are properly set
  system func postupgrade() {
    name_index := NameIndex.NameIndex(name_index_state, permissions);
  };
};
