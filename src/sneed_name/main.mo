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
  let permissions = Permissions.PermissionsManager(permission_state);

  // Now update name index with the permissions
  name_index := NameIndex.NameIndex(name_index_state, ?permissions);

  ignore NamePermissions.add_name_permissions(permissions);

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
