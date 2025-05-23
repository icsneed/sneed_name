import Result "mo:base/Result";
import Nat32 "mo:base/Nat32";
import Principal "mo:base/Principal";
import Text "mo:base/Text";
import T "../Types";
import NameIndex "../lib";
import Permissions "../Permissions";
import NamePermissions "./NamePermissions";
import Timer "mo:base/Timer";
import SnsPermissions "../SnsPermissions";

actor {
  // Stable state
  stable var stable_permission_state : Permissions.StablePermissionState = Permissions.empty_stable();
  stable var stable_sns_state : SnsPermissions.StableSnsState = SnsPermissions.empty_stable();
  stable var name_index_state : T.NameIndexState = NameIndex.empty();

  // Create name index first since we need its dedup
  var name_index : NameIndex.NameIndex = NameIndex.NameIndex(name_index_state, null);  // Pass null for permissions initially
  
  // Now create permissions using the same dedup instance
  var permission_state : Permissions.PermissionState = Permissions.from_stable(stable_permission_state, name_index.get_dedup());
  var permissions : Permissions.PermissionsManager = Permissions.PermissionsManager(permission_state);

  // Create SNS permissions wrapper
  var sns_state : SnsPermissions.SnsState = SnsPermissions.from_stable(stable_sns_state, permissions, name_index.get_dedup());
  var sns_permissions : SnsPermissions.SnsPermissions = SnsPermissions.SnsPermissions(sns_state);

  // Now update name index with the permissions
  name_index := NameIndex.NameIndex(name_index_state, ?permissions);

  // Add name-specific permission types
  ignore NamePermissions.add_name_permissions(permissions);

  // Timer for cleaning up expired permissions (runs every hour)
  // NB: We must use <system> tag here because the timer is a system timer
  let cleanup_timer = Timer.recurringTimer<system>(
    #seconds(3600),  // 1 hour
    func() : async () {
      permissions.cleanup_expired();
    }
  );

  // SNS Permission Management
  public shared ({ caller }) func set_sns_permission_settings(
    permission : Text,
    sns_governance : Principal,
    min_voting_power : Nat64,
    max_duration : ?Nat64,
    default_duration : ?Nat64
  ) : async Result.Result<(), Text> {
    let settings : SnsPermissions.SnsPermissionSettings = {
      min_voting_power = min_voting_power;
      max_duration = max_duration;
      default_duration = default_duration;
    };
    sns_permissions.set_permission_settings(caller, sns_governance, permission, settings);
  };

  public query func get_sns_permission_settings(permission : Text, sns_governance : Principal) : async ?SnsPermissions.SnsPermissionSettings {
    sns_permissions.get_permission_settings(sns_governance, permission);
  };

  public shared func check_sns_permission(
    principal : Principal,
    permission : Text,
    sns_governance : Principal
  ) : async Bool {
    let governance_canister : SnsPermissions.SnsGovernanceCanister = actor(Principal.toText(sns_governance));
    await sns_permissions.check_sns_permission(principal, permission, governance_canister);
  };

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
    Timer.cancelTimer(cleanup_timer);  // Only need to cancel the timer
  };

  system func postupgrade() {
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

  // SNS Neuron Name Management
  public shared ({ caller }) func set_sns_neuron_name(
    neuron_id : Nat64,
    name : Text,
    sns_governance : Principal
  ) : async Result.Result<(), Text> {
    let governance_canister : SnsPermissions.SnsGovernanceCanister = actor(Principal.toText(sns_governance));
    await sns_permissions.set_sns_neuron_name(caller, neuron_id, name, governance_canister);
  };

  public query func get_sns_neuron_name(neuron_id : Nat64) : async ?T.Name {
    sns_permissions.get_sns_neuron_name(neuron_id);
  };

  public shared ({ caller }) func remove_sns_neuron_name(
    neuron_id : Nat64,
    sns_governance : Principal
  ) : async Result.Result<(), Text> {
    let governance_canister : SnsPermissions.SnsGovernanceCanister = actor(Principal.toText(sns_governance));
    await sns_permissions.remove_sns_neuron_name(caller, neuron_id, governance_canister);
  };

};
