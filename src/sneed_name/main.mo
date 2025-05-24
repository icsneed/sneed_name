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
import Bans "../Bans";
import BanPermissions "../BanPermissions";
import Vector "mo:vector";

actor {
  // Stable state
  stable var stable_permission_state : Permissions.StablePermissionState = Permissions.empty_stable();
  stable var stable_sns_state : SnsPermissions.StableSnsState = SnsPermissions.empty_stable();
  stable var name_index_state : T.NameIndexState = NameIndex.empty();
  stable var ban_state : Bans.BanState = Bans.empty();

  // Create name index first since we need its dedup
  var name_index : NameIndex.NameIndex = NameIndex.NameIndex(
    name_index_state,  // from
    null  // sns_permissions
  );  // Pass null for permissions initially
  
  // Create ban system with dedup
  var ban_system = Bans.Bans(ban_state, name_index.get_dedup(), func(p: Principal, perm: Text) : Bool { false });  // Pass dummy permission checker initially
  
  // Now create permissions using the same dedup
  var permission_state : Permissions.PermissionState = Permissions.from_stable(stable_permission_state, name_index.get_dedup());
  var permissions : Permissions.PermissionsManager = Permissions.PermissionsManager(permission_state);

  // Update ban system with real permission checker
  ban_system := Bans.Bans(ban_state, name_index.get_dedup(), func(p: Principal, perm: Text) : Bool {
    permissions.check_permission(p, perm)
  });

  // Set ban checker in permissions
  permissions.set_ban_checker(func(p: Principal) : Bool {
    ban_system.is_banned(p)
  });

  // Create SNS permissions wrapper
  var sns_state : SnsPermissions.SnsState = SnsPermissions.from_stable(
    stable_sns_state, 
    permissions, 
    name_index.get_dedup(),
    ban_system
  );
  var sns_permissions : SnsPermissions.SnsPermissions = SnsPermissions.SnsPermissions(sns_state);

  // Now update name index with the permissions
  name_index := NameIndex.NameIndex(
    name_index_state,
    ?sns_permissions
  );

  // Add permission types
  ignore NamePermissions.add_name_permissions(permissions);
  ignore BanPermissions.add_ban_permissions(permissions);

  // Timer for cleaning up expired permissions and bans (runs every hour)
  // NB: We must use <system> tag here because the timer is a system timer
  let cleanup_timer = Timer.recurringTimer<system>(
    #seconds(3600),  // 1 hour
    func() : async () {
      permissions.cleanup_expired();
      ban_system.cleanup_expired();
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
    ignore BanPermissions.add_ban_permissions(permissions);
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
    neuron_id : { id : Blob },
    name : Text,
    sns_governance : Principal
  ) : async Result.Result<(), Text> {
    let governance_canister : SnsPermissions.SnsGovernanceCanister = actor(Principal.toText(sns_governance));
    await* name_index.set_sns_neuron_name(caller, neuron_id, name, governance_canister);
  };

  public query func get_sns_neuron_name(neuron_id : { id : Blob }) : async ?T.Name {
    name_index.get_sns_neuron_name(neuron_id);
  };

  public shared ({ caller }) func remove_sns_neuron_name(
    neuron_id : { id : Blob },
    sns_governance : Principal
  ) : async Result.Result<(), Text> {
    let governance_canister : SnsPermissions.SnsGovernanceCanister = actor(Principal.toText(sns_governance));
    await* name_index.remove_sns_neuron_name(caller, neuron_id, governance_canister);
  };

  // Ban Management
  public shared ({ caller }) func ban_user(
    user: Principal,
    duration_hours: ?Nat,
    reason: Text
  ) : async Result.Result<(), Text> {
    ban_system.ban_user(caller, user, duration_hours, reason);
  };

  public shared ({ caller }) func unban_user(
    user: Principal
  ) : async Result.Result<(), Text> {
    ban_system.unban_user(caller, user)
  };

  public query func check_ban_status(user: Principal) : async Result.Result<Text, Text> {
    ban_system.check_ban_status(user);
  };

  public shared ({ caller }) func get_ban_log() : async Result.Result<[{
    user: Principal;
    admin: Principal;
    ban_timestamp: Int;
    expiry_timestamp: Int;
    reason: Text;
  }], Text> {
    ban_system.get_ban_log(caller);
  };

  public shared ({ caller }) func get_banned_users() : async Result.Result<[(Principal, Int)], Text> {
    ban_system.get_banned_users(caller);
  };

  public shared ({ caller }) func get_user_ban_history(
    user: Principal
  ) : async Result.Result<[{
    admin: Principal;
    ban_timestamp: Int;
    expiry_timestamp: Int;
    reason: Text;
  }], Text> {
    ban_system.get_user_ban_history(caller, user);
  };

  public shared ({ caller }) func update_ban_settings(
    settings: {
      min_ban_duration_hours: Nat;
      duration_settings: [Bans.BanDurationSetting];  // Use array instead of Vector
    }
  ) : async Result.Result<(), Text> {
    // Convert array to Vector for internal use
    let duration_settings = Vector.new<Bans.BanDurationSetting>();
    for (setting in settings.duration_settings.vals()) {
      Vector.add(duration_settings, setting);
    };
    
    let ban_settings : Bans.BanSettings = {
      min_ban_duration_hours = settings.min_ban_duration_hours;
      duration_settings = duration_settings;
    };
    
    ban_system.update_ban_settings(caller, ban_settings)
  };
};
