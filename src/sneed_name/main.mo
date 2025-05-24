import Result "mo:base/Result";
import Nat32 "mo:base/Nat32";
import Principal "mo:base/Principal";
import Text "mo:base/Text";
import Int "mo:base/Int";
import T "../Types";
import NameIndex "../lib";
import Permissions "../Permissions";
import NamePermissions "./NamePermissions";
import Timer "mo:base/Timer";
import SnsPermissions "../SnsPermissions";
import Bans "../Bans";
import BanPermissions "../BanPermissions";
import Vector "mo:vector";
import Dedup "mo:dedup";
import Time "mo:base/Time";

actor {
  // Stable state
  stable var stable_permission_state : Permissions.StablePermissionState = Permissions.empty_stable();
  stable var stable_sns_state : SnsPermissions.StableSnsState = SnsPermissions.empty_stable();
  stable var stable_name_index_state : T.NameIndexState = NameIndex.empty_stable();

  // Create permissions first since we need its dedup
  var permission_state : Permissions.PermissionState = Permissions.from_stable(
    stable_permission_state
  );
  var permissions : Permissions.PermissionsManager = Permissions.PermissionsManager(permission_state);

  // Create SNS permissions wrapper
  var sns_state : SnsPermissions.SnsState = SnsPermissions.from_stable(
    stable_sns_state,
    permissions
  );
  var sns_permissions : SnsPermissions.SnsPermissions = SnsPermissions.SnsPermissions(sns_state);


  // Create name index using permissions' dedup
  var name_index : NameIndex.NameIndex = NameIndex.NameIndex(
    stable_name_index_state,
    ?sns_permissions
  );

  // Add permission types for bans
  ignore BanPermissions.add_ban_permissions(permissions);
  
  // Add permission types for naming
  ignore NamePermissions.add_name_permissions(permissions);

  // Timer for cleaning up expired permissions and bans (runs every hour)
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
  ) : async T.PermissionResult<()> {
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
  public shared ({ caller }) func add_admin(admin : Principal, expires_at : ?Nat64) : async T.AdminResult<()> {
    await permissions.add_admin(caller, admin, expires_at);
  };

  public shared ({ caller }) func remove_admin(admin : Principal) : async T.AdminResult<()> {
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
  ) : async T.PermissionResult<()> {
    permissions.grant_permission(caller, target, permission, expires_at);
  };

  public shared ({ caller }) func revoke_permission(
    target : Principal,
    permission : Text
  ) : async T.PermissionResult<()> {
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

  // add_permission_type should only be called internally by extending code.
  // Permission type management
  //public shared ({ caller }) func add_permission_type(name : Text, description : Text, max_duration : ?Nat64, default_duration : ?Nat64) : async T.PermissionResult<()> {
  //  if (not permissions.is_admin(caller)) {
  //    return #Err(#NotAuthorized({ required_permission = "admin" }));
  //  };
  //  permissions.add_permission_type(name, description, max_duration, default_duration);
  //};

  system func preupgrade() {
    Timer.cancelTimer(cleanup_timer);  // Only need to cancel the timer
  };

  system func postupgrade() {
    // Re-add permission types after upgrade
    ignore NamePermissions.add_name_permissions(permissions);
    ignore BanPermissions.add_ban_permissions(permissions);
  };

  public query func get_principal_name(principal : Principal) : async ?T.Name {
    name_index.get_principal_name(principal);
  };

  public shared ({ caller }) func set_principal_name(principal : Principal, name : Text) : async T.NameResult<()> {
    await* name_index.set_principal_name(caller, principal, name);
  };

  public query ({ caller }) func get_caller_name() : async ?T.Name {
    name_index.get_caller_name(caller);
  };

  public shared ({ caller }) func set_caller_name(name : Text) : async T.NameResult<()> {
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
  ) : async T.NameResult<()> {
    let governance_canister : SnsPermissions.SnsGovernanceCanister = actor(Principal.toText(sns_governance));
    await* name_index.set_sns_neuron_name(caller, neuron_id, name, governance_canister);
  };

  public query func get_sns_neuron_name(neuron_id : { id : Blob }) : async ?T.Name {
    name_index.get_sns_neuron_name(neuron_id);
  };

  public shared ({ caller }) func remove_sns_neuron_name(
    neuron_id : { id : Blob },
    sns_governance : Principal
  ) : async T.NameResult<()> {
    let governance_canister : SnsPermissions.SnsGovernanceCanister = actor(Principal.toText(sns_governance));
    await* name_index.remove_sns_neuron_name(caller, neuron_id, governance_canister);
  };

  // SNS Principal Name Management
  public shared ({ caller }) func set_sns_principal_name(
    target : Principal,
    name : Text,
    sns_governance : Principal
  ) : async T.NameResult<()> {
    let governance_canister : SnsPermissions.SnsGovernanceCanister = actor(Principal.toText(sns_governance));
    await* name_index.set_sns_principal_name(caller, target, name, governance_canister);
  };

  public shared ({ caller }) func remove_sns_principal_name(
    target : Principal,
    sns_governance : Principal
  ) : async T.NameResult<()> {
    let governance_canister : SnsPermissions.SnsGovernanceCanister = actor(Principal.toText(sns_governance));
    await* name_index.remove_sns_principal_name(caller, target, governance_canister);
  };

  // Name Verification Management
  public shared ({ caller }) func verify_name(name : Text) : async T.NameResult<()> {
    await* name_index.verify_name(caller, name);
  };

  public shared ({ caller }) func unverify_name(name : Text) : async T.NameResult<()> {
    await* name_index.unverify_name(caller, name);
  };

  // Ban Management
  public shared ({ caller }) func ban_user(
    user: Principal,
    duration_hours: ?Nat,
    reason: Text
  ) : async T.PermissionResult<()> {
    // Convert duration_hours to expires_at timestamp
    let expires_at = switch (duration_hours) {
      case (null) { null };
      case (?hours) { 
        let now = Time.now();
        let duration_nanos = Int.abs(hours) * 60 * 60 * 1_000_000_000; // Convert hours to nanoseconds
        ?(now + duration_nanos)
      };
    };
    
    permissions.ban_user(caller, user, reason, expires_at);
  };

  public shared ({ caller }) func unban_user(
    user: Principal
  ) : async T.PermissionResult<()> {
    permissions.unban_user(caller, user);
  };

  public query func check_ban_status(user: Principal) : async T.BanResult<Text> {
    permissions.check_ban_status(user);
  };

  public shared ({ caller }) func get_ban_log() : async T.BanResult<[{
    user: Principal;
    admin: Principal;
    ban_timestamp: Int;
    expiry_timestamp: Int;
    reason: Text;
  }]> {
    permissions.get_ban_log(caller);
  };

  public shared ({ caller }) func get_banned_users() : async T.BanResult<[(Principal, Int)]> {
    permissions.get_banned_users(caller);
  };

  public shared ({ caller }) func get_user_ban_history(
    user: Principal
  ) : async T.BanResult<[{
    admin: Principal;
    ban_timestamp: Int;
    expiry_timestamp: Int;
    reason: Text;
  }]> {
    permissions.get_user_ban_history(caller, user);
  };

  public shared ({ caller }) func update_ban_settings(
    settings: {
      min_ban_duration_hours: Nat;
      duration_settings: [Bans.BanDurationSetting];  // Use array instead of Vector
    }
  ) : async T.BanResult<()> {
    // Convert array to Vector for internal use
    let duration_settings = Vector.new<Bans.BanDurationSetting>();
    for (setting in settings.duration_settings.vals()) {
      Vector.add(duration_settings, setting);
    };
    
    let ban_settings : Bans.BanSettings = {
      min_ban_duration_hours = settings.min_ban_duration_hours;
      duration_settings = duration_settings;
    };
    
    permissions.update_ban_settings(caller, ban_settings);
  };

  // Banned Word Management
  public shared ({ caller }) func add_banned_word(word : Text) : async T.NameResult<()> {
    await* name_index.add_banned_word(caller, word);
  };

  public shared ({ caller }) func remove_banned_word(word : Text) : async T.NameResult<()> {
    await* name_index.remove_banned_word(caller, word);
  };

  public query func is_word_banned(word : Text) : async Bool {
    name_index.is_word_banned(word);
  };

  public shared ({ caller }) func get_banned_words() : async T.NameResult<[Text]> {
    await* name_index.get_banned_words(caller);
  };
};
