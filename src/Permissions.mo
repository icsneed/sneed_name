import Principal "mo:base/Principal";
import Map "mo:map/Map";
import Result "mo:base/Result";
import Text "mo:base/Text";
import Time "mo:base/Time";
import Nat64 "mo:base/Nat64";
import Nat32 "mo:base/Nat32";
import Array "mo:base/Array";
import Dedup "mo:dedup";
import Bans "./Bans";
import Vector "mo:vector";
import Int "mo:base/Int";
import Buffer "mo:base/Buffer";
import T "Types";

// We need module name "Permissions" to allow class methods to refer to them when they would otherwise have a name conflict.
module Permissions {
    // Permission check result type
    public type PermissionResult = {
        #Allowed;
        #Banned : { reason : Text; expires_at : ?Int };
        #PermissionNotGranted;
        #PermissionExpired : { expired_at : Nat64 };
        #PermissionTypeNotFound : { permission : Text };
        #NoPrincipalPermissions;
        #PermissionTypeExists : { permission : Text };
    };

    // Ban-related types
    public type BanLogEntry = {
        user: Nat32;  // Deduped user principal index
        admin: Nat32;  // Deduped admin principal index
        ban_timestamp: Int;
        expiry_timestamp: Int;
        reason: Text;
    };

    public type BanDurationSetting = {
        offence_count: Nat;  // Number of offences this duration applies to
        duration_hours: Nat;  // Ban duration in hours
    };

    public type BanSettings = {
        min_ban_duration_hours: Nat;  // Minimum ban duration for any offense
        duration_settings: Vector.Vector<BanDurationSetting>;  // Ordered by offence_count
    };

    public type BanState = {
        var ban_log: Vector.Vector<BanLogEntry>;
        var banned_users: Map.Map<Nat32, Int>;  // Deduped user index -> Expiry timestamp
        var settings: BanSettings;
    };

    // Default ban durations
    private let DEFAULT_MIN_BAN_DURATION = 1;  // 1 hour
    private let DEFAULT_DURATIONS = [
        { offence_count = 2; duration_hours = 24 },      // Second ban: 24 hours
        { offence_count = 3; duration_hours = 168 },     // Third ban: 1 week
        { offence_count = 4; duration_hours = 720 },     // Fourth ban: 1 month
        { offence_count = 5; duration_hours = 8760 },    // Fifth ban: 1 year
        { offence_count = 6; duration_hours = 876000 },  // Sixth+ ban: 100 years
    ];

    // Permission-related types
    public type BanChecker = Principal -> Bool;

    public type PermissionMetadata = {
        created_by : Principal;
        created_at : Nat64;
        expires_at : ?Nat64;
    };

    public type PermissionType = {
        description : Text;
        max_duration : ?Nat64;  // Maximum allowed expiration duration in nanoseconds
        default_duration : ?Nat64;  // Default expiration duration in nanoseconds if none specified
    };

    // Stable state - contains only data that needs to persist
    public type StablePermissionState = {
        var admins : Map.Map<Nat32, PermissionMetadata>;  // Admin index -> Metadata
        var principal_permissions : Map.Map<Nat32, Map.Map<Nat32, PermissionMetadata>>;  // Principal index -> Permission index -> Metadata
        var ban_state : BanState;  // Ban system state
        var dedup_state : ?Dedup.DedupState;  // Dedup state for stable storage
    };

    // Non-stable state includes permission types that are registered on start
    public type PermissionState = {
        admins : Map.Map<Nat32, PermissionMetadata>;  // Admin index -> Metadata
        principal_permissions : Map.Map<Nat32, Map.Map<Nat32, PermissionMetadata>>;  // Principal index -> Permission index -> Metadata
        var permission_types : Map.Map<Nat32, PermissionType>;  // Permission index -> Type info
        dedup : Dedup.Dedup;  // For principal -> index and text -> index conversion
        ban_state : BanState;  // Ban system state
    };

    // Built-in permission type keys
    public let ADD_ADMIN_PERMISSION = "add_admin";
    public let REMOVE_ADMIN_PERMISSION = "remove_admin";
    public let BAN_USER = "ban_user";
    public let UNBAN_USER = "unban_user";
    public let MANAGE_BAN_SETTINGS = "manage_ban_settings";

    // Helper function to convert text to index
    private func text_to_index(text : Text, dedup : Dedup.Dedup) : Nat32 {
        let blob = Text.encodeUtf8(text);
        dedup.getOrCreateIndex(blob);
    };

    public func empty() : PermissionState {
        let dedup = Dedup.Dedup(?Dedup.empty());
        let default_settings = Vector.new<BanDurationSetting>();
        for (setting in DEFAULT_DURATIONS.vals()) {
            Vector.add(default_settings, setting);
        };
        {
            admins = Map.new<Nat32, PermissionMetadata>();
            principal_permissions = Map.new<Nat32, Map.Map<Nat32, PermissionMetadata>>();
            var permission_types = Map.new<Nat32, PermissionType>();
            dedup = dedup;
            ban_state = {
                var ban_log = Vector.new<BanLogEntry>();
                var banned_users = Map.new<Nat32, Int>();
                var settings = {
                    min_ban_duration_hours = DEFAULT_MIN_BAN_DURATION;
                    duration_settings = default_settings;
                };
            };
        };
    };

    public func empty_stable() : StablePermissionState {
        let default_settings = Vector.new<BanDurationSetting>();
        for (setting in DEFAULT_DURATIONS.vals()) {
            Vector.add(default_settings, setting);
        };
        {
            var admins = Map.new<Nat32, PermissionMetadata>();
            var principal_permissions = Map.new<Nat32, Map.Map<Nat32, PermissionMetadata>>();
            var ban_state = {
                var ban_log = Vector.new<BanLogEntry>();
                var banned_users = Map.new<Nat32, Int>();
                var settings = {
                    min_ban_duration_hours = DEFAULT_MIN_BAN_DURATION;
                    duration_settings = default_settings;
                };
            };
            var dedup_state = ?Dedup.empty();
        };
    };

    public func from_dedup(dedup : Dedup.Dedup) : PermissionState {
        let default_settings = Vector.new<BanDurationSetting>();
        for (setting in DEFAULT_DURATIONS.vals()) {
            Vector.add(default_settings, setting);
        };
        {
            admins = Map.new<Nat32, PermissionMetadata>();
            principal_permissions = Map.new<Nat32, Map.Map<Nat32, PermissionMetadata>>();
            var permission_types = Map.new<Nat32, PermissionType>();
            dedup = dedup;
            ban_state = {
                var ban_log = Vector.new<BanLogEntry>();
                var banned_users = Map.new<Nat32, Int>();
                var settings = {
                    min_ban_duration_hours = DEFAULT_MIN_BAN_DURATION;
                    duration_settings = default_settings;
                };
            };
        };
    };

    public func from_stable(stable_state : StablePermissionState) : PermissionState {
        {
            admins = stable_state.admins;
            principal_permissions = stable_state.principal_permissions;
            var permission_types = Map.new<Nat32, PermissionType>();
            dedup = Dedup.Dedup(stable_state.dedup_state);
            ban_state = stable_state.ban_state;
        };
    };

    public func is_admin(principal : Principal, state : PermissionState) : Bool {
        if (Principal.isController(principal)) {
            return true;
        };

        // Check if user is banned
        let user_index = state.dedup.getOrCreateIndexForPrincipal(principal);
        switch (Map.get(state.ban_state.banned_users, (func (n : Nat32) : Nat32 { n }, Nat32.equal), user_index)) {
            case (?expiry) {
                if (expiry > Time.now()) {
                    return false;
                };
            };
            case null {};
        };

        let index = state.dedup.getOrCreateIndexForPrincipal(principal);
        switch (Map.get(state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), index)) {
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

    public func check_permission_detailed(principal : Principal, permission : Text, state : PermissionState) : PermissionResult {
        // Check if user is banned first
        let user_index = state.dedup.getOrCreateIndexForPrincipal(principal);
        switch (Map.get(state.ban_state.banned_users, (func (n : Nat32) : Nat32 { n }, Nat32.equal), user_index)) {
            case (?expiry) {
                if (expiry > Time.now()) {
                    return #Banned({ reason = "User is currently banned"; expires_at = ?expiry });
                };
            };
            case null {};
        };

        // Admins have all permissions
        if (is_admin(principal, state)) {
            return #Allowed;
        };

        let permission_index = text_to_index(permission, state.dedup);
        // First check if permission type exists
        switch (Map.get(state.permission_types, (func (n : Nat32) : Nat32 { n }, Nat32.equal), permission_index)) {
            case null { return #PermissionTypeNotFound({ permission = permission }) };
            case (?_) {};
        };

        let index = state.dedup.getOrCreateIndexForPrincipal(principal);
        // Check if principal has the permission and it hasn't expired
        switch (Map.get(state.principal_permissions, (func (n : Nat32) : Nat32 { n }, Nat32.equal), index)) {
            case (?perm_map) {
                switch (Map.get(perm_map, (func (n : Nat32) : Nat32 { n }, Nat32.equal), permission_index)) {
                    case (?metadata) {
                        // Check expiration
                        switch (metadata.expires_at) {
                            case (?expiry) {
                                let now = Nat64.fromIntWrap(Time.now());
                                if (now < expiry) {
                                    #Allowed
                                } else {
                                    #PermissionExpired({ expired_at = expiry })
                                }
                            };
                            case null { #Allowed };
                        };
                    };
                    case null { #PermissionNotGranted };
                };
            };
            case null { #NoPrincipalPermissions };
        };
    };

    public func check_permission(principal : Principal, permission : Text, state : PermissionState) : Bool {
        switch (check_permission_detailed(principal, permission, state)) {
            case (#Allowed) { true };
            case (#Banned(_)) { false };
            case (#PermissionNotGranted) { false };
            case (#PermissionExpired(_)) { false };
            case (#PermissionTypeNotFound(_)) { false };
            case (#NoPrincipalPermissions) { false };
            case (#PermissionTypeExists(_)) { false };
        };
    };

    public func add_permission_type(
        name : Text,
        permission_type : PermissionType,
        state : PermissionState
    ) : Result.Result<(), Text> {
        let name_index = text_to_index(name, state.dedup);
        // Check if permission type already exists
        switch (Map.get(state.permission_types, (func (n : Nat32) : Nat32 { n }, Nat32.equal), name_index)) {
            case (?_) { #err("Permission type already exists") };
            case null {
                Map.set(state.permission_types, (func (n : Nat32) : Nat32 { n }, Nat32.equal), name_index, permission_type);
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

        let permission_index = text_to_index(permission, state.dedup);
        // Check if permission type exists and validate expiration
        switch (Map.get(state.permission_types, (func (n : Nat32) : Nat32 { n }, Nat32.equal), permission_index)) {
            case null { return #err("Invalid permission type") };
            case (?ptype) {
                let now = Nat64.fromIntWrap(Time.now());
                let effective_expiry = switch(expires_at) {
                    case (?exp) {
                        // Check if expiry exceeds max duration
                        switch(ptype.max_duration) {
                            case (?max) {
                                if (exp > now + max) {
                                    return #err("Expiration exceeds maximum allowed duration");
                                };
                            };
                            case null {};
                        };
                        ?exp
                    };
                    case null {
                        // Use default duration if specified
                        switch(ptype.default_duration) {
                            case (?default) { ?(now + default) };
                            case null { null };
                        };
                    };
                };

                let target_index = state.dedup.getOrCreateIndexForPrincipal(target);
                // Get or create permission map for principal
                let perm_map = switch (Map.get(state.principal_permissions, (func (n : Nat32) : Nat32 { n }, Nat32.equal), target_index)) {
                    case (?existing) { existing };
                    case null {
                        let new_map = Map.new<Nat32, PermissionMetadata>();
                        Map.set(state.principal_permissions, (func (n : Nat32) : Nat32 { n }, Nat32.equal), target_index, new_map);
                        new_map;
                    };
                };

                // Create permission metadata
                let metadata : PermissionMetadata = {
                    created_by = caller;
                    created_at = now;
                    expires_at = effective_expiry;
                };

                // Grant permission
                Map.set(perm_map, (func (n : Nat32) : Nat32 { n }, Nat32.equal), permission_index, metadata);
                #ok(());
            };
        };
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

        let target_index = state.dedup.getOrCreateIndexForPrincipal(target);
        let permission_index = text_to_index(permission, state.dedup);
        switch (Map.get(state.principal_permissions, (func (n : Nat32) : Nat32 { n }, Nat32.equal), target_index)) {
            case (?perm_map) {
                Map.delete(perm_map, (func (n : Nat32) : Nat32 { n }, Nat32.equal), permission_index);
                #ok(());
            };
            case null { #err("Principal has no permissions") };
        };
    };

    public func cleanup_expired_permissions(state : PermissionState) : () {
        let now = Nat64.fromIntWrap(Time.now());
        
        // Cleanup expired admins
        let admin_entries = Map.entries(state.admins);
        for ((index, metadata) in admin_entries) {
            switch (metadata.expires_at) {
                case (?expiry) {
                    if (now >= expiry) {
                        Map.delete(state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), index);
                    };
                };
                case null {};
            };
        };

        // Cleanup expired permissions for each principal
        let principal_entries = Map.entries(state.principal_permissions);
        for ((principal_index, perm_map) in principal_entries) {
            let perm_entries = Map.entries(perm_map);
            for ((perm_index, metadata) in perm_entries) {
                switch (metadata.expires_at) {
                    case (?expiry) {
                        if (now >= expiry) {
                            Map.delete(perm_map, (func (n : Nat32) : Nat32 { n }, Nat32.equal), perm_index);
                        };
                    };
                    case null {};
                };
            };
            // Remove principal's map if empty
            if (Map.size(perm_map) == 0) {
                Map.delete(state.principal_permissions, (func (n : Nat32) : Nat32 { n }, Nat32.equal), principal_index);
            };
        };

        // Cleanup expired bans
        let now_int = Time.now();
        let ban_entries = Map.entries(state.ban_state.banned_users);
        for ((index, expiry) in ban_entries) {
            if (expiry <= now_int) {
                Map.delete(state.ban_state.banned_users, (func (n : Nat32) : Nat32 { n }, Nat32.equal), index);
            };
        };
    };

    public func is_banned(principal : Principal, state : PermissionState) : Bool {
        let user_index = state.dedup.getOrCreateIndexForPrincipal(principal);
        switch (Map.get(state.ban_state.banned_users, (func (n : Nat32) : Nat32 { n }, Nat32.equal), user_index)) {
            case (?expiry) {
                // Check if ban has expired
                if (expiry <= Time.now()) {
                    Map.delete(state.ban_state.banned_users, (func (n : Nat32) : Nat32 { n }, Nat32.equal), user_index);
                    false
                } else {
                    true
                };
            };
            case null { false };
        };
    };

    public class PermissionsManager(state : PermissionState) {
        let nat32Utils = (func (n : Nat32) : Nat32 { n }, Nat32.equal);

        // Expose dedup instance for other services to use
        public func get_dedup() : Dedup.Dedup {
            state.dedup
        };

        // Helper to calculate ban duration based on offense count
        private func calculate_ban_duration(user: Nat32) : Nat {
            let offense_count = count_offenses(user);
            
            // Find the highest matching duration setting
            let settings = Vector.toArray(state.ban_state.settings.duration_settings);
            var duration = state.ban_state.settings.min_ban_duration_hours;
            
            for (setting in settings.vals()) {
                if (offense_count >= setting.offence_count) {
                    duration := setting.duration_hours;
                };
            };
            
            duration
        };

        // Helper to count total offenses for a user
        private func count_offenses(user: Nat32) : Nat {
            let log = Vector.toArray(state.ban_state.ban_log);
            var count = 0;
            for (entry in log.vals()) {
                if (entry.user == user) {
                    count += 1;
                };
            };
            count
        };

        // Check if a user is banned
        public func is_banned(principal : Principal) : Bool {
            Permissions.is_banned(principal, state);
        };

        public func check_permission(principal : Principal, permission : Text) : Bool {
            Permissions.check_permission(principal, permission, state);
        };

        public func check_permission_detailed(principal : Principal, permission : Text) : PermissionResult {
            Permissions.check_permission_detailed(principal, permission, state);
        };

        public func ban_user(caller : Principal, target : Principal, reason : Text, expires_at : ?Int) : T.PermissionResult<()> {
            if (not check_permission(caller, "admin")) {
                if (is_banned(caller)) {
                    let user_index = state.dedup.getOrCreateIndexForPrincipal(caller);
                    switch (Map.get(state.ban_state.banned_users, nat32Utils, user_index)) {
                        case (?expiry) {
                            return #Err(#Banned({ reason = "User is currently banned"; expires_at = ?expiry }));
                        };
                        case null {
                            return #Err(#Banned({ reason = "User is currently banned"; expires_at = null }));
                        };
                    };
                } else {
                    return #Err(#NotAuthorized({ required_permission = "admin" }));
                }
            };
            
            let ban_entry : BanLogEntry = {
                user = state.dedup.getOrCreateIndexForPrincipal(target);
                admin = state.dedup.getOrCreateIndexForPrincipal(caller);
                ban_timestamp = Time.now();
                expiry_timestamp = switch (expires_at) {
                    case (?exp) { exp };
                    case null { Time.now() + (24 * 3600 * 1_000_000_000) }; // Default 24 hours
                };
                reason = reason;
            };
            
            Vector.add(state.ban_state.ban_log, ban_entry);
            Map.set(state.ban_state.banned_users, nat32Utils, ban_entry.user, ban_entry.expiry_timestamp);
            #Ok(())
        };

        public func unban_user(caller : Principal, target : Principal) : T.PermissionResult<()> {
            if (not check_permission(caller, UNBAN_USER)) {
                if (is_banned(caller)) {
                    let user_index = state.dedup.getOrCreateIndexForPrincipal(caller);
                    switch (Map.get(state.ban_state.banned_users, nat32Utils, user_index)) {
                        case (?expiry) {
                            return #Err(#Banned({ reason = "User is currently banned"; expires_at = ?expiry }));
                        };
                        case null {
                            return #Err(#Banned({ reason = "User is currently banned"; expires_at = null }));
                        };
                    };
                } else {
                    return #Err(#NotAuthorized({ required_permission = "unban_user" }));
                }
            };

            let target_index = state.dedup.getOrCreateIndexForPrincipal(target);
            
            switch (Map.get(state.ban_state.banned_users, nat32Utils, target_index)) {
                case (?_) {
                    Map.delete(state.ban_state.banned_users, nat32Utils, target_index);
                    #Ok(())
                };
                case null {
                    #Err(#PermissionNotFound({ permission = "ban"; target = target }))
                };
            }
        };

        public func check_ban_status(user : Principal) : Result.Result<Text, Text> {
            if (not is_banned(user)) {
                return #err("User is not banned");
            };

            let user_index = state.dedup.getOrCreateIndexForPrincipal(user);
            switch (Map.get(state.ban_state.banned_users, nat32Utils, user_index)) {
                case (?expiry) {
                    let remaining = expiry - Time.now();
                    let hours = remaining / (3600 * 1_000_000_000);
                    #ok("User is banned for " # Int.toText(hours) # " more hours");
                };
                case null {
                    #err("User is not banned");
                };
            };
        };

        public func get_ban_log(
            caller : Principal
        ) : Result.Result<[{
            user : Principal;
            admin : Principal;
            ban_timestamp : Int;
            expiry_timestamp : Int;
            reason : Text;
        }], Text> {
            if (not check_permission(caller, MANAGE_BAN_SETTINGS)) {
                return #err("Not authorized to view ban log");
            };

            let log = Vector.toArray(state.ban_state.ban_log);
            let result = Buffer.Buffer<{
                user : Principal;
                admin : Principal;
                ban_timestamp : Int;
                expiry_timestamp : Int;
                reason : Text;
            }>(Array.size(log));

            for (entry in log.vals()) {
                switch (state.dedup.getPrincipalForIndex(entry.user)) {
                    case (?user) {
                        switch (state.dedup.getPrincipalForIndex(entry.admin)) {
                            case (?admin) {
                                result.add({
                                    user = user;
                                    admin = admin;
                                    ban_timestamp = entry.ban_timestamp;
                                    expiry_timestamp = entry.expiry_timestamp;
                                    reason = entry.reason;
                                });
                            };
                            case null {};
                        };
                    };
                    case null {};
                };
            };

            #ok(Buffer.toArray(result));
        };

        public func get_banned_users(caller : Principal) : Result.Result<[(Principal, Int)], Text> {
            if (not check_permission(caller, MANAGE_BAN_SETTINGS)) {
                return #err("Not authorized to view banned users");
            };

            let entries = Map.entries(state.ban_state.banned_users);
            let result = Buffer.Buffer<(Principal, Int)>(Map.size(state.ban_state.banned_users));

            for ((index, expiry) in entries) {
                switch (state.dedup.getPrincipalForIndex(index)) {
                    case (?principal) {
                        result.add((principal, expiry));
                    };
                    case null {};
                };
            };

            #ok(Buffer.toArray(result));
        };

        public func get_user_ban_history(
            caller : Principal,
            user : Principal
        ) : Result.Result<[{
            admin : Principal;
            ban_timestamp : Int;
            expiry_timestamp : Int;
            reason : Text;
        }], Text> {
            if (not check_permission(caller, MANAGE_BAN_SETTINGS)) {
                return #err("Not authorized to view ban history");
            };

            let user_index = state.dedup.getOrCreateIndexForPrincipal(user);
            let log = Vector.toArray(state.ban_state.ban_log);
            let result = Buffer.Buffer<{
                admin : Principal;
                ban_timestamp : Int;
                expiry_timestamp : Int;
                reason : Text;
            }>(Array.size(log));

            for (entry in log.vals()) {
                if (entry.user == user_index) {
                    switch (state.dedup.getPrincipalForIndex(entry.admin)) {
                        case (?admin) {
                            result.add({
                                admin = admin;
                                ban_timestamp = entry.ban_timestamp;
                                expiry_timestamp = entry.expiry_timestamp;
                                reason = entry.reason;
                            });
                        };
                        case null {};
                    };
                };
            };

            #ok(Buffer.toArray(result));
        };

        public func update_ban_settings(
            caller : Principal,
            settings : BanSettings
        ) : Result.Result<(), Text> {
            if (not check_permission(caller, MANAGE_BAN_SETTINGS)) {
                return #err("Not authorized to manage ban settings");
            };

            // Validate settings
            let durations = Vector.toArray(settings.duration_settings);
            if (durations.size() == 0) {
                return #err("Must provide at least one duration setting");
            };

            // Verify durations increase with offense count
            var last_count = 0;
            var last_duration = settings.min_ban_duration_hours;
            for (setting in durations.vals()) {
                if (setting.offence_count <= last_count) {
                    return #err("Offense counts must be strictly increasing");
                };
                if (setting.duration_hours < last_duration) {
                    return #err("Durations must increase with offense count");
                };
                last_count := setting.offence_count;
                last_duration := setting.duration_hours;
            };

            state.ban_state.settings := settings;
            #ok(());
        };

        public func cleanup_expired() {
            cleanup_expired_permissions(state);
        };

        public func is_admin(principal : Principal) : Bool {
            Permissions.is_admin(principal, state);
        };

        public func add_admin(
            caller : Principal, 
            new_admin : Principal, 
            expires_at : ?Nat64
        ) : async T.AdminResult<()> {
            if (not check_permission(caller, ADD_ADMIN_PERMISSION)) {
                if (is_banned(caller)) {
                    let user_index = state.dedup.getOrCreateIndexForPrincipal(caller);
                    switch (Map.get(state.ban_state.banned_users, nat32Utils, user_index)) {
                        case (?expiry) {
                            return #Err(#Banned({ reason = "User is currently banned"; expires_at = ?expiry }));
                        };
                        case null {
                            return #Err(#Banned({ reason = "User is currently banned"; expires_at = null }));
                        };
                    };
                };
                return #Err(#NotAuthorized({ required_permission = ADD_ADMIN_PERMISSION }));
            };
            
            if (is_admin(new_admin)) {
                return #Err(#AlreadyAdmin({ principal = new_admin }));
            };

            let metadata : PermissionMetadata = {
                created_by = caller;
                created_at = Nat64.fromIntWrap(Time.now());
                expires_at = expires_at;
            };

            let new_admin_index = state.dedup.getOrCreateIndexForPrincipal(new_admin);
            Map.set(state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), new_admin_index, metadata);
            #Ok(());
        };

        public func remove_admin(caller : Principal, admin : Principal) : async T.AdminResult<()> {
            if (not check_permission(caller, REMOVE_ADMIN_PERMISSION)) {
                if (is_banned(caller)) {
                    let user_index = state.dedup.getOrCreateIndexForPrincipal(caller);
                    switch (Map.get(state.ban_state.banned_users, nat32Utils, user_index)) {
                        case (?expiry) {
                            return #Err(#Banned({ reason = "User is currently banned"; expires_at = ?expiry }));
                        };
                        case null {
                            return #Err(#Banned({ reason = "User is currently banned"; expires_at = null }));
                        };
                    };
                };
                return #Err(#NotAuthorized({ required_permission = REMOVE_ADMIN_PERMISSION }));
            };

            if (Principal.equal(caller, admin)) {
                return #Err(#CannotRemoveSelf);
            };

            if (Principal.isController(admin)) {
                return #Err(#CannotRemoveController({ principal = admin }));
            };

            let admin_index = state.dedup.getOrCreateIndexForPrincipal(admin);
            Map.delete(state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin_index);
            #Ok(());
        };

        public func add_permission_type(
            name : Text,
            description : Text,
            max_duration : ?Nat64,
            default_duration : ?Nat64
        ) : T.PermissionResult<()> {
            let permission_type : PermissionType = {
                description = description;
                max_duration = max_duration;
                default_duration = default_duration;
            };
            switch (Permissions.add_permission_type(name, permission_type, state)) {
                case (#ok()) { #Ok(()) };
                case (#err(_)) { #Err(#PermissionTypeExists({ permission = name })) };
            };
        };

        public func grant_permission(
            caller : Principal, 
            target : Principal, 
            permission : Text,
            expires_at : ?Nat64
        ) : T.PermissionResult<()> {
            switch (Permissions.grant_permission(caller, target, permission, expires_at, state)) {
                case (#ok()) { #Ok(()) };
                case (#err(msg)) {
                    if (Text.contains(msg, #text "Not authorized")) {
                        if (is_banned(caller)) {
                            let user_index = state.dedup.getOrCreateIndexForPrincipal(caller);
                            switch (Map.get(state.ban_state.banned_users, nat32Utils, user_index)) {
                                case (?expiry) {
                                    #Err(#Banned({ reason = "User is currently banned"; expires_at = ?expiry }))
                                };
                                case null {
                                    #Err(#Banned({ reason = "User is currently banned"; expires_at = null }))
                                };
                            };
                        } else {
                            #Err(#NotAuthorized({ required_permission = "admin" }))
                        }
                    } else if (Text.contains(msg, #text "Invalid permission type")) {
                        #Err(#PermissionTypeNotFound({ permission = permission }))
                    } else if (Text.contains(msg, #text "exceeds maximum")) {
                        #Err(#ExpirationExceedsMaxDuration({ max_duration = 0; requested = 0 }))
                    } else {
                        #Err(#NotAuthorized({ required_permission = "admin" }))
                    }
                };
            };
        };

        public func revoke_permission(
            caller : Principal, 
            target : Principal, 
            permission : Text
        ) : T.PermissionResult<()> {
            switch (Permissions.revoke_permission(caller, target, permission, state)) {
                case (#ok()) { #Ok(()) };
                case (#err(msg)) {
                    if (Text.contains(msg, #text "Not authorized")) {
                        if (is_banned(caller)) {
                            let user_index = state.dedup.getOrCreateIndexForPrincipal(caller);
                            switch (Map.get(state.ban_state.banned_users, nat32Utils, user_index)) {
                                case (?expiry) {
                                    #Err(#Banned({ reason = "User is currently banned"; expires_at = ?expiry }))
                                };
                                case null {
                                    #Err(#Banned({ reason = "User is currently banned"; expires_at = null }))
                                };
                            };
                        } else {
                            #Err(#NotAuthorized({ required_permission = "admin" }))
                        }
                    } else if (Text.contains(msg, #text "Permission not found")) {
                        #Err(#PermissionNotFound({ permission = permission; target = target }))
                    } else {
                        #Err(#NotAuthorized({ required_permission = "admin" }))
                    }
                };
            };
        };
    };
}