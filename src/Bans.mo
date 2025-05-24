import Principal "mo:base/Principal";
import Result "mo:base/Result";
import Vector "mo:vector";
import Map "mo:map/Map";
import Time "mo:base/Time";
import Int "mo:base/Int";
import Nat "mo:base/Nat";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import Text "mo:base/Text";
import Buffer "mo:base/Buffer";
import Dedup "mo:dedup";
import Permissions "./Permissions";
import BanPermissions "./BanPermissions";

module {
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

    public func empty() : BanState {
        let default_settings = Vector.new<BanDurationSetting>();
        for (setting in DEFAULT_DURATIONS.vals()) {
            Vector.add(default_settings, setting);
        };
        {
            var ban_log = Vector.new<BanLogEntry>();
            var banned_users = Map.new<Nat32, Int>();
            var settings = {
                min_ban_duration_hours = DEFAULT_MIN_BAN_DURATION;
                duration_settings = default_settings;
            };
        }
    };

    public class Bans(state: BanState, dedup: Dedup.Dedup, permissions: Permissions.PermissionsManager) {
        let nat32Utils = (func (n : Nat32) : Nat32 { n }, Nat32.equal);

        // Helper to calculate ban duration based on offense count
        private func calculate_ban_duration(user: Nat32) : Nat {
            let offense_count = count_offenses(user);
            
            // Find the highest matching duration setting
            let settings = Vector.toArray(state.settings.duration_settings);
            var duration = state.settings.min_ban_duration_hours;
            
            for (setting in settings.vals()) {
                if (offense_count >= setting.offence_count) {
                    duration := setting.duration_hours;
                };
            };
            
            duration
        };

        // Helper to count total offenses for a user
        private func count_offenses(user: Nat32) : Nat {
            let log = Vector.toArray(state.ban_log);
            var count = 0;
            for (entry in log.vals()) {
                if (entry.user == user) {
                    count += 1;
                };
            };
            count
        };

        // Helper to check if a user is currently banned
        public func is_banned(user: Principal) : Bool {
            let user_index = dedup.getOrCreateIndexForPrincipal(user);
            switch (Map.get(state.banned_users, nat32Utils, user_index)) {
                case (?expiry) {
                    // Check if ban has expired
                    if (expiry <= Time.now()) {
                        Map.delete(state.banned_users, nat32Utils, user_index);
                        false
                    } else {
                        true
                    };
                };
                case null { false };
            }
        };

        // Ban a user
        public func ban_user(
            caller: Principal,
            user: Principal,
            duration_hours: ?Nat,
            reason: Text
        ) : Result.Result<(), Text> {
            // Check permissions
            if (Principal.isAnonymous(caller)) {
                return #err("Anonymous caller");
            };

            if (not permissions.check_permission(caller, BanPermissions.BAN_USER)) {
                return #err("Not authorized to ban users");
            };

            // Cannot ban admins
            if (Principal.isController(user) or permissions.is_admin(user)) {
                return #err("Cannot ban admins");
            };

            // Convert principals to indices
            let caller_index = dedup.getOrCreateIndexForPrincipal(caller);
            let user_index = dedup.getOrCreateIndexForPrincipal(user);

            // Calculate ban duration
            let hours = switch (duration_hours) {
                case (?h) { h };
                case null { calculate_ban_duration(user_index) };
            };

            // Calculate expiry timestamp
            let now = Time.now();
            let expiry = now + (Int.abs(hours) * 3600 * 1_000_000_000);

            // Create ban log entry
            let entry : BanLogEntry = {
                user = user_index;
                admin = caller_index;
                ban_timestamp = now;
                expiry_timestamp = expiry;
                reason = reason;
            };

            // Add to ban log and active bans
            Vector.add(state.ban_log, entry);
            Map.set(state.banned_users, nat32Utils, user_index, expiry);

            #ok(());
        };

        // Auto-ban a user (system function)
        public func auto_ban_user(user: Principal, reason: Text) : Result.Result<(), Text> {
            if (Principal.isAnonymous(user)) {
                return #err("Cannot ban anonymous user");
            };

            if (Principal.isController(user) or permissions.is_admin(user)) {
                return #err("Cannot ban admins");
            };

            let user_index = dedup.getOrCreateIndexForPrincipal(user);
            let system_index = dedup.getOrCreateIndexForPrincipal(Principal.fromText("aaaaa-aa"));

            let hours = calculate_ban_duration(user_index);
            let now = Time.now();
            let expiry = now + (Int.abs(hours) * 3600 * 1_000_000_000);

            let entry : BanLogEntry = {
                user = user_index;
                admin = system_index;
                ban_timestamp = now;
                expiry_timestamp = expiry;
                reason = reason;
            };

            Vector.add(state.ban_log, entry);
            Map.set(state.banned_users, nat32Utils, user_index, expiry);

            #ok(());
        };

        // Unban a user
        public func unban_user(caller: Principal, user: Principal) : Result.Result<(), Text> {
            if (Principal.isAnonymous(caller)) {
                return #err("Anonymous caller");
            };

            if (not permissions.check_permission(caller, BanPermissions.UNBAN_USER)) {
                return #err("Not authorized to unban users");
            };

            let user_index = dedup.getOrCreateIndexForPrincipal(user);
            let caller_index = dedup.getOrCreateIndexForPrincipal(caller);

            // Add unban entry to log with immediate expiry
            let entry : BanLogEntry = {
                user = user_index;
                admin = caller_index;
                ban_timestamp = Time.now();
                expiry_timestamp = Time.now();  // Immediate expiry
                reason = "Manual unban";
            };

            Vector.add(state.ban_log, entry);
            Map.delete(state.banned_users, nat32Utils, user_index);

            #ok(());
        };

        // Check ban status
        public func check_ban_status(user: Principal) : Result.Result<Text, Text> {
            if (not is_banned(user)) {
                return #err("User is not banned");
            };

            let user_index = dedup.getOrCreateIndexForPrincipal(user);
            switch (Map.get(state.banned_users, nat32Utils, user_index)) {
                case (?expiry) {
                    let remaining = expiry - Time.now();
                    let hours = remaining / (3600 * 1_000_000_000);
                    #ok("User is banned for " # Int.toText(hours) # " more hours");
                };
                case null {
                    #err("User is not banned");
                };
            }
        };

        // Get ban log with converted principals
        public func get_ban_log() : Result.Result<[{
            user: Principal;
            admin: Principal;
            ban_timestamp: Int;
            expiry_timestamp: Int;
            reason: Text;
        }], Text> {
            if (not permissions.is_admin(caller)) {
                return #err("Not authorized to view ban log");
            };

            #ok(get_ban_log_internal())
        };

        // Internal helper that actually gets the log
        private func get_ban_log_internal() : [{
            user: Principal;
            admin: Principal;
            ban_timestamp: Int;
            expiry_timestamp: Int;
            reason: Text;
        }] {
            let log = Vector.toArray(state.ban_log);
            let result = Buffer.Buffer<{
                user: Principal;
                admin: Principal;
                ban_timestamp: Int;
                expiry_timestamp: Int;
                reason: Text;
            }>(log.size());

            for (entry in log.vals()) {
                switch (dedup.getPrincipalForIndex(entry.user)) {
                    case (?user) {
                        switch (dedup.getPrincipalForIndex(entry.admin)) {
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

            Buffer.toArray(result)
        };

        // Get currently banned users
        public func get_banned_users() : Result.Result<[(Principal, Int)], Text> {
            if (not permissions.is_admin(caller)) {
                return #err("Not authorized to view banned users");
            };

            #ok(get_banned_users_internal())
        };

        // Internal helper that actually gets the banned users
        private func get_banned_users_internal() : [(Principal, Int)] {
            let entries = Map.entries(state.banned_users);
            let result = Buffer.Buffer<(Principal, Int)>(Map.size(state.banned_users));

            for ((index, expiry) in entries) {
                switch (dedup.getPrincipalForIndex(index)) {
                    case (?principal) {
                        result.add((principal, expiry));
                    };
                    case null {};
                };
            };

            Buffer.toArray(result)
        };

        // Get ban history for a specific user
        public func get_user_ban_history(
            caller: Principal,
            user: Principal
        ) : Result.Result<[{
            admin: Principal;
            ban_timestamp: Int;
            expiry_timestamp: Int;
            reason: Text;
        }], Text> {
            if (not permissions.is_admin(caller)) {
                return #err("Not authorized to view ban history");
            };

            #ok(get_user_ban_history_internal(user))
        };

        // Internal helper that actually gets the user history
        private func get_user_ban_history_internal(user: Principal) : [{
            admin: Principal;
            ban_timestamp: Int;
            expiry_timestamp: Int;
            reason: Text;
        }] {
            let user_index = dedup.getOrCreateIndexForPrincipal(user);
            let log = Vector.toArray(state.ban_log);
            let result = Buffer.Buffer<{
                admin: Principal;
                ban_timestamp: Int;
                expiry_timestamp: Int;
                reason: Text;
            }>(0);

            for (entry in log.vals()) {
                if (entry.user == user_index) {
                    switch (dedup.getPrincipalForIndex(entry.admin)) {
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

            Buffer.toArray(result)
        };

        // Update ban settings
        public func update_ban_settings(
            caller: Principal,
            settings: BanSettings
        ) : Result.Result<(), Text> {
            if (not permissions.check_permission(caller, BanPermissions.MANAGE_BAN_SETTINGS)) {
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

            state.settings := settings;
            #ok(());
        };

        // Cleanup expired bans
        public func cleanup_expired() {
            let now = Time.now();
            let entries = Map.entries(state.banned_users);
            for ((index, expiry) in entries) {
                if (expiry <= now) {
                    Map.delete(state.banned_users, nat32Utils, index);
                };
            };
        };
    };
}
