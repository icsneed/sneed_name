# Ban System Specification

## Overview
The ban system provides functionality to temporarily or permanently restrict users' access to system features. It includes configurable progressive ban durations, ban history tracking, and admin management tools. The system is implemented as a reusable class in `Bans.mo` with state management handled by the actor using the library.

## Dependencies
- Uses the `Permissions.mo` library for permission management
- Uses the `dedup` module for efficient principal storage and compatibility with other services
- Requires the following permission types:
  - `BAN_USER`: Permission to ban users
  - `UNBAN_USER`: Permission to unban users
  - `MANAGE_BAN_SETTINGS`: Permission to configure ban duration settings

## Types

### BanLogEntry
```motoko
type BanLogEntry = {
    user: Nat32;  // Deduped user principal index
    admin: Nat32;  // Deduped admin principal index
    ban_timestamp: Int;
    expiry_timestamp: Int;
    reason: Text;
};
```

### BanDurationSetting
```motoko
type BanDurationSetting = {
    offence_count: Nat;  // Number of offences this duration applies to
    duration_hours: Nat;  // Ban duration in hours
};
```

### BanSettings
```motoko
type BanSettings = {
    min_ban_duration_hours: Nat;  // Minimum ban duration for any offense
    duration_settings: Vector.Vector<BanDurationSetting>;  // Ordered by offence_count
};
```

### BanState
```motoko
type BanState = {
    var ban_log: Vector.Vector<BanLogEntry>;
    var banned_users: Map.Map<Nat32, Int>;  // Deduped user index -> Expiry timestamp
    var settings: BanSettings;
};
```

## Constructor
The `Bans` class takes both the ban state and a dedup instance:
```motoko
public class Bans(state: BanState, dedup: Dedup.Dedup) {
    // Implementation
}
```

This allows the ban system to:
1. Share the same dedup instance with other services (e.g., Permissions, SnsPermissions)
2. Use consistent principal->index mapping across the entire application
3. Reduce storage overhead by storing Nat32 indices instead of full principals

## Core Functions

### Ban Management
- `ban_user(user: Principal, duration_hours: ?Nat, reason: Text) : Result.Result<(), Text>`
  - Admin function to ban a user
  - Converts principal to index using shared dedup instance
  - Optional duration override, otherwise calculated from settings
  - Requires `BAN_USER` permission
  - Validates user is not anonymous/admin
  - Records ban in log and active bans

- `auto_ban_user(user: Principal, reason: Text) : Result.Result<(), Text>`
  - System function for automatic bans
  - Converts principal to index using shared dedup instance
  - Calculates duration based on user's ban history and settings
  - Used when system rules are violated

- `unban_user(user: Principal) : Result.Result<(), Text>`
  - Admin function to remove an active ban
  - Converts principal to index using shared dedup instance
  - Requires `UNBAN_USER` permission
  - Records unban in log with immediate expiry

### Ban Status
- `is_banned(user: Principal) : Bool`
  - Internal helper to check if user is banned
  - Converts principal to index using shared dedup instance
  - Handles expiry cleanup

- `check_ban_status(user: Principal) : Result.Result<(), Text>`
  - Public query to check ban status
  - Returns formatted duration if banned

### Ban History
- `get_ban_log() : Result.Result<[{user: Principal; admin: Principal; timestamp: Int; expiry: Int; reason: Text}], Text>`
  - Admin query for complete ban history
  - Converts stored indices back to principals for display

- `get_banned_users() : Result.Result<[(Principal, Int)], Text>`
  - Admin query for currently banned users
  - Converts stored indices back to principals for display

- `get_user_ban_history(user: Principal) : Result.Result<[BanLogEntry], Text>`
  - Admin query for specific user's ban history
  - Converts stored indices back to principals for display

### Settings Management
- `update_ban_settings(settings: BanSettings) : Result.Result<(), Text>`
  - Updates ban duration settings
  - Requires `MANAGE_BAN_SETTINGS` permission
  - Validates that durations increase with offense count
  - Example valid settings:
    ```motoko
    {
        min_ban_duration_hours = 24;  // Default minimum 24h
        duration_settings = [
            { offence_count = 3; duration_hours = 168; },   // 3+ offences: 1 week
            { offence_count = 5; duration_hours = 720; },   // 5+ offences: 1 month
        ]
    }
    ```
  - In this example:
    - 1-2 offences: min_ban_duration_hours (24h)
    - 3-4 offences: 1 week
    - 5+ offences: 1 month

### Cleanup
- `cleanup_expired() : ()`
  - Internal method to remove expired bans
  - Should NOT be called directly
  - The actor using this library should set up a system timer to call this periodically

## Integration in Actor

Example integration in main.mo:
```motoko
actor {
    // Create or get existing dedup instance
    stable var dedup_state = Dedup.empty();
    let dedup = Dedup.Dedup(?dedup_state);

    // Create permissions with dedup
    let permissions = Permissions.PermissionsManager(
        Permissions.from_dedup(dedup)
    );

    // Create ban system with same dedup
    stable var ban_state : BanState = BanSystem.empty();
    let ban_system = BanSystem.Bans(ban_state, dedup);

    // Set up timer for cleanup
    let cleanup_timer = Timer.recurringTimer(
        #seconds(3600),  // Every hour
        func() : async () {
            ban_system.cleanup_expired();
        }
    );

    system func preupgrade() {
        Timer.cancelTimer(cleanup_timer);
        // Store dedup state
        dedup_state := dedup.share_state();
    };

    system func postupgrade() {
        // Re-create timer
        cleanup_timer := Timer.recurringTimer(
            #seconds(3600),
            func() : async () {
                ban_system.cleanup_expired();
            }
        );
    };
}
```

## Default Ban Durations
If no custom settings are provided, the system uses these defaults:
1. First ban: 1 hour
2. Second ban: 24 hours
3. Third ban: 1 week (168 hours)
4. Fourth ban: 1 month (720 hours)
5. Fifth ban: 1 year (8760 hours)
6. Sixth+ ban: 100 years (876000 hours)

These defaults can be overridden using `update_ban_settings`.

## State Management
The system uses stable data structures:
- `Vector` for ban log - allows efficient append operations and stable storage
- `Map` for banned users - provides stable key-value storage using deduped indices
- `Vector` for ban duration settings - ordered list of duration configurations
- Shared dedup instance for consistent principal->index mapping
- No need for upgrade/downgrade cycles since all structures are stable
- Automatic garbage collection of expired bans during checks
