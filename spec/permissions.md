# Permissions System Specification

## Overview
A flexible and reusable permissions system where each permission type has its own check function.

## Core Concepts

### Permission Types
- Each permission type is identified by a unique text key
- Permission types have associated metadata:
  - Description
  - Creation timestamp
  - Created by principal
  - Check function (the actual permission logic)

### Permission Checking Flow
1. Check if caller is in admin list (admins have all permissions)
2. Look up permission type in map
3. If found, call its check function
4. If not found, return false

### Built-in Permission Types
- `admin`: Full system access
- `add_permission_type`: Ability to add new permission types
- Additional built-in types can be added as needed

### App-Specific Permissions
- Apps can register a permission checker that implements custom logic
- Permission checks can be async (e.g., checking DAO stake)
- Only one app-specific checker can be registered at a time
- Apps are responsible for encoding/decoding their permission settings

### Administration
- Admins have full system access
- Admins can:
  - Add/remove other admins
  - Add new permission types
  - Remove permission types
- Permission types can be removed/modified after creation
- No versioning of permission types

## Implementation Considerations

### State Management
```motoko
type PermissionState = {
    var admins : [Principal];
    var permission_types : Map<Text, PermissionType>;
};

type PermissionType = {
    description : Text;
    created : Nat64;  // Timestamp
    created_by : Principal;
    check : (Principal) -> Bool;  // Sync version
    check_async : ?(Principal) -> async Bool;  // Async version if needed
};
```

### Key Functions
```motoko
// Check if principal has permission
check_permission : shared (principal : Principal, permission : Text) -> async Bool;

// Add new permission type (requires add_permission_type permission)
add_permission_type : shared (
    name : Text, 
    description : Text, 
    check : (Principal) -> Bool,
    check_async : ?(Principal) -> async Bool
) -> async Result<(), Text>;

// Remove permission type (requires admin)
remove_permission_type : shared (name : Text) -> async Result<(), Text>;

// Set app checker (requires admin)
set_app_checker : shared (checker : AppChecker) -> async Result<(), Text>;

// Helper for apps to encode their settings
encode_settings : shared <T>(settings : T) -> async Result<Blob, Text>;

// Helper for apps to decode settings
decode_settings : shared <T>(settings_blob : Blob) -> async Result<T, Text>;
```

### Example Usage
```motoko
// Example: Creating a stake-based permission
public func create_stake_permission() : async Result<(), Text> {
    let token_canister = actor "..." : actor {
        balance_of : shared (Principal) -> async Nat;
    };
    
    let minimum_stake = 1_000_000;

    await permissions.add_permission_type(
        "can_moderate",
        "Requires minimum stake to moderate",
        func (p : Principal) : Bool { false },  // Sync always returns false
        ?func (p : Principal) : async Bool {    // Async does the real check
            let balance = await token_canister.balance_of(p);
            balance >= minimum_stake
        }
    );
};

// Example: Creating a role-based permission
public func create_role_permission() : async Result<(), Text> {
    let role_canister = actor "..." : actor {
        has_role : shared (Principal, Text) -> async Bool;
    };

    await permissions.add_permission_type(
        "can_admin_forum",
        "Requires forum admin role",
        func (p : Principal) : Bool { false },  // Sync always returns false
        ?func (p : Principal) : async Bool {    // Async does the real check
            await role_canister.has_role(p, "forum_admin")
        }
    );
};

// Example: Simple synchronous permission
await permissions.add_permission_type(
    "can_view_basic",
    "Basic view permission",
    func (p : Principal) : Bool {
        not Principal.isAnonymous(p)  // Any authenticated user
    },
    null  // No async check needed
);
```

## Error Handling
- Permission checks return `Bool` for simplicity
- Administrative functions return `Result<(), Text>` with error messages
- Encoding/decoding helpers return `Result<T, Text>` to handle Candid errors

## Future Considerations
1. Caching strategies for expensive permission checks
2. Monitoring and logging of permission checks
3. Bulk permission checking
4. Permission group management