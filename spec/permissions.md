# Permissions System Specification

## Overview
A flexible and reusable permissions system where each permission type has its own check function. The system is designed to handle canister upgrades by storing only stable data (admin list) and recreating permission types on each upgrade.

## Core Concepts

### Permission Types
- Each permission type is identified by a unique text key
- Permission types have associated metadata:
  - Description
  - Check function (sync)
  - Optional async check function
- Permission types are recreated on each canister upgrade
- Permission types are defined in code, not stored in stable memory

### Permission Checking Flow
1. Check if caller is in admin list (admins have all permissions)
2. Look up permission type in map
3. If found:
   - Try sync check first
   - If sync check fails and async check exists, try async check
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
- The canister controller is always an admin
- Admins can:
  - Add/remove other admins
  - Remove permission types
- Admin list is stored in stable memory and persists across upgrades
- Cannot remove:
  - Self from admin list
  - Controller from admin list

## Implementation Details

### State Management
```motoko
// Stable state - only contains principals
type StablePermissionState = {
    var admins : [Principal];
};

// Non-stable state - contains function pointers
type PermissionState = {
    stable_state : StablePermissionState;
    var permission_types : Map.Map<Text, PermissionType>;
};

type PermissionType = {
    description : Text;
    check : (Principal) -> Bool;
    check_async : ?(Principal -> async Bool);
};
```

### Key Functions
```motoko
// Check if principal has permission
check_permission : shared (principal : Principal, permission : Text) -> async Bool;

// Add new permission type
add_permission_type : (
    name : Text, 
    description : Text, 
    check : (Principal) -> Bool,
    check_async : ?(Principal -> async Bool)
) -> Result<(), Text>;

// Remove permission type (requires admin)
remove_permission_type : (caller : Principal, name : Text) -> Result<(), Text>;

// Add admin (requires admin)
add_admin : (caller : Principal, new_admin : Principal) -> Result<(), Text>;

// Remove admin (requires admin)
remove_admin : (caller : Principal, admin : Principal) -> Result<(), Text>;

// Check if principal is admin
is_admin : (principal : Principal) -> Bool;
```

### Example Usage
```motoko
// Example: Creating a simple permission type
permissions.add_permission_type(
    "can_view_basic",
    "Basic view permission",
    func (p : Principal) : Bool {
        not Principal.isAnonymous(p)  // Any authenticated user
    },
    null  // No async check needed
);

// Example: Creating an async permission type
permissions.add_permission_type(
    "can_moderate",
    "Requires minimum stake to moderate",
    func (p : Principal) : Bool { false },  // Sync always returns false
    ?func (p : Principal) : async Bool {    // Async does the real check
        let balance = await token_canister.balance_of(p);
        balance >= minimum_stake
    }
);
```

## Upgrade Handling
1. Only admin list is stored in stable memory
2. Permission types are recreated after each upgrade
3. Apps should:
   - Store stable state in `StablePermissionState`
   - Create non-stable state in `system func postupgrade()`
   - Initialize permission types after upgrades

## Error Handling
- Permission checks return `Bool` for simplicity
- Administrative functions return `Result<(), Text>` with error messages
- Common error cases:
  - "Not authorized"
  - "Already an admin"
  - "Cannot remove self from admin"
  - "Cannot remove controller from admin"

## Best Practices
1. Keep permission types in separate modules (e.g., `NamePermissions.mo`)
2. Use constants for permission type keys
3. Prefer sync checks when possible for better performance
4. Use async checks only when external data is needed
5. Initialize permission types after deployment and upgrades

## Future Considerations
1. Caching strategies for expensive permission checks
2. Monitoring and logging of permission checks
3. Bulk permission checking
4. Permission group management