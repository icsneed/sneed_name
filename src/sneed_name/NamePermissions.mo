import Permissions "../Permissions";
import Principal "mo:base/Principal";
import Result "mo:base/Result";

module NamePermissions {
    // Permission type keys
    public let EDIT_ANY_NAME = "edit_any_name";  // Can edit anyone's name
    public let VERIFY_NAME = "verify_name";      // Can mark names as verified

    public func add_name_permissions(
        permissions : Permissions.PermissionsManager
    ) : Result.Result<(), Text> {
        // Add permission type for editing any name
        let edit_result = permissions.add_permission_type(
            EDIT_ANY_NAME,
            "Permission to edit any user's name",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        switch(edit_result) {
            case (#Err(e)) { 
                switch (e) {
                    case (#PermissionTypeExists(info)) { return #err("Permission type already exists: " # info.permission) };
                    case (#NotAuthorized(info)) { return #err("Not authorized: " # info.required_permission) };
                    case (#Banned(info)) { return #err("User is banned: " # info.reason) };
                    case _ { return #err("Failed to add edit name permission type") };
                }
            };
            case (#Ok()) {};
        };

        // Add permission type for verifying names
        let verify_result = permissions.add_permission_type(
            VERIFY_NAME,
            "Permission to verify user names",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        switch(verify_result) {
            case (#Err(e)) { 
                switch (e) {
                    case (#PermissionTypeExists(info)) { return #err("Permission type already exists: " # info.permission) };
                    case (#NotAuthorized(info)) { return #err("Not authorized: " # info.required_permission) };
                    case (#Banned(info)) { return #err("User is banned: " # info.reason) };
                    case _ { return #err("Failed to add verify name permission type") };
                }
            };
            case (#Ok()) {};
        };

        #ok(());
    };
}