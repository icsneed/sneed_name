import Permissions "./Permissions";
import Principal "mo:base/Principal";
import Result "mo:base/Result";

module {
    // Permission type keys
    public let BAN_USER = "ban_user";
    public let UNBAN_USER = "unban_user";
    public let MANAGE_BAN_SETTINGS = "manage_ban_settings";

    public func add_ban_permissions(
        permissions : Permissions.PermissionsManager
    ) : Result.Result<(), Text> {
        // Add permission type for banning users
        let ban_result = permissions.add_permission_type(
            BAN_USER,
            "Permission to ban users",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        switch(ban_result) {
            case (#Err(e)) { 
                switch (e) {
                    case (#PermissionTypeExists(info)) { return #err("Permission type already exists: " # info.permission) };
                    case (#NotAuthorized(info)) { return #err("Not authorized: " # info.required_permission) };
                    case (#Banned(info)) { return #err("User is banned: " # info.reason) };
                    case _ { return #err("Failed to add ban permission type") };
                }
            };
            case (#Ok()) {};
        };

        // Add permission type for unbanning users
        let unban_result = permissions.add_permission_type(
            UNBAN_USER,
            "Permission to unban users",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        switch(unban_result) {
            case (#Err(e)) { 
                switch (e) {
                    case (#PermissionTypeExists(info)) { return #err("Permission type already exists: " # info.permission) };
                    case (#NotAuthorized(info)) { return #err("Not authorized: " # info.required_permission) };
                    case (#Banned(info)) { return #err("User is banned: " # info.reason) };
                    case _ { return #err("Failed to add unban permission type") };
                }
            };
            case (#Ok()) {};
        };

        // Add permission type for managing ban settings
        let settings_result = permissions.add_permission_type(
            MANAGE_BAN_SETTINGS,
            "Permission to configure ban duration settings",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        switch(settings_result) {
            case (#Err(e)) { 
                switch (e) {
                    case (#PermissionTypeExists(info)) { return #err("Permission type already exists: " # info.permission) };
                    case (#NotAuthorized(info)) { return #err("Not authorized: " # info.required_permission) };
                    case (#Banned(info)) { return #err("User is banned: " # info.reason) };
                    case _ { return #err("Failed to add manage ban settings permission type") };
                }
            };
            case (#Ok()) {};
        };

        #ok(());
    };
}
