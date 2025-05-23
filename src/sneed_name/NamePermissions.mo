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
        // Add permission to edit any name
        // This is sync-only since it's a simple admin permission
        let edit_result = permissions.add_permission_type(
            EDIT_ANY_NAME,
            "Can edit any user's name",
            func (p : Principal) : Bool { false },  // Only admins can edit any name
            null
        );

        switch(edit_result) {
            case (#err(e)) { return #err(e) };
            case (#ok()) {};
        };

        // Add permission to verify names
        let verify_result = permissions.add_permission_type(
            VERIFY_NAME,
            "Can mark names as verified",
            func (p : Principal) : Bool { false },  // Only admins can verify names
            null
        );

        switch(verify_result) {
            case (#err(e)) { return #err(e) };
            case (#ok()) {};
        };

        #ok(());
    };
}