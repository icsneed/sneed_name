import Permissions "../Permissions";
import Principal "mo:base/Principal";
import Result "mo:base/Result";
import T "../Types";

module NamePermissions {
    // Permission type keys
    public let EDIT_ANY_NAME = "edit_any_name";  // Can edit anyone's name
    public let VERIFY_NAME = "verify_name";      // Can mark names as verified
    public let UNVERIFY_NAME = "unverify_name";  // Can remove verification from names

    // SNS naming permission constants
    public let SET_SNS_NEURON_NAME_PERMISSION = "set_sns_neuron_name";
    public let REMOVE_SNS_NEURON_NAME_PERMISSION = "remove_sns_neuron_name";
    public let SET_SNS_PRINCIPAL_NAME_PERMISSION = "set_sns_principal_name";
    public let REMOVE_SNS_PRINCIPAL_NAME_PERMISSION = "remove_sns_principal_name";
    public let VERIFY_SNS_NEURON_NAME_PERMISSION = "verify_sns_neuron_name";
    public let UNVERIFY_SNS_NEURON_NAME_PERMISSION = "unverify_sns_neuron_name";

    // ICRC1 account naming permission constants
    public let SET_ACCOUNT_NAME_PERMISSION = "set_account_name";
    public let REMOVE_ACCOUNT_NAME_PERMISSION = "remove_account_name";

    // Banned word management permission constants
    public let ADD_BANNED_WORD_PERMISSION = "add_banned_word";
    public let REMOVE_BANNED_WORD_PERMISSION = "remove_banned_word";

    public func add_name_permissions(
        permissions : Permissions.PermissionsManager
    ) : T.PermissionResult<()> {
        // Add permission type for editing any name
        let edit_result = permissions.add_permission_type(
            EDIT_ANY_NAME,
            "Permission to edit any user's name",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        switch(edit_result) {
            case (#Err(e)) { return #Err(e) };
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
            case (#Err(e)) { return #Err(e) };
            case (#Ok()) {};
        };

        // Add permission type for unverifying names
        let unverify_result = permissions.add_permission_type(
            UNVERIFY_NAME,
            "Permission to remove verification from user names",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        switch(unverify_result) {
            case (#Err(e)) { return #Err(e) };
            case (#Ok()) {};
        };

        // Add permission type for setting SNS neuron names
        let set_neuron_result = permissions.add_permission_type(
            SET_SNS_NEURON_NAME_PERMISSION,
            "Permission to set SNS neuron names",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        switch(set_neuron_result) {
            case (#Err(e)) { return #Err(e) };
            case (#Ok()) {};
        };

        // Add permission type for removing SNS neuron names
        let remove_neuron_result = permissions.add_permission_type(
            REMOVE_SNS_NEURON_NAME_PERMISSION,
            "Permission to remove SNS neuron names",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        switch(remove_neuron_result) {
            case (#Err(e)) { return #Err(e) };
            case (#Ok()) {};
        };

        // Add permission type for setting SNS principal names
        let set_principal_result = permissions.add_permission_type(
            SET_SNS_PRINCIPAL_NAME_PERMISSION,
            "Permission to set SNS principal names",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        switch(set_principal_result) {
            case (#Err(e)) { return #Err(e) };
            case (#Ok()) {};
        };

        // Add permission type for removing SNS principal names
        let remove_principal_result = permissions.add_permission_type(
            REMOVE_SNS_PRINCIPAL_NAME_PERMISSION,
            "Permission to remove SNS principal names",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        switch(remove_principal_result) {
            case (#Err(e)) { return #Err(e) };
            case (#Ok()) {};
        };

        // Add permission type for verifying SNS neuron names
        let verify_neuron_result = permissions.add_permission_type(
            VERIFY_SNS_NEURON_NAME_PERMISSION,
            "Permission to verify SNS neuron names",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        switch(verify_neuron_result) {
            case (#Err(e)) { return #Err(e) };
            case (#Ok()) {};
        };

        // Add permission type for unverifying SNS neuron names
        let unverify_neuron_result = permissions.add_permission_type(
            UNVERIFY_SNS_NEURON_NAME_PERMISSION,
            "Permission to unverify SNS neuron names",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        switch(unverify_neuron_result) {
            case (#Err(e)) { return #Err(e) };
            case (#Ok()) {};
        };

        // Add permission type for setting ICRC1 account names
        let set_account_result = permissions.add_permission_type(
            SET_ACCOUNT_NAME_PERMISSION,
            "Permission to set ICRC1 account names",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        switch(set_account_result) {
            case (#Err(e)) { return #Err(e) };
            case (#Ok()) {};
        };

        // Add permission type for removing ICRC1 account names
        let remove_account_result = permissions.add_permission_type(
            REMOVE_ACCOUNT_NAME_PERMISSION,
            "Permission to remove ICRC1 account names",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        switch(remove_account_result) {
            case (#Err(e)) { return #Err(e) };
            case (#Ok()) {};
        };

        // Add permission type for adding banned words
        let add_banned_word_result = permissions.add_permission_type(
            ADD_BANNED_WORD_PERMISSION,
            "Permission to add banned words",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        switch(add_banned_word_result) {
            case (#Err(e)) { return #Err(e) };
            case (#Ok()) {};
        };

        // Add permission type for removing banned words
        let remove_banned_word_result = permissions.add_permission_type(
            REMOVE_BANNED_WORD_PERMISSION,
            "Permission to remove banned words",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        switch(remove_banned_word_result) {
            case (#Err(e)) { return #Err(e) };
            case (#Ok()) {};
        };

        #Ok(());
    };
}