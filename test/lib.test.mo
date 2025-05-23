import Dedup "../src/lib";
import Blob "mo:base/Blob";
import Principal "mo:base/Principal";
import Debug "mo:base/Debug";
import Text "mo:base/Text";
import Vector "mo:vector";
import Map "mo:map/Map";
import Permissions "../src/Permissions";
import Result "mo:base/Result";

actor {
    // Test principals
    let admin1 = Principal.fromText("2vxsx-fae");
    let admin2 = Principal.fromText("rrkah-fqaaa-aaaaa-aaaaq-cai");
    let user1 = Principal.fromText("w3gef-eqaaa-aaaaa-aaaba-cai");
    let user2 = Principal.fromText("un4fu-tqaaa-aaaaa-aaabq-cai");

    // Test permission types
    let TEST_PERMISSION = "test_permission";
    let ASYNC_PERMISSION = "async_permission";

    // Helper function for async permission check
    func async_check(p : Principal) : async Bool {
        Principal.equal(p, user2)
    };

    public shared func run_tests() : async () {
        await test_admin_management();
        await test_permission_types();
        await test_permission_checking();
        Debug.print("All permission tests passed! 🎉");
    };

    // Test admin management functionality
    private shared func test_admin_management() : async () {
        let state = Permissions.empty();
        let permissions = Permissions.PermissionsManager(state);

        // Test adding admin
        switch(permissions.add_admin(admin1, admin2)) {
            case (#err(e)) { Debug.trap("Failed to add admin2: " # e) };
            case (#ok()) {};
        };

        // Test that admin2 can now add another admin
        switch(permissions.add_admin(admin2, user1)) {
            case (#err(e)) { Debug.trap("Admin2 failed to add user1 as admin: " # e) };
            case (#ok()) {};
        };

        // Test that non-admin cannot add admin
        switch(permissions.add_admin(user2, user2)) {
            case (#err(_)) {}; // Expected error
            case (#ok()) { Debug.trap("Non-admin was able to add admin") };
        };

        // Test removing admin
        switch(permissions.remove_admin(admin1, user1)) {
            case (#err(e)) { Debug.trap("Failed to remove admin: " # e) };
            case (#ok()) {};
        };

        // Test that removed admin cannot add new admin
        switch(permissions.add_admin(user1, user2)) {
            case (#err(_)) {}; // Expected error
            case (#ok()) { Debug.trap("Removed admin was able to add new admin") };
        };

        Debug.print("✓ Admin management tests passed");
    };

    // Test permission type management
    private shared func test_permission_types() : async () {
        let state = Permissions.empty();
        let permissions = Permissions.PermissionsManager(state);

        // Add initial admin
        ignore permissions.add_admin(admin1, admin1);

        // Test adding simple permission type
        switch(permissions.add_permission_type(
            admin1,
            TEST_PERMISSION,
            "Test permission",
            func (p : Principal) : Bool { Principal.equal(p, user1) },
            null
        )) {
            case (#err(e)) { Debug.trap("Failed to add permission type: " # e) };
            case (#ok()) {};
        };

        // Test adding async permission type
        switch(permissions.add_permission_type(
            admin1,
            ASYNC_PERMISSION,
            "Async test permission",
            func (p : Principal) : Bool { false },
            ?async_check
        )) {
            case (#err(e)) { Debug.trap("Failed to add async permission type: " # e) };
            case (#ok()) {};
        };

        // Test that non-admin cannot add permission type
        switch(permissions.add_permission_type(
            user2,
            "unauthorized_permission",
            "Should fail",
            func (p : Principal) : Bool { true },
            null
        )) {
            case (#err(_)) {}; // Expected error
            case (#ok()) { Debug.trap("Non-admin was able to add permission type") };
        };

        // Test removing permission type
        switch(permissions.remove_permission_type(admin1, TEST_PERMISSION)) {
            case (#err(e)) { Debug.trap("Failed to remove permission type: " # e) };
            case (#ok()) {};
        };

        Debug.print("✓ Permission type management tests passed");
    };

    // Test permission checking
    private shared func test_permission_checking() : async () {
        let state = Permissions.empty();
        let permissions = Permissions.PermissionsManager(state);

        // Add initial admin
        ignore permissions.add_admin(admin1, admin1);

        // Add test permission that only allows user1
        ignore permissions.add_permission_type(
            admin1,
            TEST_PERMISSION,
            "Test permission",
            func (p : Principal) : Bool { Principal.equal(p, user1) },
            null
        );

        // Test sync permission checks
        assert(await permissions.check_permission(user1, TEST_PERMISSION) == true);
        assert(await permissions.check_permission(user2, TEST_PERMISSION) == false);
        
        // Admin should have all permissions
        assert(await permissions.check_permission(admin1, TEST_PERMISSION) == true);
        assert(await permissions.check_permission(admin1, "nonexistent_permission") == true);

        // Test async permission
        ignore permissions.add_permission_type(
            admin1,
            ASYNC_PERMISSION,
            "Async test permission",
            func (p : Principal) : Bool { false },
            ?async_check
        );

        assert(await permissions.check_permission(user2, ASYNC_PERMISSION) == true);
        assert(await permissions.check_permission(user1, ASYNC_PERMISSION) == false);

        Debug.print("✓ Permission checking tests passed");
    };
}
