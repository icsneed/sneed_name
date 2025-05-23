import Dedup "../src/lib";
import Blob "mo:base/Blob";
import Principal "mo:base/Principal";
import Debug "mo:base/Debug";
import Text "mo:base/Text";
import Vector "mo:vector";
import Map "mo:map/Map";
import Permissions "../src/Permissions";

// Test static methods
do {

    // Test principals
    let admin1 = Principal.fromText("2vxsx-fae");
    let admin2 = Principal.fromText("rrkah-fqaaa-aaaaa-aaaaq-cai");
    let user1 = Principal.fromText("ryjl3-tyaaa-aaaaa-aaaba-cai");
    let user2 = Principal.fromText("fp274-iaaaa-aaaaq-aacha-cai");

    // Test permission types
    let TEST_PERMISSION = "test_permission";
    let ASYNC_PERMISSION = "async_permission";

    // Helper function for async permission check
    func async_check(p : Principal) : async Bool {
        Principal.equal(p, user2)
    };

    Debug.print("Running tests...");
    
    shared func run_tests() : async () {
        await test_admin_management();
        await test_permission_types();
        await test_permission_checking();
        Debug.print("All permission tests passed! 🎉");
    };

    // Test admin management functionality
    shared func test_admin_management() : async () {
        let state = Permissions.empty();
        // Set up initial admin
        state.stable_state.admins := [admin1];
        let permissions = Permissions.PermissionsManager(state);

        // Test adding admin
        switch(await permissions.add_admin(admin1, admin2)) {
            case (#err(e)) { Debug.trap("Failed to add admin2: " # e) };
            case (#ok()) {};
        };

        // Test that admin2 can now add another admin
        switch(await permissions.add_admin(admin2, user1)) {
            case (#err(e)) { Debug.trap("Admin2 failed to add user1 as admin: " # e) };
            case (#ok()) {};
        };

        // Test that non-admin cannot add admin
        switch(await permissions.add_admin(user2, user2)) {
            case (#err(_)) {}; // Expected error
            case (#ok()) { Debug.trap("Non-admin was able to add admin") };
        };

        // Test removing admin
        switch(await permissions.remove_admin(admin1, user1)) {
            case (#err(e)) { Debug.trap("Failed to remove admin: " # e) };
            case (#ok()) {};
        };

        // Test that removed admin cannot add new admin
        switch(await permissions.add_admin(user1, user2)) {
            case (#err(_)) {}; // Expected error
            case (#ok()) { Debug.trap("Removed admin was able to add new admin") };
        };

        Debug.print("✓ Admin management tests passed");
    };


    // Test permission type management
    shared func test_permission_types() : async () {
        let state = Permissions.empty();
        // Set up initial admin
        state.stable_state.admins := [admin1];
        let permissions = Permissions.PermissionsManager(state);

        // Test adding simple permission type
        switch(permissions.add_permission_type(
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
            ASYNC_PERMISSION,
            "Async test permission",
            func (p : Principal) : Bool { false },
            ?async_check
        )) {
            case (#err(e)) { Debug.trap("Failed to add async permission type: " # e) };
            case (#ok()) {};
        };

        // Test removing permission type
        switch(permissions.remove_permission_type(admin1, TEST_PERMISSION)) {
            case (#err(e)) { Debug.trap("Failed to remove permission type: " # e) };
            case (#ok()) {};
        };

        Debug.print("✓ Permission type management tests passed");
    };

    // Test permission checking
    shared func test_permission_checking() : async () {
        let state = Permissions.empty();
        // Set up initial admin
        state.stable_state.admins := [admin1];
        let permissions = Permissions.PermissionsManager(state);

        // Add test permission that only allows user1
        ignore permissions.add_permission_type(
            TEST_PERMISSION,
            "Test permission",
            func (p : Principal) : Bool { Principal.equal(p, user1) },
            null
        );

        // Test sync permission checks
        let check1 = await permissions.check_permission(user1, TEST_PERMISSION);
        assert(check1 == true);
        let check2 = await permissions.check_permission(user2, TEST_PERMISSION);
        assert(check2 == false);
        
        // Admin should have all permissions
        let check3 = await permissions.check_permission(admin1, TEST_PERMISSION);
        assert(check3 == true);
        let check4 = await permissions.check_permission(admin1, "nonexistent_permission");
        assert(check4 == true);

        // Test async permission
        ignore permissions.add_permission_type(
            ASYNC_PERMISSION,
            "Async test permission",
            func (p : Principal) : Bool { false },
            ?async_check
        );

        let check5 = await permissions.check_permission(user2, ASYNC_PERMISSION);
        assert(check5 == true);
        let check6 = await permissions.check_permission(user1, ASYNC_PERMISSION);
        assert(check6 == false);

        Debug.print("✓ Permission checking tests passed");
    };

    run_tests();
};