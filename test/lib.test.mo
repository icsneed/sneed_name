import Dedup "../src/lib";
import Blob "mo:base/Blob";
import Principal "mo:base/Principal";
import Debug "mo:base/Debug";
import Text "mo:base/Text";
import Vector "mo:vector";
import Map "mo:map/Map";
import Permissions "../src/Permissions";
import Time "mo:base/Time";
import Nat64 "mo:base/Nat64";
import Nat32 "mo:base/Nat32";

// Test static methods
do {
    // Test principals
    let admin1 = Principal.fromText("2vxsx-fae");
    let admin2 = Principal.fromText("rrkah-fqaaa-aaaaa-aaaaq-cai");
    let user1 = Principal.fromText("ryjl3-tyaaa-aaaaa-aaaba-cai");
    let user2 = Principal.fromText("fp274-iaaaa-aaaaq-aacha-cai");

    // Test permission types
    let TEST_PERMISSION = "test_permission";

    Debug.print("Running tests...");
    
    shared func run_tests() : async () {
        await test_admin_management();
        await test_permission_types();
        await test_permission_checking();
        await test_non_admin_permissions();
        Debug.print("All permission tests passed! 🎉");
    };

    // Test admin management functionality
    shared func test_admin_management() : async () {
        let state = Permissions.empty();
        // Set up initial admin with metadata
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = state.dedup.getOrCreateIndexForPrincipal(admin1);
        Map.set(state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);
        let permissions = Permissions.PermissionsManager(state);

        // Test adding admin
        switch(await permissions.add_admin(admin1, admin2, null)) {
            case (#err(e)) { Debug.trap("Failed to add admin2: " # e) };
            case (#ok()) {};
        };

        // Test that admin2 can now add another admin
        switch(await permissions.add_admin(admin2, user1, null)) {
            case (#err(e)) { Debug.trap("Admin2 failed to add user1 as admin: " # e) };
            case (#ok()) {};
        };

        // Test that non-admin cannot add admin
        switch(await permissions.add_admin(user2, user2, null)) {
            case (#err(_)) {}; // Expected error
            case (#ok()) { Debug.trap("Non-admin was able to add admin") };
        };

        // Test removing admin
        switch(await permissions.remove_admin(admin1, user1)) {
            case (#err(e)) { Debug.trap("Failed to remove admin: " # e) };
            case (#ok()) {};
        };

        // Test that removed admin cannot add new admin
        switch(await permissions.add_admin(user1, user2, null)) {
            case (#err(_)) {}; // Expected error
            case (#ok()) { Debug.trap("Removed admin was able to add new admin") };
        };

        Debug.print("✓ Admin management tests passed");
    };

    // Test permission type management
    shared func test_permission_types() : async () {
        let state = Permissions.empty();
        // Set up initial admin with metadata
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = state.dedup.getOrCreateIndexForPrincipal(admin1);
        Map.set(state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);
        let permissions = Permissions.PermissionsManager(state);

        // Test adding simple permission type
        switch(permissions.add_permission_type(TEST_PERMISSION)) {
            case (#err(e)) { Debug.trap("Failed to add permission type: " # e) };
            case (#ok()) {};
        };

        // Test adding duplicate permission type
        switch(permissions.add_permission_type(TEST_PERMISSION)) {
            case (#err(_)) {}; // Expected error
            case (#ok()) { Debug.trap("Was able to add duplicate permission type") };
        };

        // Verify built-in permission types exist
        assert(Map.get(state.permission_types, (Text.hash, Text.equal), Permissions.ADD_ADMIN_PERMISSION) != null);
        assert(Map.get(state.permission_types, (Text.hash, Text.equal), Permissions.REMOVE_ADMIN_PERMISSION) != null);

        Debug.print("✓ Permission type management tests passed");
    };

    // Test permission checking
    shared func test_permission_checking() : async () {
        let state = Permissions.empty();
        // Set up initial admin with metadata
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = state.dedup.getOrCreateIndexForPrincipal(admin1);
        Map.set(state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);
        let permissions = Permissions.PermissionsManager(state);

        // Add test permission
        ignore permissions.add_permission_type(TEST_PERMISSION);

        // Grant permission to user1
        switch(permissions.grant_permission(admin1, user1, TEST_PERMISSION, null)) {
            case (#err(e)) { Debug.trap("Failed to grant permission: " # e) };
            case (#ok()) {};
        };

        // Test permission checks
        assert(permissions.check_permission(user1, TEST_PERMISSION) == true);
        assert(permissions.check_permission(user2, TEST_PERMISSION) == false);
        
        // Admin should have all permissions
        assert(permissions.check_permission(admin1, TEST_PERMISSION) == true);
        assert(permissions.check_permission(admin1, "nonexistent_permission") == true);

        // Test built-in admin permissions
        assert(permissions.check_permission(admin1, Permissions.ADD_ADMIN_PERMISSION) == true);
        assert(permissions.check_permission(admin1, Permissions.REMOVE_ADMIN_PERMISSION) == true);

        // Non-admins should not have admin permissions by default
        assert(permissions.check_permission(user1, Permissions.ADD_ADMIN_PERMISSION) == false);
        assert(permissions.check_permission(user1, Permissions.REMOVE_ADMIN_PERMISSION) == false);

        // Test permission expiration
        let now = Nat64.fromIntWrap(Time.now());
        let expired_time = now + 20;  // Set expiration to future time
        
        Debug.print("Current time: " # debug_show(now));
        Debug.print("Expiration time: " # debug_show(expired_time));
        
        // First grant permission with future expiry - should be valid
        switch(permissions.grant_permission(admin1, user2, TEST_PERMISSION, ?expired_time)) {
            case (#err(e)) { Debug.trap("Failed to grant future permission: " # e) };
            case (#ok()) {};
        };

        // Permission should be valid since expiry is in future
        assert(permissions.check_permission(user2, TEST_PERMISSION) == true);

        // Now grant with past expiry - should be invalid
        let past_time = now - 20;  // Set expiration to past time
        switch(permissions.grant_permission(admin1, user2, TEST_PERMISSION, ?past_time)) {
            case (#err(e)) { Debug.trap("Failed to grant expired permission: " # e) };
            case (#ok()) {};
        };

        // Permission should be invalid since expiry is in past
        assert(permissions.check_permission(user2, TEST_PERMISSION) == false);

        Debug.print("✓ Permission checking tests passed");
    };

    // Test non-admin permission management
    shared func test_non_admin_permissions() : async () {
        let state = Permissions.empty();
        // Set up initial admin with metadata
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = state.dedup.getOrCreateIndexForPrincipal(admin1);
        Map.set(state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);
        let permissions = Permissions.PermissionsManager(state);

        // Grant add_admin permission to user1
        switch(permissions.grant_permission(admin1, user1, Permissions.ADD_ADMIN_PERMISSION, null)) {
            case (#err(e)) { Debug.trap("Failed to grant add_admin permission: " # e) };
            case (#ok()) {};
        };

        // Grant remove_admin permission to user2
        switch(permissions.grant_permission(admin1, user2, Permissions.REMOVE_ADMIN_PERMISSION, null)) {
            case (#err(e)) { Debug.trap("Failed to grant remove_admin permission: " # e) };
            case (#ok()) {};
        };

        // Test that user1 can add admin
        switch(await permissions.add_admin(user1, user2, null)) {
            case (#err(e)) { Debug.trap("User1 failed to add user2 as admin: " # e) };
            case (#ok()) {};
        };

        // Test that user2 can remove admin
        switch(await permissions.remove_admin(user2, user1)) {
            case (#err(e)) { Debug.trap("User2 failed to remove user1 as admin: " # e) };
            case (#ok()) {};
        };

        Debug.print("✓ Non-admin permission management tests passed");
    };

    run_tests();
};