import Result "mo:base/Result";
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
import SnsPermissions "../src/SnsPermissions";
import T "../src/Types";
import Bans "../src/Bans";
import BanPermissions "../src/BanPermissions";
import NamePermissions "../src/sneed_name/NamePermissions";
import Lib "../src/lib";

// Mock SNS governance canister
actor class MockSnsGovernance() {
    public shared query func list_neurons(caller : Principal) : async [SnsPermissions.Neuron] {
        // Return test neurons where caller has hotkey access
        let neuron1 : SnsPermissions.Neuron = {
            id = ?{ id = Text.encodeUtf8("neuron1") };
            permissions = [{
                principal = ?caller;
                permission_type = [1, 2, 3];  // Some test permissions
            }];
            cached_neuron_stake_e8s = 100_000_000;  // 1 token
            voting_power_percentage_multiplier = 100;  // 1x multiplier
            // Required fields with default values
            staked_maturity_e8s_equivalent = null;
            maturity_e8s_equivalent = 0;
            created_timestamp_seconds = 0;
            source_nns_neuron_id = null;
            auto_stake_maturity = null;
            aging_since_timestamp_seconds = 0;
            dissolve_state = null;
            vesting_period_seconds = null;
            disburse_maturity_in_progress = [];
            followees = [];
            neuron_fees_e8s = 0;
        };
        [neuron1]
    };
};

// Test static methods
do {
    // Test principals
    let admin1 = Principal.fromText("h4f44-ayaaa-aaaaq-aacjq-cai");
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
        await test_sns_permissions();
        await test_name_management();
        await test_ban_system();
        await test_ban_integration();
        Debug.print("All tests passed! 🎉");
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
            case (#Err(e)) { Debug.trap("Failed to add admin2: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test that admin2 can now add another admin
        switch(await permissions.add_admin(admin2, user1, null)) {
            case (#Err(e)) { Debug.trap("Admin2 failed to add user1 as admin: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test that non-admin cannot add admin
        switch(await permissions.add_admin(user2, user2, null)) {
            case (#Err(_)) {}; // Expected error
            case (#Ok()) { Debug.trap("Non-admin was able to add admin") };
        };

        // Test removing admin
        switch(await permissions.remove_admin(admin1, user1)) {
            case (#Err(e)) { Debug.trap("Failed to remove admin: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test that removed admin cannot add new admin
        switch(await permissions.add_admin(user1, user2, null)) {
            case (#Err(_)) {}; // Expected error
            case (#Ok()) { Debug.trap("Removed admin was able to add new admin") };
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

        // Add built-in permission types
        ignore permissions.add_permission_type(
            Permissions.ADD_ADMIN_PERMISSION,
            "Can add new admins",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        ignore permissions.add_permission_type(
            Permissions.REMOVE_ADMIN_PERMISSION,
            "Can remove admins",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );

        // Test adding simple permission type
        switch(permissions.add_permission_type(
            TEST_PERMISSION,
            "Test permission for unit tests",
            ?(24 * 60 * 60 * 1_000_000_000),  // 1 day max
            ?(60 * 60 * 1_000_000_000)  // 1 hour default
        )) {
            case (#Err(e)) { Debug.trap("Failed to add permission type: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test adding duplicate permission type
        switch(permissions.add_permission_type(
            TEST_PERMISSION,
            "Duplicate test permission",
            null,
            null
        )) {
            case (#Err(_)) {}; // Expected error
            case (#Ok()) { Debug.trap("Was able to add duplicate permission type") };
        };

        // Convert permission type texts to indices
        let add_admin_blob = Text.encodeUtf8(Permissions.ADD_ADMIN_PERMISSION);
        let remove_admin_blob = Text.encodeUtf8(Permissions.REMOVE_ADMIN_PERMISSION);
        let add_admin_index = state.dedup.getOrCreateIndex(add_admin_blob);
        let remove_admin_index = state.dedup.getOrCreateIndex(remove_admin_blob);

        // Verify built-in permission types exist
        switch (Map.get(state.permission_types, (func (n : Nat32) : Nat32 { n }, Nat32.equal), add_admin_index)) {
            case (?ptype) {
                assert(ptype.description == "Can add new admins");
                assert(ptype.max_duration != null);
                assert(ptype.default_duration != null);
            };
            case null { Debug.trap("Add admin permission type not found") };
        };
        switch (Map.get(state.permission_types, (func (n : Nat32) : Nat32 { n }, Nat32.equal), remove_admin_index)) {
            case (?ptype) {
                assert(ptype.description == "Can remove admins");
                assert(ptype.max_duration != null);
                assert(ptype.default_duration != null);
            };
            case null { Debug.trap("Remove admin permission type not found") };
        };

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
        ignore permissions.add_permission_type(
            TEST_PERMISSION,
            "Test permission for unit tests",
            ?(24 * 60 * 60 * 1_000_000_000),  // 1 day max
            ?(60 * 60 * 1_000_000_000)  // 1 hour default
        );

        // Grant permission to user1
        switch(permissions.grant_permission(admin1, user1, TEST_PERMISSION, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant permission: " # debug_show(e)) };
            case (#Ok()) {};
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
            case (#Err(e)) { Debug.trap("Failed to grant future permission: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Permission should be valid since expiry is in future
        assert(permissions.check_permission(user2, TEST_PERMISSION) == true);

        // Now grant with past expiry - should be invalid
        let past_time = now - 20;  // Set expiration to past time
        switch(permissions.grant_permission(admin1, user2, TEST_PERMISSION, ?past_time)) {
            case (#Err(e)) { Debug.trap("Failed to grant expired permission: " # debug_show(e)) };
            case (#Ok()) {};
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

        // Add built-in permission types first
        ignore permissions.add_permission_type(
            Permissions.ADD_ADMIN_PERMISSION,
            "Can add new admins",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        ignore permissions.add_permission_type(
            Permissions.REMOVE_ADMIN_PERMISSION,
            "Can remove admins",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );

        // Grant add_admin permission to user1
        switch(permissions.grant_permission(admin1, user1, Permissions.ADD_ADMIN_PERMISSION, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant add_admin permission: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Grant remove_admin permission to user2
        switch(permissions.grant_permission(admin1, user2, Permissions.REMOVE_ADMIN_PERMISSION, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant remove_admin permission: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test that user1 can add admin
        switch(await permissions.add_admin(user1, user2, null)) {
            case (#Err(e)) { Debug.trap("User1 failed to add user2 as admin: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test that user2 can remove admin
        switch(await permissions.remove_admin(user2, user1)) {
            case (#Err(e)) { Debug.trap("User2 failed to remove user1 as admin: " # debug_show(e)) };
            case (#Ok()) {};
        };

        Debug.print("✓ Non-admin permission management tests passed");
    };

    // Test SNS permissions functionality
    shared func test_sns_permissions() : async () {
        Debug.print("Testing SNS permissions...");

        // Set up base permissions
        let state = Permissions.empty();
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = state.dedup.getOrCreateIndexForPrincipal(admin1);
        Map.set(state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);
        let permissions = Permissions.PermissionsManager(state);

        // Create ban system with dummy permission checker
        let ban_state = Bans.empty();
        let ban_system = Bans.Bans(ban_state, state.dedup, func(p: Principal, perm: Text) : Bool { false });

        // Set up SNS permissions
        let sns_state = SnsPermissions.from_stable(
            SnsPermissions.empty_stable(),
            permissions
        );
        let sns_permissions = SnsPermissions.SnsPermissions(sns_state);

        // Create mock SNS governance canister
        let mock_governance = await MockSnsGovernance();

        // Set up name index
        let name_state = Lib.empty_stable();
        let name_index = Lib.NameIndex(name_state, ?sns_permissions);

        // Test setting SNS permission settings
        let settings : SnsPermissions.SnsPermissionSettings = {
            min_voting_power = 50_000_000;  // 0.5 tokens
            max_duration = ?(30 * 24 * 60 * 60 * 1_000_000_000);  // 30 days
            default_duration = ?(24 * 60 * 60 * 1_000_000_000);  // 1 day
        };

        switch(sns_permissions.set_permission_settings(
            admin1,
            Principal.fromActor(mock_governance),
            Lib.SET_SNS_NEURON_NAME_PERMISSION,
            settings
        )) {
            case (#err(e)) { Debug.trap("Failed to set SNS permission settings: " # e) };
            case (#ok()) {};
        };

        // Test neuron access
        let test_neuron_id = { id = Text.encodeUtf8("neuron1") };
        let has_access = await sns_permissions.has_neuron_access(
            user1,
            test_neuron_id,
            mock_governance
        );
        assert(has_access == true);

        // Test setting neuron name
        switch(await* name_index.set_sns_neuron_name(
            user1,
            test_neuron_id,
            "test-neuron",
            mock_governance
        )) {
            case (#Err(e)) { Debug.trap("Failed to set neuron name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify neuron name was set
        switch(name_index.get_sns_neuron_name(test_neuron_id)) {
            case null { Debug.trap("Neuron name not found") };
            case (?name) {
                assert(name.name == "test-neuron");
                assert(name.created_by == user1);
            };
        };

        Debug.print("✓ SNS permissions tests passed");
    };

    // Test name management functionality
    shared func test_name_management() : async () {
        Debug.print("Testing name management...");

        // Set up base permissions
        let state = Permissions.empty();
        let permissions = Permissions.PermissionsManager(state);

        // Set up name index
        let name_state = Lib.empty_stable();
        let name_index = Lib.NameIndex(name_state, null);  // No SNS permissions needed

        // Test setting principal name
        switch(await* name_index.set_principal_name(user1, user1, "test-user")) {
            case (#Err(e)) { Debug.trap("Failed to set principal name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify principal name was set
        switch(name_index.get_principal_name(user1)) {
            case null { Debug.trap("Principal name not found") };
            case (?name) {
                assert(name.name == "test-user");
                assert(name.created_by == user1);
            };
        };

        // Test name lookup
        switch(name_index.get_name_principal("test-user")) {
            case null { Debug.trap("Principal not found by name") };
            case (?p) {
                assert(Principal.equal(p, user1));
            };
        };

        // Test name taken check
        assert(name_index.is_name_taken("test-user") == true);
        assert(name_index.is_name_taken("nonexistent") == false);

        // Test setting name for another principal (should fail)
        switch(await* name_index.set_principal_name(user2, user1, "another-name")) {
            case (#Err(_)) {}; // Expected error
            case (#Ok()) { Debug.trap("Should not be able to set name for another principal") };
        };

        Debug.print("✓ Name management tests passed");
    };

    // Test basic ban system functionality
    shared func test_ban_system() : async () {
        Debug.print("Testing ban system...");

        // Set up permissions
        let state = Permissions.empty();
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = state.dedup.getOrCreateIndexForPrincipal(admin1);
        Map.set(state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);
        let permissions = Permissions.PermissionsManager(state);

        // Add built-in permission types first
        ignore permissions.add_permission_type(
            Permissions.ADD_ADMIN_PERMISSION,
            "Can add new admins",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        ignore permissions.add_permission_type(
            Permissions.REMOVE_ADMIN_PERMISSION,
            "Can remove admins",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );

        // Add ban permission types
        switch(BanPermissions.add_ban_permissions(permissions)) {
            case (#err(e)) { Debug.trap("Failed to add ban permissions: " # e) };
            case (#ok()) {};
        };

        // Set up ban system
        let ban_state = Bans.empty();
        let ban_system = Bans.Bans(ban_state, state.dedup, func(p: Principal, perm: Text) : Bool {
            permissions.check_permission(p, perm)
        });

        // Grant ban permissions to user1
        switch(permissions.grant_permission(admin1, user1, BanPermissions.BAN_USER, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant ban permission: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Grant unban permission to admin1
        switch(permissions.grant_permission(admin1, admin1, BanPermissions.UNBAN_USER, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant unban permission: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Grant manage ban settings permission to admin1
        switch(permissions.grant_permission(admin1, admin1, BanPermissions.MANAGE_BAN_SETTINGS, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant manage ban settings permission: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test banning a user
        switch(ban_system.ban_user(user1, user2, ?(24), "Test ban")) {
            case (#err(e)) { Debug.trap("Failed to ban user: " # e) };
            case (#ok()) {};
        };

        // Verify user is banned
        assert(ban_system.is_banned(user2) == true);

        // Test ban status check
        switch(ban_system.check_ban_status(user2)) {
            case (#err(_)) { Debug.trap("Ban status check failed") };
            case (#ok(msg)) {
                assert(Text.contains(msg, #text "banned"));
            };
        };

        // Test ban log
        switch(ban_system.get_ban_log(admin1)) {
            case (#err(e)) { Debug.trap("Failed to get ban log: " # e) };
            case (#ok(log)) {
                assert(log.size() == 1);
                assert(Principal.equal(log[0].user, user2));
                assert(Principal.equal(log[0].admin, user1));
                assert(log[0].reason == "Test ban");
            };
        };

        // Test unbanning
        switch(ban_system.unban_user(admin1, user2)) {
            case (#err(e)) { Debug.trap("Failed to unban user: " # e) };
            case (#ok()) {};
        };

        // Verify user is no longer banned
        assert(ban_system.is_banned(user2) == false);

        Debug.print("✓ Ban system tests passed");
    };

    // Test ban system integration with permissions and name management
    shared func test_ban_integration() : async () {
        Debug.print("Testing ban integration...");

        // Set up permissions first (this contains the dedup and ban system)
        let state = Permissions.empty();
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = state.dedup.getOrCreateIndexForPrincipal(admin1);
        Map.set(state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);
        let permissions = Permissions.PermissionsManager(state);

        // Add built-in permission types first
        ignore permissions.add_permission_type(
            Permissions.ADD_ADMIN_PERMISSION,
            "Can add new admins",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );
        ignore permissions.add_permission_type(
            Permissions.REMOVE_ADMIN_PERMISSION,
            "Can remove admins",
            ?(365 * 24 * 60 * 60 * 1_000_000_000),  // 1 year max
            ?(30 * 24 * 60 * 60 * 1_000_000_000)    // 30 days default
        );

        // Add required permission types
        switch(BanPermissions.add_ban_permissions(permissions)) {
            case (#err(e)) { Debug.trap("Failed to add ban permissions: " # e) };
            case (#ok()) {};
        };
        switch(NamePermissions.add_name_permissions(permissions)) {
            case (#err(e)) { Debug.trap("Failed to add name permissions: " # e) };
            case (#ok()) {};
        };

        // Set up SNS permissions using the same permissions instance (which contains dedup and bans)
        let sns_state = SnsPermissions.from_stable(
            SnsPermissions.empty_stable(),
            permissions  // This ensures SNS permissions uses the same dedup and ban system
        );
        let sns_permissions = SnsPermissions.SnsPermissions(sns_state);

        // Set up name index using the SNS permissions (which will use the shared dedup and ban system)
        let name_state = Lib.empty_stable();
        let name_index = Lib.NameIndex(name_state, ?sns_permissions);

        // Grant permissions to user1
        switch(permissions.grant_permission(admin1, user1, NamePermissions.EDIT_ANY_NAME, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant name permission: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Grant ban permissions to admin1
        switch(permissions.grant_permission(admin1, admin1, BanPermissions.BAN_USER, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant ban permission: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify user1 can set names before being banned
        switch(await* name_index.set_principal_name(user1, user2, "test-name")) {
            case (#Err(e)) { Debug.trap("Failed to set name before ban: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Ban user1 using the permissions system (which contains the ban system)
        switch(permissions.ban_user(admin1, user1, "Test integration", ?(Time.now() + 24 * 3600 * 1_000_000_000))) {
            case (#Err(e)) { Debug.trap("Failed to ban user: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify banned user1 cannot set names despite having permission
        switch(await* name_index.set_principal_name(user1, user2, "another-name")) {
            case (#Err(_)) {}; // Expected error
            case (#Ok()) { Debug.trap("Banned user should not be able to set names") };
        };

        // Create mock SNS governance
        let mock_governance = await MockSnsGovernance();

        // Test that banned user cannot use SNS permissions
        let test_neuron_id = { id = Text.encodeUtf8("neuron1") };
        switch(await* name_index.set_sns_neuron_name(
            user1,
            test_neuron_id,
            "test-neuron",
            mock_governance
        )) {
            case (#Err(_)) {}; // Expected error
            case (#Ok()) { Debug.trap("Banned user should not be able to set neuron names") };
        };

        // Grant unban permission to admin1
        switch(permissions.grant_permission(admin1, admin1, BanPermissions.UNBAN_USER, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant unban permission: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Unban user1
        switch(permissions.unban_user(admin1, user1)) {
            case (#Err(e)) { Debug.trap("Failed to unban user: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify user1 can set names again after unban
        switch(await* name_index.set_principal_name(user1, user2, "post-ban-name")) {
            case (#Err(e)) { Debug.trap("Failed to set name after unban: " # debug_show(e)) };
            case (#Ok()) {};
        };

        Debug.print("✓ Ban integration tests passed");
    };

    run_tests();
};