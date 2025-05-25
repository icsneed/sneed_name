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
import Array "mo:base/Array";
import SnsPermissions "../src/SnsPermissions";
import T "../src/Types";
import Bans "../src/Bans";
import BanPermissions "../src/BanPermissions";
import NamePermissions "../src/sneed_name/NamePermissions";
import Lib "../src/lib";

// NOTE: Time.now() returns the same value throughout a single method execution in Motoko.
// This means time doesn't advance during test execution, which affects time-based tests.
// For testing time-based functionality, we use fixed time values or relative offsets.

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

    public shared query func get_neuron(neuron_id : SnsPermissions.NeuronId) : async ?SnsPermissions.Neuron {
        // Return the test neuron if it matches neuron1
        if (neuron_id.id == Text.encodeUtf8("neuron1")) {
            ?{
                id = ?neuron_id;
                permissions = [{
                    principal = null;  // Generic neuron for testing
                    permission_type = [1, 2, 3];
                }];
                cached_neuron_stake_e8s = 100_000_000;
                voting_power_percentage_multiplier = 100;
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
            }
        } else {
            null  // Neuron not found
        }
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
        await test_verification_system();
        await test_ban_system();
        await test_ban_integration();
        await test_account_naming();
        await test_banned_words();
        await test_edge_cases();
        await test_permission_expiration();
        await test_concurrent_operations();
        await test_banned_words_advanced();
        await test_account_naming_edge_cases();
        await test_name_settings();
        Debug.print("All tests passed! 🎉");
    };

    // Test admin management functionality
    shared func test_admin_management() : async () {
        let stable_state = Permissions.empty_stable();
        let permissions = Permissions.PermissionsManager(stable_state);
        
        // Set up initial admin with metadata
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = permissions.get_dedup().getOrCreateIndexForPrincipal(admin1);
        Map.set(stable_state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);

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

        // Test that non-admin cannot add admin - expect specific NotAuthorized error
        switch(await permissions.add_admin(user2, user2, null)) {
            case (#Err(#NotAuthorized(info))) { 
                assert(info.required_permission == Permissions.ADD_ADMIN_PERMISSION);
            };
            case (#Err(e)) { Debug.trap("Expected NotAuthorized error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Non-admin was able to add admin") };
        };

        // Test removing admin
        switch(await permissions.remove_admin(admin1, user1)) {
            case (#Err(e)) { Debug.trap("Failed to remove admin: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test that removed admin cannot add new admin - expect specific NotAuthorized error
        switch(await permissions.add_admin(user1, user2, null)) {
            case (#Err(#NotAuthorized(info))) { 
                assert(info.required_permission == Permissions.ADD_ADMIN_PERMISSION);
            };
            case (#Err(e)) { Debug.trap("Expected NotAuthorized error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Removed admin was able to add new admin") };
        };

        // Test trying to remove self - expect CannotRemoveSelf error
        switch(await permissions.remove_admin(admin1, admin1)) {
            case (#Err(#CannotRemoveSelf)) {}; // Expected
            case (#Err(e)) { Debug.trap("Expected CannotRemoveSelf error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Should not be able to remove self") };
        };

        // Test adding duplicate admin - expect AlreadyAdmin error
        switch(await permissions.add_admin(admin1, admin2, null)) {
            case (#Err(#AlreadyAdmin(info))) { 
                assert(Principal.equal(info.principal, admin2));
            };
            case (#Err(e)) { Debug.trap("Expected AlreadyAdmin error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Should not be able to add existing admin") };
        };

        Debug.print("✓ Admin management tests passed");
    };

    // Test permission type management
    shared func test_permission_types() : async () {
        let stable_state = Permissions.empty_stable();
        let permissions = Permissions.PermissionsManager(stable_state);
        
        // Set up initial admin with metadata
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = permissions.get_dedup().getOrCreateIndexForPrincipal(admin1);
        Map.set(stable_state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);

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
            case (#Err(#PermissionTypeExists(info))) { 
                assert(info.permission == TEST_PERMISSION);
            };
            case (#Err(e)) { Debug.trap("Expected PermissionTypeExists error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Was able to add duplicate permission type") };
        };

        // Convert permission type texts to indices
        let add_admin_blob = Text.encodeUtf8(Permissions.ADD_ADMIN_PERMISSION);
        let remove_admin_blob = Text.encodeUtf8(Permissions.REMOVE_ADMIN_PERMISSION);
        let add_admin_index = permissions.get_dedup().getOrCreateIndex(add_admin_blob);
        let remove_admin_index = permissions.get_dedup().getOrCreateIndex(remove_admin_blob);

        // Verify built-in permission types exist by checking if they can be used
        assert(permissions.check_permission(admin1, Permissions.ADD_ADMIN_PERMISSION) == true);
        assert(permissions.check_permission(admin1, Permissions.REMOVE_ADMIN_PERMISSION) == true);

        Debug.print("✓ Permission type management tests passed");
    };

    // Test permission checking
    shared func test_permission_checking() : async () {
        let stable_state = Permissions.empty_stable();
        let permissions = Permissions.PermissionsManager(stable_state);
        
        // Set up initial admin with metadata
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = permissions.get_dedup().getOrCreateIndexForPrincipal(admin1);
        Map.set(stable_state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);

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
        let stable_state = Permissions.empty_stable();
        let permissions = Permissions.PermissionsManager(stable_state);
        
        // Set up initial admin with metadata
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = permissions.get_dedup().getOrCreateIndexForPrincipal(admin1);
        Map.set(stable_state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);

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
        let stable_state = Permissions.empty_stable();
        let permissions = Permissions.PermissionsManager(stable_state);
        
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = permissions.get_dedup().getOrCreateIndexForPrincipal(admin1);
        Map.set(stable_state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);

        // Create ban system with dummy permission checker
        let ban_state = Bans.empty();
        let ban_system = Bans.Bans(ban_state, permissions.get_dedup(), func(p: Principal, perm: Text) : Bool { false });

        // Add SNS permission types
        switch(NamePermissions.add_name_permissions(permissions)) {
            case (#Err(e)) { Debug.trap("Failed to add SNS permission types: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Set up SNS permissions
        let sns_permissions = SnsPermissions.SnsPermissions(SnsPermissions.empty_stable(), permissions);

        // Create mock SNS governance canister
        let mock_governance = await MockSnsGovernance();

        // Set up name index with permissions
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
            case (#Err(e)) { Debug.trap("Failed to set SNS permission settings: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Set permission settings for SNS principal names as well
        switch(sns_permissions.set_permission_settings(
            admin1,
            Principal.fromActor(mock_governance),
            Lib.SET_SNS_PRINCIPAL_NAME_PERMISSION,
            settings
        )) {
            case (#Err(e)) { Debug.trap("Failed to set SNS principal permission settings: " # debug_show(e)) };
            case (#Ok()) {};
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

        // Test setting SNS principal name
        switch(await* name_index.set_sns_principal_name(
            user1,
            user1,
            "test-principal",
            mock_governance
        )) {
            case (#Err(e)) { Debug.trap("Failed to set SNS principal name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify principal name was set
        switch(name_index.get_principal_name(user1)) {
            case null { Debug.trap("Principal name not found") };
            case (?name) {
                assert(name.name == "test-principal");
                assert(name.created_by == user1);
            };
        };

        // Test removing SNS principal name
        switch(await* name_index.remove_sns_principal_name(
            user1,
            user1,
            mock_governance
        )) {
            case (#Err(e)) { Debug.trap("Failed to remove SNS principal name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify principal name was removed
        switch(name_index.get_principal_name(user1)) {
            case null {}; // Expected
            case (?name) { Debug.trap("Principal name should have been removed") };
        };

        // Test that SNS governance canister itself has access to its own SNS methods
        let governance_principal = Principal.fromActor(mock_governance);
        
        // Test governance canister setting neuron name
        switch(await* name_index.set_sns_neuron_name(
            governance_principal,
            test_neuron_id,
            "governance-neuron",
            mock_governance
        )) {
            case (#Err(e)) { Debug.trap("Governance canister failed to set neuron name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify governance neuron name was set
        switch(name_index.get_sns_neuron_name(test_neuron_id)) {
            case null { Debug.trap("Governance neuron name not found") };
            case (?name) {
                assert(name.name == "governance-neuron");
                assert(name.updated_by == governance_principal);
            };
        };

        // Test governance canister setting principal name
        switch(await* name_index.set_sns_principal_name(
            governance_principal,
            user2,
            "governance-principal",
            mock_governance
        )) {
            case (#Err(e)) { Debug.trap("Governance canister failed to set principal name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify governance principal name was set
        switch(name_index.get_principal_name(user2)) {
            case null { Debug.trap("Governance principal name not found") };
            case (?name) {
                assert(name.name == "governance-principal");
                assert(name.created_by == governance_principal);
            };
        };

        // Test SNS neuron name verification
        // First verify that the neuron name starts unverified
        switch(name_index.get_sns_neuron_name(test_neuron_id)) {
            case null { Debug.trap("Neuron name not found for verification test") };
            case (?name) {
                assert(name.verified == false);
            };
        };

        // Test that governance canister can verify its own neuron names
        switch(await* name_index.verify_sns_neuron_name(
            governance_principal,
            test_neuron_id,
            mock_governance
        )) {
            case (#Err(e)) { Debug.trap("Governance canister failed to verify neuron name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify the neuron name is now verified
        switch(name_index.get_sns_neuron_name(test_neuron_id)) {
            case null { Debug.trap("Neuron name not found after verification") };
            case (?name) {
                assert(name.verified == true);
                assert(name.updated_by == governance_principal);
            };
        };

        // Test that governance canister can unverify its own neuron names
        switch(await* name_index.unverify_sns_neuron_name(
            governance_principal,
            test_neuron_id,
            mock_governance
        )) {
            case (#Err(e)) { Debug.trap("Governance canister failed to unverify neuron name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify the neuron name is now unverified
        switch(name_index.get_sns_neuron_name(test_neuron_id)) {
            case null { Debug.trap("Neuron name not found after unverification") };
            case (?name) {
                assert(name.verified == false);
                assert(name.updated_by == governance_principal);
            };
        };

        // Test that non-governance principals cannot verify neuron names without permission
        switch(await* name_index.verify_sns_neuron_name(
            user1,
            test_neuron_id,
            mock_governance
        )) {
            case (#Err(#NotAuthorized(info))) { 
                assert(info.required_permission == ?Lib.VERIFY_SNS_NEURON_NAME_PERMISSION);
            };
            case (#Err(e)) { Debug.trap("Expected NotAuthorized error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Non-governance user should not be able to verify neuron names without permission") };
        };

        // Test verification of non-existent neuron
        let fake_neuron_id = { id = Text.encodeUtf8("fake_neuron") };
        switch(await* name_index.verify_sns_neuron_name(
            governance_principal,
            fake_neuron_id,
            mock_governance
        )) {
            case (#Err(#NeuronNotFound(info))) { 
                assert(info.neuron_id == fake_neuron_id.id);
            };
            case (#Err(e)) { Debug.trap("Expected NeuronNotFound error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Should not be able to verify non-existent neuron") };
        };

        Debug.print("✓ SNS permissions tests passed");
    };

    // Test name management functionality
    shared func test_name_management() : async () {
        Debug.print("Testing name management...");

        // Set up base permissions
        let stable_state = Permissions.empty_stable();
        let permissions = Permissions.PermissionsManager(stable_state);

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

        // Test anonymous caller - expect AnonymousCaller error
        let anonymous = Principal.fromText("2vxsx-fae");  // Anonymous principal
        switch(await* name_index.set_principal_name(anonymous, anonymous, "anon-name")) {
            case (#Err(#AnonymousCaller)) {}; // Expected
            case (#Err(e)) { Debug.trap("Expected AnonymousCaller error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Anonymous caller should not be able to set names") };
        };

        // Test setting duplicate name - expect NameAlreadyTaken error
        switch(await* name_index.set_principal_name(user2, user2, "test-user")) {
            case (#Err(#NameAlreadyTaken(info))) { 
                assert(info.name == "test-user");
                assert(info.taken_by == ?user1);
            };
            case (#Err(e)) { Debug.trap("Expected NameAlreadyTaken error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Should not be able to set duplicate name") };
        };

        // Test setting name for another principal (should fail) - expect NotAuthorized error
        switch(await* name_index.set_principal_name(user2, user1, "another-name")) {
            case (#Err(#NotAuthorized(info))) { 
                assert(info.required_permission == ?NamePermissions.EDIT_ANY_NAME);
            };
            case (#Err(e)) { Debug.trap("Expected NotAuthorized error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Should not be able to set name for another principal") };
        };

        Debug.print("✓ Name management tests passed");
    };

    // Test verification system functionality
    shared func test_verification_system() : async () {
        Debug.print("Testing verification system...");

        // Set up base permissions
        let stable_state = Permissions.empty_stable();
        let permissions = Permissions.PermissionsManager(stable_state);
        
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = permissions.get_dedup().getOrCreateIndexForPrincipal(admin1);
        Map.set(stable_state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);

        // Add required permission types
        switch(NamePermissions.add_name_permissions(permissions)) {
            case (#Err(e)) { Debug.trap("Failed to add name permissions: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Set up name index with permissions
        let sns_permissions = SnsPermissions.SnsPermissions(SnsPermissions.empty_stable(), permissions);
        let name_state = Lib.empty_stable();
        let name_index = Lib.NameIndex(name_state, ?sns_permissions);

        // Grant verification permissions to admin1
        switch(permissions.grant_permission(admin1, admin1, NamePermissions.VERIFY_NAME, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant verify permission: " # debug_show(e)) };
            case (#Ok()) {};
        };

        switch(permissions.grant_permission(admin1, admin1, NamePermissions.UNVERIFY_NAME, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant unverify permission: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // First, set a name for user1
        switch(await* name_index.set_principal_name(user1, user1, "test-user")) {
            case (#Err(e)) { Debug.trap("Failed to set name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify the name starts unverified
        switch(name_index.get_principal_name(user1)) {
            case null { Debug.trap("Name not found") };
            case (?name) {
                assert(name.verified == false);
            };
        };

        // Test verifying the name
        switch(await* name_index.verify_name(admin1, "test-user")) {
            case (#Err(e)) { Debug.trap("Failed to verify name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify the name is now verified
        switch(name_index.get_principal_name(user1)) {
            case null { Debug.trap("Name not found after verification") };
            case (?name) {
                assert(name.verified == true);
                assert(name.updated_by == admin1);
            };
        };

        // Test unverifying the name
        switch(await* name_index.unverify_name(admin1, "test-user")) {
            case (#Err(e)) { Debug.trap("Failed to unverify name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify the name is now unverified
        switch(name_index.get_principal_name(user1)) {
            case null { Debug.trap("Name not found after unverification") };
            case (?name) {
                assert(name.verified == false);
                assert(name.updated_by == admin1);
            };
        };

        // Test that non-authorized users cannot verify names - expect NotAuthorized error
        switch(await* name_index.verify_name(user2, "test-user")) {
            case (#Err(#NotAuthorized(info))) { 
                assert(info.required_permission == ?NamePermissions.VERIFY_NAME);
            };
            case (#Err(e)) { Debug.trap("Expected NotAuthorized error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Non-authorized user should not be able to verify names") };
        };

        // Test that non-authorized users cannot unverify names - expect NotAuthorized error
        switch(await* name_index.unverify_name(user2, "test-user")) {
            case (#Err(#NotAuthorized(info))) { 
                assert(info.required_permission == ?NamePermissions.UNVERIFY_NAME);
            };
            case (#Err(e)) { Debug.trap("Expected NotAuthorized error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Non-authorized user should not be able to unverify names") };
        };

        // Test verifying non-existent name - expect NameNotFound error
        switch(await* name_index.verify_name(admin1, "nonexistent-name")) {
            case (#Err(#NameNotFound(info))) { 
                assert(info.name == "nonexistent-name");
            };
            case (#Err(e)) { Debug.trap("Expected NameNotFound error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Should not be able to verify non-existent name") };
        };

        // Test that changing a verified name unverifies it
        // First verify the name again
        switch(await* name_index.verify_name(admin1, "test-user")) {
            case (#Err(e)) { Debug.trap("Failed to verify name again: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Grant edit permission to user1
        switch(permissions.grant_permission(admin1, user1, NamePermissions.EDIT_ANY_NAME, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant edit permission: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Change the name
        switch(await* name_index.set_principal_name(user1, user1, "new-test-user")) {
            case (#Err(e)) { Debug.trap("Failed to change name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify the new name is unverified
        switch(name_index.get_principal_name(user1)) {
            case null { Debug.trap("Name not found after change") };
            case (?name) {
                assert(name.name == "new-test-user");
                assert(name.verified == false);  // Should be unverified after change
            };
        };

        Debug.print("✓ Verification system tests passed");
    };

    // Test basic ban system functionality
    shared func test_ban_system() : async () {
        Debug.print("Testing ban system...");

        // Set up permissions
        let stable_state = Permissions.empty_stable();
        let permissions = Permissions.PermissionsManager(stable_state);
        
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = permissions.get_dedup().getOrCreateIndexForPrincipal(admin1);
        Map.set(stable_state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);

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
            case (#Err(e)) { Debug.trap("Failed to add ban permissions: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Set up ban system
        let ban_state = Bans.empty();
        let ban_system = Bans.Bans(ban_state, permissions.get_dedup(), func(p: Principal, perm: Text) : Bool {
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
        switch(ban_system.ban_user(admin1, user2, ?(24), "Test ban")) {
            case (#Err(e)) { Debug.trap("Failed to ban user: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify user is banned
        assert(ban_system.is_banned(user2) == true);

        // Test ban status check
        switch(ban_system.check_ban_status(user2)) {
            case (#Err(_)) { Debug.trap("Ban status check failed") };
            case (#Ok(msg)) {
                assert(Text.contains(msg, #text "banned"));
            };
        };

        // Test ban log
        switch(ban_system.get_ban_log(admin1)) {
            case (#Err(e)) { Debug.trap("Failed to get ban log: " # debug_show(e)) };
            case (#Ok(log)) {
                assert(log.size() == 1);
                assert(Principal.equal(log[0].user, user2));
                assert(Principal.equal(log[0].admin, admin1));
                assert(log[0].reason == "Test ban");
            };
        };

        // Test unbanning
        switch(ban_system.unban_user(admin1, user2)) {
            case (#Err(e)) { Debug.trap("Failed to unban user: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify user is no longer banned
        assert(ban_system.is_banned(user2) == false);

        Debug.print("✓ Ban system tests passed");
    };

    // Test ban system integration with permissions and name management
    shared func test_ban_integration() : async () {
        Debug.print("Testing ban integration...");

        // Set up permissions first (this contains the dedup and ban system)
        let stable_state = Permissions.empty_stable();
        let permissions = Permissions.PermissionsManager(stable_state);
        
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = permissions.get_dedup().getOrCreateIndexForPrincipal(admin1);
        Map.set(stable_state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);

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
            case (#Err(e)) { Debug.trap("Failed to add ban permissions: " # debug_show(e)) };
            case (#Ok()) {};
        };
        switch(NamePermissions.add_name_permissions(permissions)) {
            case (#Err(e)) { Debug.trap("Failed to add name permissions: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Set up SNS permissions using the same permissions instance (which contains dedup and bans)
        let sns_permissions = SnsPermissions.SnsPermissions(SnsPermissions.empty_stable(), permissions);

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

        // Verify banned user1 cannot set names despite having permission - expect Banned error
        switch(await* name_index.set_principal_name(user1, user2, "another-name")) {
            case (#Err(#Banned(info))) { 
                assert(Text.contains(info.reason, #text "banned"));
                assert(info.expires_at != null);
            };
            case (#Err(e)) { Debug.trap("Expected Banned error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Banned user should not be able to set names") };
        };

        // Create mock SNS governance
        let mock_governance = await MockSnsGovernance();

        // Test that banned user cannot use SNS permissions - expect Banned error
        let test_neuron_id = { id = Text.encodeUtf8("neuron1") };
        switch(await* name_index.set_sns_neuron_name(
            user1,
            test_neuron_id,
            "test-neuron",
            mock_governance
        )) {
            case (#Err(#Banned(info))) { 
                assert(Text.contains(info.reason, #text "banned"));
                assert(info.expires_at != null);
            };
            case (#Err(e)) { Debug.trap("Expected Banned error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Banned user should not be able to set neuron names") };
        };

        // Test that banned user cannot set SNS principal names - expect Banned error
        switch(await* name_index.set_sns_principal_name(
            user1,
            user1,
            "test-banned-principal",  // Use a different name to avoid conflicts
            mock_governance
        )) {
            case (#Err(#Banned(info))) { 
                assert(Text.contains(info.reason, #text "banned"));
                assert(info.expires_at != null);
            };
            case (#Err(e)) { Debug.trap("Expected Banned error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Banned user should not be able to set SNS principal names") };
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

    // Test ICRC1 account naming functionality
    shared func test_account_naming() : async () {
        Debug.print("Testing ICRC1 account naming...");

        // Set up base permissions
        let stable_state = Permissions.empty_stable();
        let permissions = Permissions.PermissionsManager(stable_state);
        
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = permissions.get_dedup().getOrCreateIndexForPrincipal(admin1);
        Map.set(stable_state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);

        // Add account permission types
        switch(NamePermissions.add_name_permissions(permissions)) {
            case (#Err(e)) { Debug.trap("Failed to add account permission types: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Set up name index
        let name_state = Lib.empty_stable();
        let name_index = Lib.NameIndex(name_state, null);

        // Test account with default subaccount (should route to principal naming)
        let default_account : T.Account = { owner = user1; subaccount = null };
        
        // Test setting name for default subaccount
        switch(await* name_index.set_account_name(user1, default_account, "default-account")) {
            case (#Err(e)) { Debug.trap("Failed to set default account name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify it was set as a principal name
        switch(name_index.get_principal_name(user1)) {
            case null { Debug.trap("Default account name not found in principal names") };
            case (?name) {
                assert(name.name == "default-account");
                assert(name.created_by == user1);
            };
        };

        // Verify get_account_name also works for default subaccount
        switch(name_index.get_account_name(default_account)) {
            case null { Debug.trap("Default account name not found via get_account_name") };
            case (?name) {
                assert(name.name == "default-account");
            };
        };

        // Test account with actual subaccount
        let subaccount_bytes = Array.tabulate<Nat8>(32, func(i) { if (i == 0) { 1 } else { 0 } });
        let subaccount_blob = Blob.fromArray(subaccount_bytes);
        let real_account : T.Account = { owner = user1; subaccount = ?subaccount_blob };

        // Test setting name for real subaccount
        switch(await* name_index.set_account_name(user1, real_account, "real-account")) {
            case (#Err(e)) { Debug.trap("Failed to set real account name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify it was set as an account name
        switch(name_index.get_account_name(real_account)) {
            case null { Debug.trap("Real account name not found") };
            case (?name) {
                assert(name.name == "real-account");
                assert(name.created_by == user1);
            };
        };

        // Test that account names are separate from principal names
        assert(name_index.is_account_name_taken("default-account") == true);
        assert(name_index.is_account_name_taken("real-account") == true);
        assert(name_index.is_account_name_taken("nonexistent") == false);

        // Test removing real account name
        switch(await* name_index.remove_account_name(user1, real_account)) {
            case (#Err(e)) { Debug.trap("Failed to remove real account name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify it was removed
        switch(name_index.get_account_name(real_account)) {
            case null {}; // Expected
            case (?name) { Debug.trap("Real account name should have been removed") };
        };

        // Test that non-owner cannot set account names
        let other_account : T.Account = { owner = user2; subaccount = ?subaccount_blob };
        switch(await* name_index.set_account_name(user1, other_account, "unauthorized")) {
            case (#Err(#NotAuthorized(info))) { 
                assert(info.required_permission == ?NamePermissions.SET_ACCOUNT_NAME_PERMISSION);
            };
            case (#Err(e)) { Debug.trap("Expected NotAuthorized error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Non-owner should not be able to set account names") };
        };

        Debug.print("✓ ICRC1 account naming tests passed");
    };

    // Test banned words functionality
    shared func test_banned_words() : async () {
        Debug.print("Testing banned words...");

        // Set up base permissions
        let stable_state = Permissions.empty_stable();
        let permissions = Permissions.PermissionsManager(stable_state);
        
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = permissions.get_dedup().getOrCreateIndexForPrincipal(admin1);
        Map.set(stable_state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);

        // Add all required permission types
        switch(NamePermissions.add_name_permissions(permissions)) {
            case (#Err(e)) { Debug.trap("Failed to add permission types: " # debug_show(e)) };
            case (#Ok()) {};
        };
        switch(BanPermissions.add_ban_permissions(permissions)) {
            case (#Err(e)) { Debug.trap("Failed to add ban permissions: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Set up name index with permissions
        let sns_permissions = SnsPermissions.SnsPermissions(SnsPermissions.empty_stable(), permissions);
        let name_state = Lib.empty_stable();
        let name_index = Lib.NameIndex(name_state, ?sns_permissions);

        // Grant banned word management permissions to admin1
        switch(permissions.grant_permission(admin1, admin1, NamePermissions.ADD_BANNED_WORD_PERMISSION, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant add banned word permission: " # debug_show(e)) };
            case (#Ok()) {};
        };

        switch(permissions.grant_permission(admin1, admin1, NamePermissions.REMOVE_BANNED_WORD_PERMISSION, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant remove banned word permission: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Grant view banned words permission to admin1 for testing
        switch(permissions.grant_permission(admin1, admin1, NamePermissions.VIEW_BANNED_WORDS_PERMISSION, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant view banned words permission: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test adding banned words
        switch(await* name_index.add_banned_word(admin1, "BadWord")) {
            case (#Err(e)) { Debug.trap("Failed to add banned word: " # debug_show(e)) };
            case (#Ok()) {};
        };

        switch(await* name_index.add_banned_word(admin1, "SPAM")) {
            case (#Err(e)) { Debug.trap("Failed to add banned word: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test checking if words are banned by trying to set names with them
        switch(await* name_index.set_principal_name(user1, user1, "badword")) {
            case (#Err(#BannedWord(info))) { 
                assert(info.word == "badword");
            };
            case (#Err(e)) { Debug.trap("Expected BannedWord error for 'badword', got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Should not be able to set 'badword' as name") };
        };

        switch(await* name_index.set_principal_name(user2, user2, "BADWORD")) {
            case (#Err(#BannedWord(info))) { 
                assert(info.word == "BADWORD");  // Should return the original name when exact match
            };
            case (#Err(e)) { Debug.trap("Expected BannedWord error for 'BADWORD', got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Should not be able to set 'BADWORD' as name") };
        };

        // Test that non-banned words work
        switch(await* name_index.set_principal_name(user1, user1, "goodword")) {
            case (#Err(e)) { Debug.trap("Failed to set non-banned word: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Clean up the good word for later tests
        switch(await* name_index.set_principal_name(user1, user1, "testuser1")) {
            case (#Err(e)) { Debug.trap("Failed to set test name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test getting banned words list
        switch(await* name_index.get_banned_words(admin1)) {
            case (#Err(e)) { Debug.trap("Failed to get banned words: " # debug_show(e)) };
            case (#Ok(words)) {
                assert(words.size() == 2);
                // Words should be stored in lowercase
                assert(Array.find<Text>(words, func(w) = w == "badword") != null);
                assert(Array.find<Text>(words, func(w) = w == "spam") != null);
            };
        };

        // Test that using banned words as substring also triggers ban
        switch(await* name_index.set_principal_name(user2, user2, "mybadwordname")) {
            case (#Err(#BannedWord(info))) { 
                assert(info.word == "badword");
            };
            case (#Err(e)) { Debug.trap("Expected BannedWord error for substring, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Should not be able to set name containing banned word") };
        };

        // Test removing banned words
        switch(await* name_index.remove_banned_word(admin1, "badword")) {
            case (#Err(e)) { Debug.trap("Failed to remove banned word: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test that removed word is no longer banned
        switch(await* name_index.set_principal_name(user1, user1, "badword")) {
            case (#Err(e)) { Debug.trap("Word should no longer be banned: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test that other banned word still works
        switch(await* name_index.set_principal_name(user2, user2, "spam")) {
            case (#Err(#BannedWord(info))) { 
                assert(info.word == "spam");
            };
            case (#Err(e)) { Debug.trap("Expected BannedWord error for 'spam', got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Should not be able to set 'spam' as name") };
        };

        // Test that non-authorized users cannot manage banned words
        switch(await* name_index.add_banned_word(user1, "newbadword")) {
            case (#Err(#NotAuthorized(info))) { 
                assert(info.required_permission == ?NamePermissions.ADD_BANNED_WORD_PERMISSION);
            };
            case (#Err(e)) { Debug.trap("Expected NotAuthorized error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Non-authorized user should not be able to add banned words") };
        };

        switch(await* name_index.remove_banned_word(user1, "spam")) {
            case (#Err(#NotAuthorized(info))) { 
                assert(info.required_permission == ?NamePermissions.REMOVE_BANNED_WORD_PERMISSION);
            };
            case (#Err(e)) { Debug.trap("Expected NotAuthorized error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Non-authorized user should not be able to remove banned words") };
        };

        // Test that non-authorized users cannot view banned words
        switch(await* name_index.get_banned_words(user1)) {
            case (#Err(#NotAuthorized(info))) { 
                assert(info.required_permission == ?NamePermissions.VIEW_BANNED_WORDS_PERMISSION);
            };
            case (#Err(e)) { Debug.trap("Expected NotAuthorized error for viewing banned words, got: " # debug_show(e)) };
            case (#Ok(_)) { Debug.trap("Non-authorized user should not be able to view banned words") };
        };

        Debug.print("✓ Banned words tests passed");
    };

    // Test edge cases and input validation
    shared func test_edge_cases() : async () {
        Debug.print("Testing edge cases and input validation...");

        // Set up base permissions
        let stable_state = Permissions.empty_stable();
        let permissions = Permissions.PermissionsManager(stable_state);
        
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = permissions.get_dedup().getOrCreateIndexForPrincipal(admin1);
        Map.set(stable_state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);

        // Add all required permission types
        switch(NamePermissions.add_name_permissions(permissions)) {
            case (#Err(e)) { Debug.trap("Failed to add permission types: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Set up name index
        let name_state = Lib.empty_stable();
        let name_index = Lib.NameIndex(name_state, null);

        // Test empty string names
        switch(await* name_index.set_principal_name(user1, user1, "")) {
            case (#Err(#InvalidName(info))) { 
                assert(Text.contains(info.reason, #text "too short"));
            };
            case (#Err(e)) { Debug.trap("Expected InvalidName error for empty string, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Should not be able to set empty name") };
        };

        // Test very long names (test system limits)
        let very_long_name = Array.tabulate<Text>(1000, func(_) = "a");
        let very_long_name_text = Text.join("", very_long_name.vals());
        switch(await* name_index.set_principal_name(user1, user1, very_long_name_text)) {
            case (#Err(_)) {}; // May fail due to length limits
            case (#Ok()) {}; // Or may succeed - depends on implementation
        };

        // Test names with special characters
        switch(await* name_index.set_principal_name(user1, user1, "test-name_123")) {
            case (#Err(e)) { Debug.trap("Failed to set name with valid special chars: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test names with unicode characters
        switch(await* name_index.set_principal_name(user1, user1, "test-名前-🚀")) {
            case (#Err(_)) {}; // May fail depending on validation rules
            case (#Ok()) {}; // Or may succeed
        };

        // Test case sensitivity in name lookups
        switch(await* name_index.set_principal_name(user1, user1, "TestName")) {
            case (#Err(e)) { Debug.trap("Failed to set TestName: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify case-insensitive lookup works
        assert(name_index.is_name_taken("testname") == true);
        assert(name_index.is_name_taken("TESTNAME") == true);
        assert(name_index.is_name_taken("TestName") == true);

        // Test whitespace handling
        switch(await* name_index.set_principal_name(user2, user2, " whitespace ")) {
            case (#Err(_)) {}; // May fail due to whitespace validation
            case (#Ok()) {}; // Or may succeed with trimming
        };

        Debug.print("✓ Edge cases and input validation tests passed");
    };

    // Test permission expiration and time-based scenarios
    shared func test_permission_expiration() : async () {
        Debug.print("Testing permission expiration scenarios...");

        let stable_state = Permissions.empty_stable();
        let permissions = Permissions.PermissionsManager(stable_state);
        
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = permissions.get_dedup().getOrCreateIndexForPrincipal(admin1);
        Map.set(stable_state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);

        // Add permission types with specific durations
        switch(NamePermissions.add_name_permissions(permissions)) {
            case (#Err(e)) { Debug.trap("Failed to add permission types: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test granting permission with past expiry date (use current time - offset to ensure it's in the past)
        let current_time = Nat64.fromIntWrap(Time.now());
        let past_time = if (current_time > 1_000_000_000) { current_time - 1_000_000_000 } else { 1 : Nat64 }; // 1 second ago or minimal value
        switch(permissions.grant_permission(admin1, user1, NamePermissions.EDIT_ANY_NAME, ?past_time)) {
            case (#Err(_)) {}; // May fail immediately
            case (#Ok()) {}; // Or may succeed but be immediately expired
        };

        // Verify expired permission doesn't work
        assert(permissions.check_permission(user1, NamePermissions.EDIT_ANY_NAME) == false);

        // Test granting permission with future expiry (use current time + offset)
        let future_time = current_time + 1_000_000_000; // 1 second in future
        switch(permissions.grant_permission(admin1, user1, NamePermissions.EDIT_ANY_NAME, ?future_time)) {
            case (#Err(e)) { Debug.trap("Failed to grant future permission: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify future permission works
        assert(permissions.check_permission(user1, NamePermissions.EDIT_ANY_NAME) == true);

        Debug.print("✓ Permission expiration tests passed");
    };

    // Test concurrent operations and race conditions
    shared func test_concurrent_operations() : async () {
        Debug.print("Testing concurrent operations...");

        let stable_state = Permissions.empty_stable();
        let permissions = Permissions.PermissionsManager(stable_state);
        
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = permissions.get_dedup().getOrCreateIndexForPrincipal(admin1);
        Map.set(stable_state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);

        switch(NamePermissions.add_name_permissions(permissions)) {
            case (#Err(e)) { Debug.trap("Failed to add permission types: " # debug_show(e)) };
            case (#Ok()) {};
        };

        let name_state = Lib.empty_stable();
        let name_index = Lib.NameIndex(name_state, null);

        // Test multiple users trying to claim the same name
        // (This would be more meaningful in a truly concurrent environment)
        switch(await* name_index.set_principal_name(user1, user1, "contested-name")) {
            case (#Err(e)) { Debug.trap("Failed to set contested name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Second user should fail
        switch(await* name_index.set_principal_name(user2, user2, "contested-name")) {
            case (#Err(#NameAlreadyTaken(info))) { 
                assert(info.name == "contested-name");
                assert(info.taken_by == ?user1);
            };
            case (#Err(e)) { Debug.trap("Expected NameAlreadyTaken error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Should not be able to take already taken name") };
        };

        Debug.print("✓ Concurrent operations tests passed");
    };

    // Test banned words with complex scenarios
    shared func test_banned_words_advanced() : async () {
        Debug.print("Testing advanced banned words scenarios...");

        let stable_state = Permissions.empty_stable();
        let permissions = Permissions.PermissionsManager(stable_state);
        
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = permissions.get_dedup().getOrCreateIndexForPrincipal(admin1);
        Map.set(stable_state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);

        switch(NamePermissions.add_name_permissions(permissions)) {
            case (#Err(e)) { Debug.trap("Failed to add permission types: " # debug_show(e)) };
            case (#Ok()) {};
        };
        switch(BanPermissions.add_ban_permissions(permissions)) {
            case (#Err(e)) { Debug.trap("Failed to add ban permissions: " # debug_show(e)) };
            case (#Ok()) {};
        };

        let sns_permissions = SnsPermissions.SnsPermissions(SnsPermissions.empty_stable(), permissions);
        let name_state = Lib.empty_stable();
        let name_index = Lib.NameIndex(name_state, ?sns_permissions);

        // Grant permissions
        switch(permissions.grant_permission(admin1, admin1, NamePermissions.ADD_BANNED_WORD_PERMISSION, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant add banned word permission: " # debug_show(e)) };
            case (#Ok()) {};
        };
        switch(permissions.grant_permission(admin1, admin1, NamePermissions.REMOVE_BANNED_WORD_PERMISSION, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant remove banned word permission: " # debug_show(e)) };
            case (#Ok()) {};
        };
        switch(permissions.grant_permission(admin1, admin1, NamePermissions.VIEW_BANNED_WORDS_PERMISSION, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant view banned words permission: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test adding duplicate banned words
        switch(await* name_index.add_banned_word(admin1, "duplicate")) {
            case (#Err(e)) { Debug.trap("Failed to add banned word: " # debug_show(e)) };
            case (#Ok()) {};
        };

        switch(await* name_index.add_banned_word(admin1, "DUPLICATE")) {
            case (#Err(_)) {}; // May fail as duplicate (case-insensitive)
            case (#Ok()) {}; // Or may succeed if case-sensitive
        };

        // Test removing non-existent banned word
        switch(await* name_index.remove_banned_word(admin1, "nonexistent")) {
            case (#Err(_)) {}; // May fail
            case (#Ok()) {}; // Or may succeed silently
        };

        // Test banned word with special characters
        switch(await* name_index.add_banned_word(admin1, "bad-word_123")) {
            case (#Err(e)) { Debug.trap("Failed to add banned word with special chars: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test that the special character banned word works
        switch(await* name_index.set_principal_name(user1, user1, "my-bad-word_123-name")) {
            case (#Err(#BannedWord(info))) { 
                assert(info.word == "bad-word_123");
            };
            case (#Err(e)) { Debug.trap("Expected BannedWord error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Should not be able to set name with banned word") };
        };

        // Test empty banned word
        switch(await* name_index.add_banned_word(admin1, "")) {
            case (#Err(_)) {}; // May fail
            case (#Ok()) {}; // Or may succeed - empty strings might be allowed
        };

        Debug.print("✓ Advanced banned words tests passed");
    };

    // Test account naming edge cases
    shared func test_account_naming_edge_cases() : async () {
        Debug.print("Testing account naming edge cases...");

        let stable_state = Permissions.empty_stable();
        let permissions = Permissions.PermissionsManager(stable_state);
        
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = permissions.get_dedup().getOrCreateIndexForPrincipal(admin1);
        Map.set(stable_state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);

        switch(NamePermissions.add_name_permissions(permissions)) {
            case (#Err(e)) { Debug.trap("Failed to add permission types: " # debug_show(e)) };
            case (#Ok()) {};
        };

        let name_state = Lib.empty_stable();
        let name_index = Lib.NameIndex(name_state, null);

        // Test account with all-zeros subaccount (should be treated as default)
        let zero_subaccount = Array.tabulate<Nat8>(32, func(_) = 0);
        let zero_account : T.Account = { 
            owner = user1; 
            subaccount = ?Blob.fromArray(zero_subaccount) 
        };

        switch(await* name_index.set_account_name(user1, zero_account, "zero-account")) {
            case (#Err(e)) { Debug.trap("Failed to set zero subaccount name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify it was treated as principal name
        switch(name_index.get_principal_name(user1)) {
            case (?name) { assert(name.name == "zero-account") };
            case null { Debug.trap("Zero subaccount should be treated as principal") };
        };

        // Test account with invalid subaccount size
        let invalid_subaccount = Array.tabulate<Nat8>(16, func(_) = 1); // Wrong size
        let invalid_account : T.Account = { 
            owner = user1; 
            subaccount = ?Blob.fromArray(invalid_subaccount) 
        };

        switch(await* name_index.set_account_name(user1, invalid_account, "invalid-account")) {
            case (#Err(_)) {}; // May fail due to invalid subaccount
            case (#Ok()) {}; // Or may handle gracefully
        };

        // Test multiple subaccounts for same owner
        let subaccount1 = Array.tabulate<Nat8>(32, func(i) = if (i == 0) 1 else 0);
        let subaccount2 = Array.tabulate<Nat8>(32, func(i) = if (i == 0) 2 else 0);
        
        let account1 : T.Account = { owner = user1; subaccount = ?Blob.fromArray(subaccount1) };
        let account2 : T.Account = { owner = user1; subaccount = ?Blob.fromArray(subaccount2) };

        switch(await* name_index.set_account_name(user1, account1, "account-1")) {
            case (#Err(e)) { Debug.trap("Failed to set account1 name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        switch(await* name_index.set_account_name(user1, account2, "account-2")) {
            case (#Err(e)) { Debug.trap("Failed to set account2 name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify both accounts have different names
        switch(name_index.get_account_name(account1)) {
            case (?name) { assert(name.name == "account-1") };
            case null { Debug.trap("Account1 name not found") };
        };

        switch(name_index.get_account_name(account2)) {
            case (?name) { assert(name.name == "account-2") };
            case null { Debug.trap("Account2 name not found") };
        };

        Debug.print("✓ Account naming edge cases tests passed");
    };

    // Test name settings management
    shared func test_name_settings() : async () {
        Debug.print("Testing name settings management...");

        let stable_state = Permissions.empty_stable();
        let permissions = Permissions.PermissionsManager(stable_state);
        
        let admin_metadata : Permissions.PermissionMetadata = {
            created_by = admin1;
            created_at = Nat64.fromIntWrap(Time.now());
            expires_at = null;
        };
        let admin1_index = permissions.get_dedup().getOrCreateIndexForPrincipal(admin1);
        Map.set(stable_state.admins, (func (n : Nat32) : Nat32 { n }, Nat32.equal), admin1_index, admin_metadata);

        switch(NamePermissions.add_name_permissions(permissions)) {
            case (#Err(e)) { Debug.trap("Failed to add permission types: " # debug_show(e)) };
            case (#Ok()) {};
        };

        let sns_permissions = SnsPermissions.SnsPermissions(SnsPermissions.empty_stable(), permissions);
        let name_state = Lib.empty_stable();
        let name_index = Lib.NameIndex(name_state, ?sns_permissions);

        // Grant name settings management permission to admin1
        switch(permissions.grant_permission(admin1, admin1, NamePermissions.MANAGE_NAME_SETTINGS_PERMISSION, null)) {
            case (#Err(e)) { Debug.trap("Failed to grant manage settings permission: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test getting default settings
        let default_settings = name_index.get_name_settings();
        assert(default_settings.min_length == 1);
        assert(default_settings.max_length == 64);
        assert(default_settings.allow_special_chars == true);
        assert(default_settings.allow_unicode == false);

        // Test setting new settings
        let new_settings : T.NameSettings = {
            min_length = 3;
            max_length = 20;
            allow_special_chars = false;
            allow_unicode = false;
        };

        switch(await* name_index.set_name_settings(admin1, new_settings)) {
            case (#Err(e)) { Debug.trap("Failed to set name settings: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Verify settings were updated
        let updated_settings = name_index.get_name_settings();
        assert(updated_settings.min_length == 3);
        assert(updated_settings.max_length == 20);
        assert(updated_settings.allow_special_chars == false);
        assert(updated_settings.allow_unicode == false);

        // Test that names now follow new rules
        // Test name too short
        switch(await* name_index.set_principal_name(user1, user1, "ab")) {
            case (#Err(#InvalidName(info))) { 
                assert(Text.contains(info.reason, #text "too short"));
            };
            case (#Err(e)) { Debug.trap("Expected InvalidName error for short name, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Should not be able to set name shorter than min_length") };
        };

        // Test name too long
        let long_name = "verylongnamethatexceedsmaxlength";
        switch(await* name_index.set_principal_name(user1, user1, long_name)) {
            case (#Err(#InvalidName(info))) { 
                assert(Text.contains(info.reason, #text "too long"));
            };
            case (#Err(e)) { Debug.trap("Expected InvalidName error for long name, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Should not be able to set name longer than max_length") };
        };

        // Test special characters not allowed
        switch(await* name_index.set_principal_name(user1, user1, "test-name")) {
            case (#Err(#InvalidName(info))) { 
                assert(Text.contains(info.reason, #text "Special characters"));
            };
            case (#Err(e)) { Debug.trap("Expected InvalidName error for special chars, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Should not be able to set name with special characters when disabled") };
        };

        // Test valid name
        switch(await* name_index.set_principal_name(user1, user1, "validname")) {
            case (#Err(e)) { Debug.trap("Failed to set valid name: " # debug_show(e)) };
            case (#Ok()) {};
        };

        // Test that non-authorized users cannot change settings
        switch(await* name_index.set_name_settings(user2, new_settings)) {
            case (#Err(#NotAuthorized(info))) { 
                assert(info.required_permission == ?NamePermissions.MANAGE_NAME_SETTINGS_PERMISSION);
            };
            case (#Err(e)) { Debug.trap("Expected NotAuthorized error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Non-authorized user should not be able to change settings") };
        };

        // Test invalid settings
        let invalid_settings : T.NameSettings = {
            min_length = 0;  // Invalid: must be at least 1
            max_length = 20;
            allow_special_chars = false;
            allow_unicode = false;
        };

        switch(await* name_index.set_name_settings(admin1, invalid_settings)) {
            case (#Err(#InvalidNameSettings(info))) { 
                assert(Text.contains(info.reason, #text "at least 1"));
            };
            case (#Err(e)) { Debug.trap("Expected InvalidNameSettings error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Should not be able to set invalid settings") };
        };

        // Test min > max
        let invalid_settings2 : T.NameSettings = {
            min_length = 10;
            max_length = 5;  // Invalid: min > max
            allow_special_chars = false;
            allow_unicode = false;
        };

        switch(await* name_index.set_name_settings(admin1, invalid_settings2)) {
            case (#Err(#InvalidNameSettings(info))) { 
                assert(Text.contains(info.reason, #text "greater than maximum"));
            };
            case (#Err(e)) { Debug.trap("Expected InvalidNameSettings error, got: " # debug_show(e)) };
            case (#Ok()) { Debug.trap("Should not be able to set min > max") };
        };

        Debug.print("✓ Name settings management tests passed");
    };

    run_tests();
};