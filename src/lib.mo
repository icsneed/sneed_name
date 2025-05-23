import Map "mo:map/Map";
import Dedup "mo:dedup";
import T "Types";
import Nat32 "mo:base/Nat32";
import Text "mo:base/Text";
import Principal "mo:base/Principal";
import Result "mo:base/Result";
import Time "mo:base/Time";
import Nat64 "mo:base/Nat64";
import Permissions "./Permissions";

module {
    public func empty() : T.NameIndexState {
        {
            dedup_state = ?Dedup.empty();
            name_to_index = Map.new<Nat32, T.Name>();
            index_to_name = Map.new<Text, Nat32>();
        };
    };

    public class NameIndex(from: T.NameIndexState) {
        private let state = from;
        let dedup = Dedup.Dedup(state.dedup_state);

        let nat32Utils = (func (n : Nat32) : Nat32 { n }, Nat32.equal);
        let textUtils = (Text.hash, Text.equal);

        public func get_principal_name(principal : Principal) : ?T.Name {
            let index = dedup.getOrCreateIndexForPrincipal(principal);
            Map.get(state.name_to_index, nat32Utils, index);
        };

        public func set_principal_name(caller : Principal, principal : Principal, name : Text) : async* Result.Result<(), Text> {
            if (Principal.isAnonymous(caller)) {
                return #err("Anonymous caller");
            };
            
            // Allow if caller is setting their own name or if caller is an admin
            if (not Principal.equal(caller, principal) and not Permissions.is_admin(caller, state)) {
                return #err("Not authorized: must be admin or setting own name");
            };
            
            let name_lower = Text.toLowercase(name);
            
            // Check if name is already taken by someone else
            switch (Map.get(state.index_to_name, textUtils, name_lower)) {
                case (?existing_index) {
                    let target_index = dedup.getOrCreateIndexForPrincipal(principal);
                    if (existing_index != target_index) {
                        return #err("Name already taken");
                    };
                };
                case null {};
            };

            let index = dedup.getOrCreateIndexForPrincipal(principal);
            let now = Nat64.fromIntWrap(Time.now());
            
            // Get existing record if any
            let name_record = switch (Map.get(state.name_to_index, nat32Utils, index)) {
                case (?existing) {
                    // Keep original creation info, update the rest
                    {
                        name = name;
                        verified = existing.verified;
                        created = existing.created;
                        updated = now;
                        created_by = existing.created_by;
                        updated_by = caller;
                    };
                };
                case null {
                    // Create new record
                    {
                        name = name;
                        verified = false;
                        created = now;
                        updated = now;
                        created_by = caller;
                        updated_by = caller;
                    };
                };
            };
            
            // Remove old name from inverse map if it exists
            switch (Map.get(state.name_to_index, nat32Utils, index)) {
                case (?old_record) {
                    Map.delete(state.index_to_name, textUtils, Text.toLowercase(old_record.name));
                };
                case null {};
            };

            // Set new mappings
            Map.set(state.name_to_index, nat32Utils, index, name_record);
            Map.set(state.index_to_name, textUtils, name_lower, index);
            return #ok(());
        };

        public func get_caller_name(caller : Principal) : ?T.Name {
            get_principal_name(caller);
        };

        public func set_caller_name(caller : Principal, name : Text) : async* Result.Result<(), Text> {
            await* set_principal_name(caller, caller, name);
        };

        // Helper functions for reverse lookups
        public func get_name_principal(name : Text) : ?Principal {
            switch (Map.get(state.index_to_name, textUtils, Text.toLowercase(name))) {
                case (?index) {
                    dedup.getPrincipalForIndex(index);
                };
                case null { null };
            };
        };

        public func is_name_taken(name : Text) : Bool {
            switch (Map.get(state.index_to_name, textUtils, Text.toLowercase(name))) {
                case (?_) { true };
                case null { false };
            };
        };

        // Helper function to get full name record by name
        public func get_name_record(name : Text) : ?T.Name {
            switch (Map.get(state.index_to_name, textUtils, Text.toLowercase(name))) {
                case (?index) {
                    Map.get(state.name_to_index, nat32Utils, index);
                };
                case null { null };
            };
        };
    };
}