import Dedup "mo:dedup";
import Map "mo:map/Map";
import Result "mo:base/Result";
import Nat32 "mo:base/Nat32";
import Principal "mo:base/Principal";
import Text "mo:base/Text";
import Hash "mo:base/Hash";
import Blob "mo:base/Blob";

actor {
  stable var name_map : Map.Map<Nat32, Text> = Map.new<Nat32, Text>();
  stable var name_inverse : Map.Map<Text, Nat32> = Map.new<Text, Nat32>();
  
  stable var dedup_state : ?Dedup.DedupState = null;

  let dedup = Dedup.Dedup(dedup_state);

  

  let nat32Utils = (func (n : Nat32) : Nat32 { n }, Nat32.equal);
  let textUtils = (Text.hash, Text.equal);

  public query func get_principal_name(principal : Principal) : async ?Text {
    let key = dedup.getOrCreateIndexForPrincipal(principal);
    Map.get(name_map, nat32Utils, key);
  };

  public shared ({ caller }) func set_principal_name(principal : Principal, name : Text) : async Result.Result<(), Text> {
    if (Principal.isAnonymous(caller)) {
      return #err("Anonymous caller");
    };
    
    let name_lower = Text.toLowercase(name);
    
    // Check if name is already taken by someone else
    switch (Map.get(name_inverse, textUtils, name_lower)) {
      case (?existing_key) {
        let target_key = dedup.getOrCreateIndexForPrincipal(principal);
        if (existing_key != target_key) {
          return #err("Name already taken");
        };
      };
      case null {};
    };

    let key = dedup.getOrCreateIndexForPrincipal(principal);
    
    // Remove old name from inverse map if it exists
    switch (Map.get(name_map, nat32Utils, key)) {
      case (?old_name) {
        Map.delete(name_inverse, textUtils, Text.toLowercase(old_name));
      };
      case null {};
    };

    // Set new mappings
    Map.set(name_map, nat32Utils, key, name);
    Map.set(name_inverse, textUtils, name_lower, key);
    return #ok(());
  };

  public query ({ caller }) func get_caller_name() : async ?Text {
    let key = dedup.getOrCreateIndexForPrincipal(caller);
    Map.get(name_map, nat32Utils, key);
  };

  public shared ({ caller }) func set_caller_name(name : Text) : async Result.Result<(), Text> {
    if (Principal.isAnonymous(caller)) {
      return #err("Anonymous caller");
    };

    let name_lower = Text.toLowercase(name);

    // Check if name is already taken by someone else
    switch (Map.get(name_inverse, textUtils, name_lower)) {
      case (?existing_key) {
        let caller_key = dedup.getOrCreateIndexForPrincipal(caller);
        if (existing_key != caller_key) {
          return #err("Name already taken");
        };
      };
      case null {};
    };

    let key = dedup.getOrCreateIndexForPrincipal(caller);
    
    // Remove old name from inverse map if it exists
    switch (Map.get(name_map, nat32Utils, key)) {
      case (?old_name) {
        Map.delete(name_inverse, textUtils, Text.toLowercase(old_name));
      };
      case null {};
    };

    // Set new mappings
    Map.set(name_map, nat32Utils, key, name);
    Map.set(name_inverse, textUtils, name_lower, key);
    return #ok(());
  };

  // New helper functions for reverse lookups
  public query func get_name_principal(name : Text) : async ?Principal {
    switch (Map.get(name_inverse, textUtils, Text.toLowercase(name))) {
      case (?key) {
        dedup.getPrincipalForIndex(key);
      };
      case null { null };
    };
  };

  public query func is_name_taken(name : Text) : async Bool {
    switch (Map.get(name_inverse, textUtils, Text.toLowercase(name))) {
      case (?_) { true };
      case null { false };
    };
  };
};
