import Dedup "mo:dedup";
import Map "mo:map/Map";
import Result "mo:base/Result";
import Nat32 "mo:base/Nat32";

actor {

  stable var name_map : Map.Map<Nat32, Text> = Map.new<Nat32, Text>();
  stable var name_inverse : Map.Map<Text, Nat32> = Map.new<Text, Nat32>();
  
  stable var dedup_state : ?Dedup.DedupState = null;

  let dedup = Dedup.Dedup(dedup_state);

  let nat32Utils = (func (n : Nat32) : Nat32 { n }, Nat32.equal);

  public query func get_principal_name(principal : Principal) : async ?Text {
    let key = dedup.getOrCreateIndexForPrincipal(principal);
    Map.get(name_map, nat32Utils, key);
  };

  public shared ({ caller }) func set_principal_name(principal : Principal, name : Text) : async Result.Result<(), Text> {
    if (Principal.isAnonymous(caller)) {
      return #err("Anonymous caller");
    };
    
    let key = dedup.getOrCreateIndexForPrincipal(principal);
    Map.set(name_map, nat32Utils, key, name);
    return #ok(());
  };

  public query ({ caller }) func get_caller_name() : async ?Text {
    let key = dedup.getOrCreateIndexForPrincipal(caller);
    Map.get(name_map, nat32Utils, key);
  };

  public shared ({ caller }) func set_caller_name(name : Text) : async Result.Result<(), Text> {
    let key = dedup.getOrCreateIndexForPrincipal(caller);
    Map.set(name_map, nat32Utils, key, name);
    return #ok(());
  };
};
