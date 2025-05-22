import Dedup "mo:dedup";
import Map "mo:map/Map";
import Result "mo:base/Result";
import Nat32 "mo:base/Nat32";

actor {

  stable var name_map : Map.Map<Nat32, Text> = Map.new<Nat32, Text>();
  stable var key_dedup_state : ?Dedup.DedupState = null;

  let key_dedup = Dedup.Dedup(key_dedup_state);

  let nat32Utils = (func (n : Nat32) : Nat32 { n }, Nat32.equal);


  public query func get_principal_name(principal : Principal) : async ?Text {
    let key = key_dedup.getOrCreateIndexForPrincipal(principal);
    Map.get(name_map, nat32Utils, key);
  };

  public shared func set_principal_name(principal : Principal, name : Text) : async Result.Result<(), Text> {
    let key = key_dedup.getOrCreateIndexForPrincipal(principal);
    Map.set(name_map, nat32Utils, key, name);
    return #ok(());
  };
};
