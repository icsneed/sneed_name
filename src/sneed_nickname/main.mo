import Dedup "mo:dedup";
import Map "mo:map/Map";
import Vector "mo:vector";
actor {
  public query func greet(name : Text) : async Text {
    return "Hello, " # name # "!";
  };

    stable var dedupState3: ?Dedup.DedupState = ?Dedup.empty();

    // use as class
    var dedup = Dedup.Dedup(dedupState3);

    public query func getIndexForPrincipal(principal : Principal) : async ?Nat32 {
        dedup.getIndexForPrincipal(principal);
    };

    public shared func getOrCreateIndexForPrincipal(principal : Principal) : async Nat32 {
        dedup.getOrCreateIndexForPrincipal(principal);
    };

    public query func getPrincipalForIndexZ(index : Nat32) : async ?Principal {
        dedup.getPrincipalForIndex(index);
    };
};
