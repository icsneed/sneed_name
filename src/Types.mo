import Map "mo:map/Map";
import Dedup "mo:dedup";

module {
    public type Name = {
        name : Text;
        verified : Bool;
        created : Nat64;
        updated : Nat64;
        created_by : Principal;
        updated_by : Principal;
    };

    public type NameIndexState = {
        name_to_index : Map.Map<Nat32, Name>;
        index_to_name : Map.Map<Text, Nat32>;
        blacklisted_words : Map.Map<Text, Name>;
        // todo blacklisted words, admins, banned users
    };
}