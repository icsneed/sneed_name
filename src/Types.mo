import Map "mo:map/Map";
import Dedup "mo:dedup";
import Principal "mo:base/Principal";
import Nat64 "mo:base/Nat64";
import Nat32 "mo:base/Nat32";

module {
    public type Name = {
        name : Text;
        verified : Bool;
        created : Nat64;
        updated : Nat64;
        created_by : Principal;
        updated_by : Principal;
    };

    // ICRC1 Account type
    public type Account = {
        owner : Principal;
        subaccount : ?Blob;
    };

    // Name validation settings
    public type NameSettings = {
        min_length : Nat;
        max_length : Nat;
        allow_special_chars : Bool;
        allow_unicode : Bool;
    };

    public type NameIndexState = {
        index_to_name : Map.Map<Nat32, Name>;
        blacklisted_words : Map.Map<Text, Name>;
        var name_settings : NameSettings;
        // todo blacklisted words, admins, banned users
    };

    // Comprehensive error types for the entire project
    public type NameError = {
        #AnonymousCaller;
        #NotAuthorized : { required_permission : ?Text };
        #NameAlreadyTaken : { name : Text; taken_by : ?Principal };
        #NameNotFound : { name : Text };
        #InvalidName : { name : Text; reason : Text };
        #Banned : { reason : Text; expires_at : ?Int };
        #PermissionExpired : { permission : Text; expired_at : Nat64 };
        #PermissionNotFound : { permission : Text };
        #InsufficientVotingPower : { required : Nat64; actual : Nat64 };
        #NeuronNotFound : { neuron_id : Blob };
        #PrincipalNotFound : { principal : Principal };
        #BannedWord : { word : Text };
        #InvalidNameSettings : { reason : Text };
    };

    public type AdminError = {
        #NotAuthorized : { required_permission : Text };
        #AlreadyAdmin : { principal : Principal };
        #NotAdmin : { principal : Principal };
        #CannotRemoveSelf;
        #CannotRemoveController : { principal : Principal };
        #Banned : { reason : Text; expires_at : ?Int };
        #PermissionExpired : { permission : Text; expired_at : Nat64 };
    };

    public type PermissionError = {
        #NotAuthorized : { required_permission : Text };
        #PermissionExpired : { expired_at : Nat64; permission : Text };
        #InvalidPermissionType : { permission : Text };
        #PermissionTypeNotFound : { permission : Text };
        #PermissionTypeExists : { permission : Text };
        #NoPrincipalPermissions : { principal : Principal };
        #ExpirationExceedsMaxDuration : { max_duration : Nat64; requested : Nat64 };
        #PermissionNotFound : { permission : Text; target : Principal };
        #Banned : { reason : Text; expires_at : ?Int };
    };

    public type BanError = {
        #NotAuthorized : { required_permission : Text };
        #CannotBanAdmin : { principal : Principal };
        #UserNotBanned : { principal : Principal };
        #InvalidDurationSettings : { reason : Text };
        #Banned : { reason : Text; expires_at : ?Int };
    };

    public type SnsError = {
        #NotAuthorized : { required_permission : Text };
        #InsufficientVotingPower : { required : Nat64; actual : Nat64 };
        #NeuronNotFound : { neuron_id : Blob };
        #NoNeuronAccess : { neuron_id : Blob };
        #NoPrincipalAccess : { principal : Principal };
        #Banned : { reason : Text; expires_at : ?Int };
        #PermissionExpired : { permission : Text; expired_at : Nat64 };
    };

    // Generic result types
    public type NameResult<T> = {
        #Ok : T;
        #Err : NameError;
    };

    public type AdminResult<T> = {
        #Ok : T;
        #Err : AdminError;
    };

    public type PermissionResult<T> = {
        #Ok : T;
        #Err : PermissionError;
    };

    public type BanResult<T> = {
        #Ok : T;
        #Err : BanError;
    };

    public type SnsResult<T> = {
        #Ok : T;
        #Err : SnsError;
    };
}