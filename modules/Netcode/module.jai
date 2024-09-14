#module_parameters(
    NETCODE_ENABLE_LOGGING := false,
    NETCODE_DISABLE_SECURITY := false
);

// Some fuckery to trick Jai into only exporting #scope_export things, even when the user names their #import.
// Without this, for some reason, when you name an #import, it imports #scope_module stuff. o_O
using #import,file "netcode.jai"(
    NETCODE_ENABLE_LOGGING,
    NETCODE_DISABLE_SECURITY
);