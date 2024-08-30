#module_parameters(
    ENABLE_LOGGING := false,
    LITTLE_ENDIAN := true
);

// Some fuckery to trick Jai into only exporting #scope_export things, even when the user names their #import.
// Without this, for some reason, when you name an #import, it imports #scope_module stuff. o_O
using #import,file "serialize.jai"(
    ENABLE_LOGGING,
    LITTLE_ENDIAN
);