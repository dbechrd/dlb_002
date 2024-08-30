#module_parameters(
    YOJIMBO_ENABLE_LOGGING       := false,
    YOJIMBO_ENABLE_TESTS         := false,
    YOJIMBO_DEFAULT_TIMEOUT      := 10,
    YOJIMBO_DEBUG_MESSAGE_BUDGET := false,
    YOJIMBO_SERIALIZE_CHECKS     := false
);

// Some fuckery to trick Jai into only exporting #scope_export things, even when the user names their #import.
// Without this, for some reason, when you name an #import, it imports #scope_module stuff. o_O
using #import,file "yojimbo.jai"(
    YOJIMBO_ENABLE_LOGGING,
    YOJIMBO_ENABLE_TESTS,
    YOJIMBO_DEFAULT_TIMEOUT,
    YOJIMBO_DEBUG_MESSAGE_BUDGET,
    YOJIMBO_SERIALIZE_CHECKS
);