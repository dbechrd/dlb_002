#module_parameters(
    YOJIMBO_ENABLE_LOGGING       := false,
    YOJIMBO_DEFAULT_TIMEOUT      := 10,
    YOJIMBO_DEBUG_MEMORY_LEAKS   := #ifx DEBUG,  // then true else false,
    YOJIMBO_DEBUG_MESSAGE_LEAKS  := #ifx DEBUG,  // then true else false,
    YOJIMBO_DEBUG_MESSAGE_BUDGET := #ifx DEBUG   // then true else false,
)

// Some fuckery to trick Jai into only exporting #scope_export things, even when the user names their #import.
// Without this, for some reason, when you name an #import, it imports #scope_module stuff. o_O
using #import,file "yojimbo.jai"(
    YOJIMBO_ENABLE_LOGGING,
    YOJIMBO_DEFAULT_TIMEOUT,
    YOJIMBO_DEBUG_MEMORY_LEAKS,
    YOJIMBO_DEBUG_MESSAGE_LEAKS,
    YOJIMBO_DEBUG_MESSAGE_BUDGET
);