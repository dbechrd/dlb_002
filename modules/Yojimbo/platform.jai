#scope_module

/**
    Sleep for approximately this number of seconds.
    @param time number of seconds to sleep for.
 */

void yojimbo_sleep( double time );

/**
    Get a high precision time in seconds since the application has started.
    Please store time in doubles so you retain sufficient precision as time increases.
    @returns Time value in seconds.
 */

double yojimbo_time();

#define YOJIMBO_LOG_LEVEL_NONE      0
#define YOJIMBO_LOG_LEVEL_ERROR     1
#define YOJIMBO_LOG_LEVEL_INFO      2
#define YOJIMBO_LOG_LEVEL_DEBUG     3

/**
    Set the yojimbo log level.
    Valid log levels are: YOJIMBO_LOG_LEVEL_NONE, YOJIMBO_LOG_LEVEL_ERROR, YOJIMBO_LOG_LEVEL_INFO and YOJIMBO_LOG_LEVEL_DEBUG
    @param level The log level to set. Initially set to YOJIMBO_LOG_LEVEL_NONE.
 */

void yojimbo_log_level( int level );

/**
    Printf function used by yojimbo to emit logs.
    This function internally calls the printf callback set by the user.
    @see yojimbo_set_printf_function
 */

void yojimbo_printf( int level, const char * format, ... );

extern void (*yojimbo_assert_function)( const char *, const char *, const char * file, int line );

/**
    Assert function used by yojimbo.
    This assert function lets the user override the assert presentation.
    @see yojimbo_set_assert_functio
 */

#ifdef YOJIMBO_DEBUG
#define yojimbo_assert( condition )                                                         \
do                                                                                          \
{                                                                                           \
    if ( !(condition) )                                                                     \
    {                                                                                       \
        yojimbo_assert_function( #condition, __FUNCTION__, __FILE__, __LINE__ );            \
        exit(1);                                                                            \
    }                                                                                       \
} while(0)
#else
#define yojimbo_assert( ignore ) ((void)0)
#endif

/**
    Call this to set the printf function to use for logging.
    @param function The printf callback function.
 */

void yojimbo_set_printf_function( int (*function)( const char * /*format*/, ... ) );

/**
    Call this to set the function to call when an assert triggers.
    @param function The assert callback function.
 */

void yojimbo_set_assert_function( void (*function)( const char * /*condition*/, const char * /*function*/, const char * /*file*/, int /*line*/ ) );

static void default_assert_handler( const char * condition, const char * function, const char * file, int line )
{
    // We use YOJIMBO_LOG_LEVEL_NONE because it's lower than YOJIMBO_LOG_LEVEL_ERROR, so even if you suppress errors (by setting
    // yojimbo_log_level(YOJIMBO_LOG_LEVEL_NONE)), this will still be logged.
    yojimbo_printf( YOJIMBO_LOG_LEVEL_NONE, "assert failed: ( %s ), function %s, file %s, line %d\n", condition, function, file, line );
    #if defined( __GNUC__ )
    __builtin_trap();
    #elif defined( _MSC_VER )
    __debugbreak();
    #endif
}

static int log_level = 0;

static int (*printf_function)( const char *, ... ) = printf;

void (*yojimbo_assert_function)( const char *, const char *, const char * file, int line ) = default_assert_handler;

void yojimbo_log_level( int level )
{
    log_level = level;
    netcode_log_level( level );
    reliable_log_level( level );
}

void yojimbo_set_printf_function( int (*function)( const char *, ... ) )
{
    yojimbo_assert( function );
    printf_function = function;
    netcode_set_printf_function( function );
    reliable_set_printf_function( function );
}

void yojimbo_set_assert_function( void (*function)( const char *, const char *, const char * file, int line ) )
{
    yojimbo_assert_function = function;
    netcode_set_assert_function( function );
    reliable_set_assert_function( function );
}

#if YOJIMBO_ENABLE_LOGGING

void yojimbo_printf( int level, const char * format, ... )
{
    if ( level > log_level )
        return;
    va_list args;
    va_start( args, format );
    char buffer[4*1024];
    vsnprintf( buffer, sizeof(buffer), format, args );
    printf_function( "%s", buffer );
    va_end( args );
}

#else // #if YOJIMBO_ENABLE_LOGGING

void yojimbo_printf( int level, const char * format, ... )
{
    (void) level;
    (void) format;
}

#endif // #if YOJIMBO_ENABLE_LOGGING

#if __APPLE__

// ===============================
//              MacOS
// ===============================

#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_time.h>

void yojimbo_sleep( double time )
{
    usleep( (int) ( time * 1000000 ) );
}

double yojimbo_time()
{
    static uint64_t start = 0;

    static mach_timebase_info_data_t timebase_info;

    if ( start == 0 )
    {
        mach_timebase_info( &timebase_info );
        start = mach_absolute_time();
        return 0.0;
    }

    uint64_t current = mach_absolute_time();

    if ( current < start )
        current = start;

    return ( double( current - start ) * double( timebase_info.numer ) / double( timebase_info.denom ) ) / 1000000000.0;
}

#elif __linux

// ===============================
//              Linux
// ===============================

#include <unistd.h>
#include <time.h>

void yojimbo_sleep( double time )
{
    usleep( (int) ( time * 1000000 ) );
}

double yojimbo_time()
{
    static double start = -1;

    if ( start == -1 )
    {
        timespec ts;
        clock_gettime( CLOCK_MONOTONIC_RAW, &ts );
        start = ts.tv_sec + double( ts.tv_nsec ) / 1000000000.0;
        return 0.0;
    }

    timespec ts;
    clock_gettime( CLOCK_MONOTONIC_RAW, &ts );
    double current = ts.tv_sec + double( ts.tv_nsec ) / 1000000000.0;
    if ( current < start )
        current = start;
    return current - start;
}

#elif defined(_WIN32)

// ===============================
//             Windows
// ===============================

#define NOMINMAX
#include <windows.h>

void yojimbo_sleep( double time )
{
    const int milliseconds = time * 1000;
    Sleep( milliseconds );
}

static bool timer_initialized = false;
static LARGE_INTEGER timer_frequency;
static LARGE_INTEGER timer_start;

double yojimbo_time()
{
    if ( !timer_initialized )
    {
        QueryPerformanceFrequency( &timer_frequency );
        QueryPerformanceCounter( &timer_start );
        timer_initialized = true;
    }
    LARGE_INTEGER now;
    QueryPerformanceCounter( &now );
    if ( now.QuadPart < timer_start.QuadPart )
        now.QuadPart = timer_start.QuadPart;
    return double( now.QuadPart - timer_start.QuadPart ) / double( timer_frequency.QuadPart );
}

#else

#error unsupported platform!

#endif

