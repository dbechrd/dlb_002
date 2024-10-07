Simp :: #import "Simp";

Size :: struct { x: s64; y: s64; };

init :: () {
    path := path_strip_filename(get_path_of_running_executable());
    set_working_directory(path);

    #if OS == .WINDOWS {
        Windows :: #import "Windows";

        Windows.SetProcessDPIAware();

        // Windows is very bad at thread-switching by default unless you do this. Sad.
        Windows.timeBeginPeriod(1);
    }

    init_logger();
}

#scope_file

#import "String";  // For path_strip_filename. @Cleanup.
#import "System";  // For get_path_of_running_executable. @Cleanup.
