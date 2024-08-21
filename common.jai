Simp :: #import "Simp";

Size :: struct { x: s64; y: s64; };

dlb_init_common :: () {
    path := path_strip_filename(get_path_of_running_executable());
    set_working_directory(path);

    #if OS == .WINDOWS {
        Windows :: #import "Windows";

        Windows.SetProcessDPIAware();

        // Windows is very bad at thread-switching by default unless you do this. Sad.
        Windows.timeBeginPeriod(1);
    }

    context.print_style.default_format_struct.use_long_form_if_more_than_this_many_members = -1;
    context.print_style.default_format_struct.use_newlines_if_long_form = true;
}

#scope_file

#import "String";  // For path_strip_filename. @Cleanup.
#import "System";  // For get_path_of_running_executable. @Cleanup.
