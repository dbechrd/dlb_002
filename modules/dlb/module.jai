array_fill_byte :: (array: [] $T, value: u8) {
    memset(array.data, value, size_of(T) * array.count);
}

array_zero :: (array: [] $T) {
    memset(array.data, 0, size_of(T) * array.count);
}

array_equal :: (a: [$N] $T, b: [N] T) -> bool {
    return !memcmp(a.data, b.data, a.count);
}

array_copy :: (a: [$N] $T, b: [N] T) {
    memcpy(a.data, b.data, N * size_of(T));
}

pointer_diff :: (a: *$T, b: *$U) -> s64 #expand {
    return cast(s64)((cast(*u8) a) - (cast(*u8) b));
}

get_expression :: (call: Code) -> string {
    #import "Compiler";
    #import "Program_Print";

    root := compiler_get_nodes(call);
    builder: String_Builder;
    print_expression(*builder, root);
    return builder_to_string(*builder);
};

get_argument_name :: (call: Code, index := 0) -> string {
    #import "Compiler";

    root := compiler_get_nodes(call);
    if root.kind == .PROCEDURE_CALL {
        proc_call := cast(*Code_Procedure_Call) root;
        arg := cast(*Code_Ident) proc_call.arguments_sorted[index];
        return arg.name;
    } else {
        err :: "expected a procedure code node";
        assert(false, err);
        return err;
    }
};

dlb_run_test :: (test: (), call := #caller_code) #expand {
    arg0 :: #run get_argument_name(call);
    spaces :: #run -> string {
        space_count := (80 - arg0.count - 10);
        builder: String_Builder;
        for 0..space_count-1 {
            append(*builder, #char " ");
        }
        return builder_to_string(*builder);
    };

TEST_HEADER :: #string EOS
┌──────────────────────────────────────────────────────────────────────────────┐
│ [Test] %0%│
└──────────────────────────────────────────────────────────────────────────────┘
EOS

    log(TEST_HEADER, arg0, spaces);

    test();
}

#scope_file

#import "Basic";