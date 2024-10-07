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
