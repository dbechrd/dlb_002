missing_ogg: Sound_Data;
sine_350: Sound_Data;
sine_440: Sound_Data;
sine_480: Sound_Data;

init_audio :: (state: *State) {
    devices := get_devices();
    log("devices: %\n", devices);

    success := sound_player_init(.{ audible_when_window_is_not_in_focus = false });
    assert(success);
    log("sampling rate = %\n", get_audio_sampling_rate());

    set_master_volume(0.5);
    log("volume = %\n", Sound.master_volume);

    //------------------------------------------------------------

    generate_sine_wave(*sine_350, "sine_350", 350.0);
    generate_sine_wave(*sine_440, "sine_440", 440.0);
    generate_sine_wave(*sine_480, "sine_480", 480.0);

    missing_ogg = load_audio_data("missing_ogg", MISSING_OGG_BYTES);
    //------------------------------------------------------------
}

deinit_audio :: (state: *State) {
    sound_player_shutdown();
}

play_sound :: (sound_data: *Sound_Data, loop := false) {
    stream := make_stream(sound_data);
    set_repeating(stream, loop);
    start_playing(stream);
}

#scope_file

// sound_data : destination struct
// sound_name : human-readable name
// frequency  : note to play in Hz
// gain       : volume strength in the range [0.0, 1.0] (warning: 1.0 is *very* loud)
generate_sine_wave :: (using sound_data: *Sound_Data, sound_name: string, frequency := 440.0, gain := 0.05) {
    name                     = sound_name;
    type                     = .LINEAR_SAMPLE_ARRAY;
    sampling_rate            = 44100;
    nchannels                = 2;
    nsamples_times_nchannels = cast(s64) (sampling_rate / frequency) * nchannels;  // exactly one period
    sample_buffer := NewArray(nsamples_times_nchannels, s16);
    buffer  = string.{ sample_buffer.count * 2, cast(*u8) sample_buffer.data };
    samples = sample_buffer.data;

    amplitude := 0xffff * gain;
    dx := frequency / sampling_rate;
    x := 0.0;
    for 0..(sample_buffer.count / nchannels)-1 {
        sample := cast(s16) (amplitude * sin(x * TAU));
        sample_buffer[it*2] = sample;
        sample_buffer[it*2+1] = sample;
        x += dx;
    }
}