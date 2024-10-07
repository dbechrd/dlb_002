font: *Simp.Dynamic_Font;

init_fonts :: (state: *State) {
    if font != null {
        Simp.release_font(font);
    }

    pixel_height := state.window_size.y / 36;

    // @Cleanup: Don't have path + name be separate.
    font = Simp.get_font_at_size(".", "KarminaBold.otf", pixel_height);
    assert(font != null);
}