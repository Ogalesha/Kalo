#![no_main]
// The whole sanitizer module is included so the fuzz target exercises the
// exact code the application uses; its filesystem helpers are not called here.
#![allow(dead_code)]

//! Fuzz the filename sanitizer applied to every incoming OPP object.
//!
//! The sanitizer must always return a single, non-empty, portable path
//! component. Path traversal, control characters, Windows device names and
//! alternate data streams must never survive it.

use libfuzzer_sys::fuzz_target;

#[path = "../../src/sanitize.rs"]
mod sanitize;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let name = sanitize::filename(input);
    assert!(!name.is_empty(), "empty name for {input:?}");
    assert!(name.len() <= 200, "oversized name for {input:?}");
    assert!(!name.starts_with('.'), "dotfile for {input:?}");
    assert!(!name.ends_with('.'), "trailing dot for {input:?}");
    assert!(!name.ends_with(' '), "trailing space for {input:?}");

    for character in name.chars() {
        assert!(!character.is_control(), "control character for {input:?}");
        assert!(
            !matches!(
                character,
                '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'
            ),
            "hostile character {character:?} for {input:?}"
        );
    }

    // Sanitizing an already-safe component must keep it usable.
    assert!(!sanitize::filename(&name).is_empty());
});
