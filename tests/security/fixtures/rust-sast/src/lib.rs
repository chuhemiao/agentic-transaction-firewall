//! Deliberately unsafe, never executed: DS-038 proves the SAST gate rejects it.

pub fn read_unchecked(pointer: *const u8) -> u8 {
    // SAFETY: This is an inert negative fixture, not application code.
    unsafe { *pointer }
}
