// SPDX-License-Identifier: MIT OR Apache-2.0

#[path = "../xtask/src/artifacts.rs"]
mod artifacts;

use std::cell::Cell;

#[kani::proof]
#[kani::unwind(4)]
fn all_artifacts_are_staged_before_any_read_and_failures_stop_transfer() {
    let length: usize = kani::any();
    kani::assume(length <= artifacts::MAX_FILES);
    let stage_pass: [bool; artifacts::MAX_FILES] = kani::any();
    let read_pass: [bool; artifacts::MAX_FILES] = kani::any();
    let files = [0_usize, 1];
    let staged = Cell::new(0_u8);
    let read = Cell::new(0_u8);
    let required = ((1_u16 << length) - 1) as u8;
    let result = artifacts::stage_then_read(
        &files[..length],
        |&index| {
            if !stage_pass[index] {
                return Err(());
            }
            staged.set(staged.get() | (1 << index));
            Ok(())
        },
        |&index| {
            assert_eq!(staged.get(), required);
            read.set(read.get() | (1 << index));
            if read_pass[index] { Ok(()) } else { Err(()) }
        },
    );
    let all_staged = (0..length).all(|index| stage_pass[index]);
    let all_read = (0..length).all(|index| read_pass[index]);
    assert_eq!(result.is_ok(), all_staged && all_read);
    assert!(all_staged || read.get() == 0);
    kani::cover!(length == artifacts::MAX_FILES && result.is_ok());
    kani::cover!(length > 0 && !all_staged && read.get() == 0);
    kani::cover!(all_staged && !all_read && result.is_err());
}
