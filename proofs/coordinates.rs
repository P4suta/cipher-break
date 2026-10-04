// SPDX-License-Identifier: MIT OR Apache-2.0

#[path = "../src/alphabet.rs"]
mod alphabet;
#[path = "../src/enigma_types.rs"]
mod enigma_types;

use enigma_types::{Indicator, Offset, Ring};

#[kani::proof]
fn ring_coordinate_round_trips() {
    let raw: u8 = kani::any();
    let raw_ring: u8 = kani::any();
    let indicator = Indicator::new(raw);
    let offset = Offset::new(raw);
    let ring = Ring::new(raw_ring);
    assert_eq!(indicator.against(ring).with_ring(ring), indicator);
    assert_eq!(offset.with_ring(ring).against(ring), offset);
    assert!(indicator.step().value() < alphabet::ALPHABET as u8);
    assert_eq!(
        indicator.step().value(),
        (indicator.value() + 1) % alphabet::ALPHABET as u8
    );
    kani::cover!(indicator.value() == 25 && ring.value() == 0);
    kani::cover!(indicator.value() == 0 && ring.value() == 25);
    kani::cover!(raw == 255 && raw_ring == 255);
}
