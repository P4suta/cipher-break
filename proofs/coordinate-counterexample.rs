// SPDX-License-Identifier: MIT OR Apache-2.0

#[path = "../src/alphabet.rs"]
mod alphabet;
#[path = "../src/enigma_types.rs"]
mod enigma_types;

use enigma_types::{Indicator, Ring};

#[kani::proof]
fn an_incorrect_round_trip_is_refuted() {
    let indicator = Indicator::new(kani::any());
    let ring = Ring::new(kani::any());
    assert_eq!(indicator.against(ring).with_ring(ring), indicator.step());
}
