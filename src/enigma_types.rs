// SPDX-License-Identifier: MIT OR Apache-2.0

//! The three numbers an Enigma rotor has, kept apart by the type system.
//!
//! A rotor carries an indicator — the letter in its window — and a ring setting, and enters its wiring at the difference between them.
//! All three are numbers modulo 26, all three are written as single letters, and mixing them up produces a machine that runs perfectly and deciphers nothing.
//!
//! This module exists because that mistake was made here.
//! A GPU kernel was written that stepped the indicator and then used it as the wiring offset,
//! which is correct for every message whose ring setting is `A` and wrong for every other one — a bug that passes its round-trip test, passes its textbook vector, and fails only on real traffic.
//!
//! So the three are different types.
//! An [`Offset`] can only be made by taking a [`Ring`] away from an [`Indicator`]; a notch can only be tested against an [`Indicator`]; a wiring can only be entered at an [`Offset`].
//! The compiler now refuses the program that was written.

use crate::alphabet::ALPHABET;

/// The letter showing in a rotor's window, which is what its notch fires on and what steps with every keypress.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Indicator(u8);

/// Where a rotor's alphabet ring is clamped, which is fixed for a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ring(u8);

/// How far into its wiring a rotor is entered: the indicator less the ring.
///
/// There is deliberately no way to build one of these from a number.
/// It comes from an indicator and a ring or it does not exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Offset(u8);

macro_rules! modular {
    ($name:ident) => {
        impl $name {
            /// Reduce any number into the alphabet.
            #[inline]
            #[must_use]
            pub const fn new(value: u8) -> Self {
                $name(value % ALPHABET as u8)
            }

            /// The underlying residue, for the arithmetic that has to happen somewhere.
            #[inline]
            #[must_use]
            pub const fn value(self) -> u8 {
                self.0
            }

            /// As an index into a 26-element table.
            #[inline]
            #[must_use]
            pub const fn index(self) -> usize {
                self.0 as usize
            }
        }

        impl From<$name> for u8 {
            fn from(v: $name) -> u8 {
                v.0
            }
        }
    };
}

modular!(Indicator);
modular!(Ring);
modular!(Offset);

impl Indicator {
    /// The next letter in the window.
    #[inline]
    #[must_use]
    pub const fn step(self) -> Self {
        Indicator((self.0 + 1) % ALPHABET as u8)
    }

    /// Where the wiring is entered, given where the ring sits.
    ///
    /// The only constructor of an [`Offset`], on purpose.
    #[inline]
    #[must_use]
    pub const fn against(self, ring: Ring) -> Offset {
        Offset((self.0 + ALPHABET as u8 - ring.0) % ALPHABET as u8)
    }
}

impl Offset {
    /// The indicator that produces this offset against a given ring.
    ///
    /// The inverse of [`Indicator::against`], and the operation a ring search is made of: hold the wiring where the rotor sweep found it and move only the moment the notch fires.
    #[inline]
    #[must_use]
    pub const fn with_ring(self, ring: Ring) -> Indicator {
        Indicator((self.0 + ring.value()) % ALPHABET as u8)
    }

    /// Enter a wiring at this offset and leave it at the same one.
    ///
    /// Both halves of the shift live here together, which is the other way this arithmetic used to go wrong: shifting in and forgetting to shift out produces a machine that is its own inverse and reads nothing.
    #[inline]
    #[must_use]
    pub fn through(self, wiring: &[u8; ALPHABET], letter: u8) -> u8 {
        let entered = (letter + self.0) % ALPHABET as u8;
        (wiring[entered as usize] + ALPHABET as u8 - self.0) % ALPHABET as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_offset_is_the_indicator_less_the_ring() {
        assert_eq!(Indicator::new(5).against(Ring::new(2)), Offset::new(3));
        assert_eq!(Indicator::new(1).against(Ring::new(5)), Offset::new(22));
    }

    #[test]
    fn a_ring_of_a_leaves_the_indicator_alone() {
        for i in 0..26u8 {
            assert_eq!(Indicator::new(i).against(Ring::new(0)).value(), i);
        }
    }

    #[test]
    fn stepping_wraps() {
        assert_eq!(Indicator::new(25).step(), Indicator::new(0));
    }

    #[test]
    fn everything_reduces_into_the_alphabet() {
        assert_eq!(Indicator::new(30).value(), 4);
        assert_eq!(Ring::new(52).value(), 0);
    }

    #[test]
    fn with_ring_inverts_against() {
        for i in 0..26u8 {
            for r in 0..26u8 {
                let indicator = Indicator::new(i);
                let ring = Ring::new(r);
                assert_eq!(indicator.against(ring).with_ring(ring), indicator);
            }
        }
    }

    #[test]
    fn moving_a_ring_and_its_indicator_together_leaves_the_wiring_alone() {
        // The property a ring search depends on and the reason it is a search over notch timings rather than over wirings.
        let offset = Indicator::new(9).against(Ring::new(0));
        for r in 0..26u8 {
            let ring = Ring::new(r);
            assert_eq!(offset.with_ring(ring).against(ring), offset);
        }
    }

    #[test]
    fn a_wiring_at_offset_zero_is_the_wiring() {
        let identity: [u8; ALPHABET] = std::array::from_fn(|i| i as u8);
        for l in 0..26u8 {
            assert_eq!(Offset::new(0).through(&identity, l), l);
        }
    }

    #[test]
    fn a_shift_in_is_a_shift_out() {
        // The property the pair of shifts exists to hold: an offset applied to the identity wiring is still the identity, whatever the offset.
        let identity: [u8; ALPHABET] = std::array::from_fn(|i| i as u8);
        for o in 0..26u8 {
            for l in 0..26u8 {
                assert_eq!(
                    Offset::new(o).through(&identity, l),
                    l,
                    "offset {o}, letter {l}"
                );
            }
        }
    }
}
