// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::alphabet::ALPHABET;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Indicator(u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ring(u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Offset(u8);

macro_rules! modular {
    ($name:ident) => {
        impl $name {
            #[inline]
            #[must_use]
            pub const fn new(value: u8) -> Self {
                $name(value % ALPHABET as u8)
            }

            #[inline]
            #[must_use]
            pub const fn value(self) -> u8 {
                self.0
            }

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
    #[inline]
    #[must_use]
    pub const fn step(self) -> Self {
        Indicator((self.0 + 1) % ALPHABET as u8)
    }

    #[inline]
    #[must_use]
    pub const fn against(self, ring: Ring) -> Offset {
        Offset((self.0 + ALPHABET as u8 - ring.0) % ALPHABET as u8)
    }
}

impl Offset {
    #[inline]
    #[must_use]
    pub const fn with_ring(self, ring: Ring) -> Indicator {
        Indicator((self.0 + ring.value()) % ALPHABET as u8)
    }

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
