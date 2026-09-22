// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Enigma machine.
//!
//! Enigma is the one cipher here whose key does not fit in any of the shapes the rest of this module uses.
//! Its state advances with every letter, so it has no period to find; its plugboard is a 26-letter involution chosen from about a hundred and fifty trillion; and its rotors turn over on notches that make the whole thing non-linear in the position.
//!
//! What it does have is a seam.
//! The rotor order, the starting positions and the reflector together number only a couple of million, and the plugboard —
//! enormous as it is — barely disturbs the statistics of a decipherment that has the rotors right.
//! That is the whole of the ciphertext-only attack: find the rotors by exhaustion, then let the plugboard fall out one pair at a time.
//!
//! The reflector also gives the machine its most famous property and its greatest weakness: no letter is ever enciphered as itself.
//! Nothing in this module needs that, but an attack does, and it is exact rather than statistical, which makes it worth more than any amount of frequency work.

use crate::alphabet::{ALPHABET, Letter};

/// The five Wehrmacht rotors and the three Naval ones, with the notch positions at which each turns the rotor to its left.
pub const ROTORS: [(&str, &str); 8] = [
    ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
    ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
    ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
    ("ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
    ("VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
    ("JPGVOUMFYQBENHZRDKASXLICTW", "ZM"),
    ("NZJHGRCXMYSWBOUFAIVLPEKQDT", "ZM"),
    ("FKQHTLXOCBJSPDZRAMEWNIUYGV", "ZM"),
];

/// Reflectors B and C.
pub const REFLECTORS: [&str; 2] = ["YRUHQSLDPXNGOKMIEBFZCWVJAT", "FVPJIAOYEDRZXWGCTKUQSBNMHL"];

fn wiring(s: &str) -> [u8; ALPHABET] {
    let mut out = [0u8; ALPHABET];
    for (i, c) in s.bytes().enumerate() {
        out[i] = c - b'A';
    }
    out
}

fn inverse(w: &[u8; ALPHABET]) -> [u8; ALPHABET] {
    let mut out = [0u8; ALPHABET];
    for (i, &v) in w.iter().enumerate() {
        out[v as usize] = i as u8;
    }
    out
}

/// One rotor, wired both ways with its notches resolved.
#[derive(Clone, Copy, Debug)]
pub struct Rotor {
    forward: [u8; ALPHABET],
    backward: [u8; ALPHABET],
    notches: [bool; ALPHABET],
}

/// The eight rotors, wired once.
///
/// A sweep builds a machine for every setting it tries, and a naval sweep tries six hundred million of them.
/// Parsing a wiring out of a string that many times is most of the cost of the attack and none of the work; the table is built once and copied from.
static WIRED: std::sync::LazyLock<[Rotor; 8]> = std::sync::LazyLock::new(|| {
    std::array::from_fn(|index| {
        let (spec, notch) = ROTORS[index];
        let forward = wiring(spec);
        let mut notches = [false; ALPHABET];
        for c in notch.bytes() {
            notches[(c - b'A') as usize] = true;
        }
        Rotor {
            forward,
            backward: inverse(&forward),
            notches,
        }
    })
});

/// The reflectors, wired once.
static REFLECTED: std::sync::LazyLock<[[u8; ALPHABET]; 2]> =
    std::sync::LazyLock::new(|| std::array::from_fn(|i| wiring(REFLECTORS[i])));

impl Rotor {
    /// The nth historical rotor, counting from zero.
    #[must_use]
    pub fn new(index: usize) -> Rotor {
        WIRED[index % WIRED.len()]
    }
}

/// A plugboard: an involution on the alphabet.
#[derive(Clone, Copy, Debug)]
pub struct Plugboard([u8; ALPHABET]);

impl Default for Plugboard {
    fn default() -> Self {
        Plugboard(std::array::from_fn(|i| i as u8))
    }
}

impl Plugboard {
    /// A board with no leads in it.
    #[must_use]
    pub fn empty() -> Self {
        Plugboard::default()
    }

    /// Add a lead, removing whatever either letter was joined to.
    pub fn connect(&mut self, a: Letter, b: Letter) {
        let (a, b) = (a as usize % ALPHABET, b as usize % ALPHABET);
        let (oa, ob) = (self.0[a] as usize, self.0[b] as usize);
        self.0[oa] = oa as u8;
        self.0[ob] = ob as u8;
        self.0[a] = b as u8;
        self.0[b] = a as u8;
    }

    /// Remove whatever leads touch a letter.
    pub fn disconnect(&mut self, a: Letter) {
        let a = a as usize % ALPHABET;
        let partner = self.0[a] as usize;
        self.0[partner] = partner as u8;
        self.0[a] = a as u8;
    }

    /// The letter a lead sends this one to.
    #[inline]
    #[must_use]
    pub fn map(&self, l: Letter) -> Letter {
        self.0[l as usize % ALPHABET]
    }

    /// The pairs the board joins.
    #[must_use]
    pub fn pairs(&self) -> Vec<(Letter, Letter)> {
        (0..ALPHABET as u8)
            .filter(|&a| self.0[a as usize] > a)
            .map(|a| (a, self.0[a as usize]))
            .collect()
    }
}

/// Everything that has to be chosen before a message can be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Which rotor sits in each slot, left to right.
    pub rotors: [usize; 3],
    /// Which reflector is fitted.
    pub reflector: usize,
    /// The ring setting of each rotor, left to right.
    pub rings: [u8; 3],
    /// Where each rotor starts, left to right.
    pub positions: [u8; 3],
}

impl Settings {
    /// Settings with everything at its first value.
    #[must_use]
    pub fn new(rotors: [usize; 3], reflector: usize) -> Settings {
        Settings {
            rotors,
            reflector,
            rings: [0; 3],
            positions: [0; 3],
        }
    }
}

/// A machine, set up and ready to run.
#[derive(Clone, Debug)]
pub struct Enigma {
    rotors: [Rotor; 3],
    reflector: [u8; ALPHABET],
    rings: [u8; 3],
    positions: [u8; 3],
    plugboard: Plugboard,
}

impl Enigma {
    /// Assemble a machine.
    #[must_use]
    pub fn new(settings: Settings, plugboard: Plugboard) -> Enigma {
        Enigma {
            rotors: [
                Rotor::new(settings.rotors[0]),
                Rotor::new(settings.rotors[1]),
                Rotor::new(settings.rotors[2]),
            ],
            reflector: REFLECTED[settings.reflector % REFLECTED.len()],
            rings: settings.rings,
            positions: settings.positions,
            plugboard,
        }
    }

    /// Advance the rotors, including the double step the middle one makes when it is sitting on its own notch.
    fn step(&mut self) {
        let middle_at_notch = self.rotors[1].notches[self.positions[1] as usize];
        let right_at_notch = self.rotors[2].notches[self.positions[2] as usize];
        if middle_at_notch {
            self.positions[1] = (self.positions[1] + 1) % ALPHABET as u8;
            self.positions[0] = (self.positions[0] + 1) % ALPHABET as u8;
        } else if right_at_notch {
            self.positions[1] = (self.positions[1] + 1) % ALPHABET as u8;
        }
        self.positions[2] = (self.positions[2] + 1) % ALPHABET as u8;
    }

    #[inline]
    fn through(wire: &[u8; ALPHABET], l: Letter, position: u8, ring: u8) -> Letter {
        let shift = (position + ALPHABET as u8 - ring) % ALPHABET as u8;
        let entered = (l + shift) % ALPHABET as u8;
        (wire[entered as usize] + ALPHABET as u8 - shift) % ALPHABET as u8
    }

    /// Encipher one letter, advancing the machine first as a keypress does.
    ///
    /// Enigma is its own inverse, so this deciphers too.
    #[must_use]
    pub fn press(&mut self, l: Letter) -> Letter {
        self.step();
        let mut c = self.plugboard.map(l);
        for i in (0..3).rev() {
            c = Self::through(&self.rotors[i].forward, c, self.positions[i], self.rings[i]);
        }
        c = self.reflector[c as usize];
        for i in 0..3 {
            c = Self::through(
                &self.rotors[i].backward,
                c,
                self.positions[i],
                self.rings[i],
            );
        }
        self.plugboard.map(c)
    }

    /// Run a whole message.
    #[must_use]
    pub fn run(&mut self, text: &[Letter]) -> Vec<Letter> {
        text.iter().map(|&l| self.press(l)).collect()
    }

    /// Run a whole message into an existing buffer.
    pub fn run_into(&mut self, text: &[Letter], out: &mut [Letter]) {
        for (&l, slot) in text.iter().zip(out.iter_mut()) {
            *slot = self.press(l);
        }
    }

    /// Point an existing machine at a new setting, without rebuilding it.
    ///
    /// A sweep can then keep one machine per thread and move it, which is the difference between copying three wiring tables per key and copying none.
    pub fn aim(&mut self, settings: Settings, reflector: [u8; ALPHABET]) {
        for (slot, &r) in self.rotors.iter_mut().zip(settings.rotors.iter()) {
            *slot = WIRED[r % WIRED.len()];
        }
        self.reflector = reflector;
        self.rings = settings.rings;
        self.positions = settings.positions;
    }

    /// Point an existing machine at a new setting, keeping its rotors.
    ///
    /// The inner loop of a sweep walks the starting positions with everything else fixed, and this is that loop's whole cost: three bytes.
    #[inline]
    pub fn restart(&mut self, positions: [u8; 3]) {
        self.positions = positions;
    }

    /// The plugboard in use.
    #[must_use]
    pub fn plugboard(&self) -> Plugboard {
        self.plugboard
    }

    /// Fit a different plugboard.
    #[inline]
    pub fn replug(&mut self, plugboard: Plugboard) {
        self.plugboard = plugboard;
    }
}

/// The rotor wirings, flattened for a device: forward, backward, and one notch bitmask per rotor.
#[must_use]
pub fn rotor_tables() -> (Vec<u8>, Vec<u8>, Vec<u32>) {
    let mut forward = Vec::with_capacity(8 * ALPHABET);
    let mut backward = Vec::with_capacity(8 * ALPHABET);
    let mut notches = Vec::with_capacity(8);
    for r in &*WIRED {
        forward.extend_from_slice(&r.forward);
        backward.extend_from_slice(&r.backward);
        let mut mask = 0u32;
        for (i, &n) in r.notches.iter().enumerate() {
            if n {
                mask |= 1 << i;
            }
        }
        notches.push(mask);
    }
    (forward, backward, notches)
}

/// The wiring of reflector B or C.
#[must_use]
pub fn reflector_wiring(index: usize) -> [u8; ALPHABET] {
    REFLECTED[index % REFLECTED.len()]
}

/// Every rotor order that can be drawn from the first `available` rotors.
#[must_use]
pub fn rotor_orders(available: usize) -> Vec<[usize; 3]> {
    let mut out = Vec::new();
    for a in 0..available {
        for b in 0..available {
            if b == a {
                continue;
            }
            for c in 0..available {
                if c == a || c == b {
                    continue;
                }
                out.push([a, b, c]);
            }
        }
    }
    out
}

/// Whether a plaintext could have come from a ciphertext through an Enigma.
///
/// The reflector can never send a letter back to itself, so no position of a true decipherment agrees with the ciphertext.
/// One pass, no key, and it refutes outright rather than by degree.
#[must_use]
pub fn compatible(ct: &[Letter], pt: &[Letter]) -> bool {
    ct.iter().zip(pt).all(|(a, b)| a != b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alphabet::{from_letters, to_letters};

    #[test]
    fn it_matches_the_textbook_vector() {
        // Rotors I II III, reflector B, rings AAA, positions AAA, no leads:
        // AAAAA enciphers to BDZGO.
        let mut m = Enigma::new(Settings::new([0, 1, 2], 0), Plugboard::empty());
        assert_eq!(from_letters(&m.run(&to_letters("AAAAA"))), "BDZGO");
    }

    #[test]
    fn it_is_its_own_inverse() {
        let settings = Settings {
            rotors: [2, 0, 3],
            reflector: 1,
            rings: [4, 17, 9],
            positions: [11, 2, 25],
        };
        let mut board = Plugboard::empty();
        board.connect(0, 20);
        board.connect(4, 12);
        let plain = to_letters("DASISTEINGEHEIMERTEXTFUERDIEPRUEFUNGDERMASCHINE");
        let ct = Enigma::new(settings, board).run(&plain);
        let back = Enigma::new(settings, board).run(&ct);
        assert_eq!(back, plain);
    }

    #[test]
    fn no_letter_is_ever_itself() {
        let settings = Settings {
            rotors: [0, 1, 2],
            reflector: 0,
            rings: [0; 3],
            positions: [0; 3],
        };
        let plain: Vec<u8> = (0..200).map(|i| (i % 26) as u8).collect();
        let ct = Enigma::new(settings, Plugboard::empty()).run(&plain);
        assert!(compatible(&ct, &plain));
    }

    #[test]
    fn the_middle_rotor_double_steps() {
        // The famous anomaly: a rotor sitting on its own notch takes the one to its left with it, and moves again itself.
        // Rotor II notches at E,
        // so a middle rotor resting there carries the left rotor on the very next keypress.
        let settings = Settings {
            rotors: [0, 1, 2],
            reflector: 0,
            rings: [0; 3],
            positions: [0, 4, 0],
        };
        let mut m = Enigma::new(settings, Plugboard::empty());
        let _ = m.press(0);
        assert_eq!(m.positions[0], 1, "the left rotor should have moved");
        assert_eq!(
            m.positions[1], 5,
            "the middle rotor should have moved with it"
        );

        // And without the middle rotor on its notch, the left one stays put.
        let quiet = Settings {
            rotors: [0, 1, 2],
            reflector: 0,
            rings: [0; 3],
            positions: [0, 0, 0],
        };
        let mut still = Enigma::new(quiet, Plugboard::empty());
        let _ = still.press(0);
        assert_eq!(still.positions[0], 0);
        assert_eq!(still.positions[1], 0);
    }

    #[test]
    fn a_plugboard_lead_is_reciprocal() {
        let mut board = Plugboard::empty();
        board.connect(0, 5);
        assert_eq!(board.map(0), 5);
        assert_eq!(board.map(5), 0);
        board.disconnect(0);
        assert_eq!(board.map(0), 0);
        assert_eq!(board.map(5), 5);
    }

    #[test]
    fn connecting_a_letter_twice_moves_its_lead() {
        let mut board = Plugboard::empty();
        board.connect(0, 5);
        board.connect(0, 9);
        assert_eq!(board.map(5), 5);
        assert_eq!(board.map(0), 9);
        assert_eq!(board.pairs(), vec![(0, 9)]);
    }

    #[test]
    fn there_are_sixty_wehrmacht_rotor_orders() {
        assert_eq!(rotor_orders(5).len(), 60);
        assert_eq!(rotor_orders(8).len(), 336);
    }
}

// --------------------------------------------------------------------------
// The Naval four-rotor machine
// --------------------------------------------------------------------------

/// The two Greek rotors, which sit to the left of the other three and never turn.
pub const GREEK: [&str; 2] = ["LEYJVCNIXWPBQMDRTAKZGFUHOS", "FSOKANUERHMBTIYCWLQPZXVGJD"];

/// The thin reflectors the four-rotor machine uses in place of B and C.
pub const THIN: [&str; 2] = ["ENKQAUYWJICOPBLMDXZVFTHRGS", "RDOBJNTKVEHMLFCWZAXGYIPSUQ"];

/// Fold a Greek rotor, its setting and a thin reflector into one reflector.
///
/// This is what makes the four-rotor machine tractable.
/// The Greek rotor never steps, so for a whole message it and the thin reflector behind it are a single fixed permutation — and a permutation that is still an involution,
/// because the reflector is.
/// A four-rotor Enigma is therefore a three-rotor Enigma with one of `2 × 26 × 2` reflectors, which turns a key space of billions into one an exhaustive sweep can hold.
#[must_use]
pub fn composite_reflector(greek: usize, setting: u8, thin: usize) -> [u8; ALPHABET] {
    let g = wiring(GREEK[greek % GREEK.len()]);
    let g_inv = inverse(&g);
    let t = wiring(THIN[thin % THIN.len()]);
    let shift = setting % ALPHABET as u8;
    let mut out = [0u8; ALPHABET];
    for (c, slot) in out.iter_mut().enumerate() {
        let entered = (c as u8 + shift) % ALPHABET as u8;
        let a = (g[entered as usize] + ALPHABET as u8 - shift) % ALPHABET as u8;
        let b = t[a as usize];
        let entered_back = (b + shift) % ALPHABET as u8;
        *slot = (g_inv[entered_back as usize] + ALPHABET as u8 - shift) % ALPHABET as u8;
    }
    out
}

/// Every reflector a four-rotor machine can present, with the name of each.
#[must_use]
pub fn naval_reflectors() -> Vec<(String, [u8; ALPHABET])> {
    let mut out = Vec::new();
    for (g, gname) in ["beta", "gamma"].iter().enumerate() {
        for (t, tname) in ["B-thin", "C-thin"].iter().enumerate() {
            for setting in 0..ALPHABET as u8 {
                out.push((
                    format!("{gname}/{} {tname}", crate::alphabet::letter_char(setting)),
                    composite_reflector(g, setting, t),
                ));
            }
        }
    }
    out
}

impl Enigma {
    /// A machine with a reflector given outright, for the four-rotor case.
    #[must_use]
    pub fn with_reflector(
        settings: Settings,
        reflector: [u8; ALPHABET],
        plugboard: Plugboard,
    ) -> Enigma {
        Enigma {
            rotors: [
                Rotor::new(settings.rotors[0]),
                Rotor::new(settings.rotors[1]),
                Rotor::new(settings.rotors[2]),
            ],
            reflector,
            rings: settings.rings,
            positions: settings.positions,
            plugboard,
        }
    }
}

#[cfg(test)]
mod naval_tests {
    use super::*;
    use crate::alphabet::to_letters;

    #[test]
    fn a_composite_reflector_is_still_an_involution() {
        for g in 0..2 {
            for t in 0..2 {
                for setting in 0..26u8 {
                    let r = composite_reflector(g, setting, t);
                    for c in 0..26u8 {
                        assert_eq!(r[r[c as usize] as usize], c, "g{g} t{t} s{setting} c{c}");
                        assert_ne!(r[c as usize], c, "a reflector never fixes a letter");
                    }
                }
            }
        }
    }

    #[test]
    fn there_are_104_naval_reflectors() {
        assert_eq!(naval_reflectors().len(), 104);
    }

    #[test]
    fn the_naval_machine_is_its_own_inverse() {
        let settings = Settings {
            rotors: [0, 3, 6],
            reflector: 0,
            rings: [2, 5, 11],
            positions: [7, 19, 3],
        };
        let reflector = composite_reflector(0, 12, 0);
        let mut board = Plugboard::empty();
        board.connect(1, 20);
        board.connect(8, 15);
        let plain = to_letters("VONVONJAWEGENDERSITUATIONXXMELDEICHXXFEINDKONVOIINSICHT");
        let ct = Enigma::with_reflector(settings, reflector, board).run(&plain);
        let back = Enigma::with_reflector(settings, reflector, board).run(&ct);
        assert_eq!(back, plain);
        assert!(compatible(&ct, &plain));
    }
}
