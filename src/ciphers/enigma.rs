// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::alphabet::{ALPHABET, Letter};
use crate::enigma_types::{Indicator, Offset, Ring};

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

pub const REFLECTORS: [&str; 2] = ["YRUHQSLDPXNGOKMIEBFZCWVJAT", "FVPJIAOYEDRZXWGCTKUQSBNMHL"];

pub const ROTOR_COUNT: usize = ROTORS.len();

pub const SLOTS: usize = 3;

pub const REFLECTOR_COUNT: usize = REFLECTORS.len();

pub const NAVAL_REFLECTOR_COUNT: usize = GREEK.len() * THIN.len() * ALPHABET;

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

#[derive(Clone, Copy, Debug)]
pub struct Rotor {
    forward: [u8; ALPHABET],
    backward: [u8; ALPHABET],
    notches: [bool; ALPHABET],
}

static WIRED: std::sync::LazyLock<[Rotor; ROTOR_COUNT]> = std::sync::LazyLock::new(|| {
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

type Shifted = [[[u8; ALPHABET]; ALPHABET]; ROTOR_COUNT];

static SHIFTED: std::sync::LazyLock<(Shifted, Shifted)> = std::sync::LazyLock::new(|| {
    let build = |pick: fn(&Rotor) -> &[u8; ALPHABET]| -> Shifted {
        std::array::from_fn(|r| {
            let wiring = pick(&WIRED[r]);
            std::array::from_fn(|o| {
                std::array::from_fn(|l| {
                    let (l, shift) = (l as u8, o as u8);
                    let entered = (l + shift) % ALPHABET as u8;
                    (wiring[entered as usize] + ALPHABET as u8 - shift) % ALPHABET as u8
                })
            })
        })
    };
    (build(|r| &r.forward), build(|r| &r.backward))
});

static REFLECTED: std::sync::LazyLock<[[u8; ALPHABET]; REFLECTOR_COUNT]> =
    std::sync::LazyLock::new(|| std::array::from_fn(|i| wiring(REFLECTORS[i])));

#[must_use]
pub fn key_bits(naval: bool, leads: usize) -> f64 {
    let slots = if naval { SLOTS + 1 } else { SLOTS };
    let orders: f64 = (0..SLOTS).map(|i| (ROTOR_COUNT - i) as f64).product();
    let reflectors = if naval {
        NAVAL_REFLECTOR_COUNT as f64 / ALPHABET as f64
    } else {
        REFLECTOR_COUNT as f64
    };
    let wheels = (ALPHABET as f64).powi(slots as i32);
    let rings = (ALPHABET as f64).powi(SLOTS as i32 - 1);
    (orders * reflectors * wheels * rings).log2() + plugboard_bits(leads)
}

#[must_use]
pub fn notches_repeat_by_half_turn(rotor: usize) -> bool {
    let notched = |at: u8| ROTORS[rotor].1.bytes().any(|c| c - b'A' == at);
    (0..ALPHABET as u8).all(|at| notched(at) == notched((at + 13) % ALPHABET as u8))
}

#[must_use]
pub fn rings_repeat(
    rotors: [usize; 3],
    middle: u8,
    right: u8,
    (middle_ring, right_ring): (u8, u8),
    length: usize,
) -> bool {
    (right_ring >= 13 && notches_repeat_by_half_turn(rotors[2]))
        || (middle_ring >= 13 && notches_repeat_by_half_turn(rotors[1]))
        || right_ring_repeats(rotors[2], right, right_ring, length)
        || middle_ring_repeats(rotors, middle, right, middle_ring, length)
}

#[must_use]
pub fn right_turns_within(rotor: usize, indicator: u8, length: usize) -> bool {
    let notched = |at: u8| ROTORS[rotor].1.bytes().any(|c| c - b'A' == at);
    (0..length.min(ALPHABET)).any(|i| notched((indicator as usize + i) as u8 % ALPHABET as u8))
}

#[must_use]
pub fn right_ring_repeats(rotor: usize, indicator: u8, ring: u8, length: usize) -> bool {
    if right_turns_within(rotor, indicator, length) {
        return false;
    }
    let side = ALPHABET as u8;
    let wiring = (indicator + side - ring % side) % side;
    let first = (0..side)
        .find(|&r| !right_turns_within(rotor, (wiring + r) % side, length))
        .unwrap_or(ring);
    ring != first
}

#[must_use]
pub fn middle_ring_repeats(
    rotors: [usize; 3],
    middle: u8,
    right: u8,
    ring: u8,
    length: usize,
) -> bool {
    if ring == 0 {
        return false;
    }
    let notched = |rotor: usize, at: u8| ROTORS[rotor].1.bytes().any(|c| c - b'A' == at);
    let mut q1 = middle;
    let mut q2 = right;
    for _ in 0..length {
        let copy = (q1 + ALPHABET as u8 - ring) % ALPHABET as u8;
        if notched(rotors[1], q1) || notched(rotors[1], copy) {
            return false;
        }
        if notched(rotors[2], q2) {
            q1 = (q1 + 1) % ALPHABET as u8;
        }
        q2 = (q2 + 1) % ALPHABET as u8;
    }
    true
}

#[must_use]
pub fn plugboard_bits(leads: usize) -> f64 {
    if leads == 0 || leads * 2 > ALPHABET {
        return 0.0;
    }
    let mut bits = 0.0;
    for i in 0..leads * 2 {
        bits += ((ALPHABET - i) as f64).log2();
    }
    for i in 1..=leads {
        bits -= (i as f64).log2();
    }
    bits - leads as f64
}

impl Rotor {
    #[must_use]
    pub fn new(index: usize) -> Rotor {
        WIRED[index % WIRED.len()]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plugboard([u8; ALPHABET]);

impl Default for Plugboard {
    fn default() -> Self {
        Plugboard(std::array::from_fn(|i| i as u8))
    }
}

impl Plugboard {
    #[must_use]
    pub fn empty() -> Self {
        Plugboard::default()
    }

    #[must_use]
    pub fn from_mapping(mapping: [u8; ALPHABET]) -> Self {
        Plugboard(mapping)
    }

    pub fn connect(&mut self, a: Letter, b: Letter) {
        let (a, b) = (a as usize % ALPHABET, b as usize % ALPHABET);
        let (oa, ob) = (self.0[a] as usize, self.0[b] as usize);
        self.0[oa] = oa as u8;
        self.0[ob] = ob as u8;
        self.0[a] = b as u8;
        self.0[b] = a as u8;
    }

    pub fn disconnect(&mut self, a: Letter) {
        let a = a as usize % ALPHABET;
        let partner = self.0[a] as usize;
        self.0[partner] = partner as u8;
        self.0[a] = a as u8;
    }

    #[inline]
    #[must_use]
    pub fn map(&self, l: Letter) -> Letter {
        self.0[l as usize % ALPHABET]
    }

    #[must_use]
    pub fn pairs(&self) -> Vec<(Letter, Letter)> {
        (0..ALPHABET as u8)
            .filter(|&a| self.0[a as usize] > a)
            .map(|a| (a, self.0[a as usize]))
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub rotors: [usize; 3],
    pub reflector: usize,
    pub rings: [Ring; 3],
    pub positions: [Indicator; 3],
}

impl Settings {
    #[must_use]
    pub fn new(rotors: [usize; 3], reflector: usize) -> Settings {
        Settings {
            rotors,
            reflector,
            rings: [Ring::new(0); 3],
            positions: [Indicator::new(0); 3],
        }
    }

    #[must_use]
    pub fn at(
        rotors: [usize; 3],
        reflector: usize,
        rings: [u8; 3],
        positions: [u8; 3],
    ) -> Settings {
        Settings {
            rotors,
            reflector,
            rings: rings.map(Ring::new),
            positions: positions.map(Indicator::new),
        }
    }

    #[must_use]
    pub fn ring_letters(&self) -> [Letter; 3] {
        self.rings.map(Ring::value)
    }

    #[must_use]
    pub fn position_letters(&self) -> [Letter; 3] {
        self.positions.map(Indicator::value)
    }
}

#[derive(Clone, Debug)]
pub struct Enigma {
    rotor_ids: [usize; SLOTS],
    rotors: [Rotor; 3],
    reflector: [u8; ALPHABET],
    rings: [Ring; 3],
    positions: [Indicator; 3],
    plugboard: Plugboard,
}

impl Enigma {
    #[must_use]
    pub fn new(settings: Settings, plugboard: Plugboard) -> Enigma {
        Enigma {
            rotor_ids: settings.rotors,
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

    fn step(&mut self) {
        let middle_at_notch = self.rotors[1].notches[self.positions[1].index()];
        let right_at_notch = self.rotors[2].notches[self.positions[2].index()];
        if middle_at_notch {
            self.positions[1] = self.positions[1].step();
            self.positions[0] = self.positions[0].step();
        } else if right_at_notch {
            self.positions[1] = self.positions[1].step();
        }
        self.positions[2] = self.positions[2].step();
    }

    #[inline]
    fn offsets(&self) -> [Offset; 3] {
        [
            self.positions[0].against(self.rings[0]),
            self.positions[1].against(self.rings[1]),
            self.positions[2].against(self.rings[2]),
        ]
    }

    #[must_use]
    pub fn press(&mut self, l: Letter) -> Letter {
        self.step();
        let offsets = self.offsets();
        let mut c = self.plugboard.map(l);
        for (offset, rotor) in offsets.iter().zip(&self.rotors).rev() {
            c = offset.through(&rotor.forward, c);
        }
        c = self.reflector[c as usize];
        for (offset, rotor) in offsets.iter().zip(&self.rotors) {
            c = offset.through(&rotor.backward, c);
        }
        self.plugboard.map(c)
    }

    #[must_use]
    pub fn offset_trace(&mut self, n: usize) -> Vec<[Offset; 3]> {
        let mut out = Vec::with_capacity(n);
        self.trace_into(n, &mut out);
        out
    }

    pub fn trace_into(&mut self, n: usize, out: &mut Vec<[Offset; 3]>) {
        out.clear();
        for _ in 0..n {
            self.step();
            out.push(self.offsets());
        }
    }

    #[inline]
    #[must_use]
    pub fn transform_at(&self, offsets: [Offset; 3], l: Letter) -> Letter {
        let (forward, backward) = &*SHIFTED;
        let ids = self.rotor_ids;
        let mut c = l;
        for i in (0..SLOTS).rev() {
            c = forward[ids[i]][offsets[i].index()][c as usize];
        }
        c = self.reflector[c as usize];
        for i in 0..SLOTS {
            c = backward[ids[i]][offsets[i].index()][c as usize];
        }
        c
    }

    #[must_use]
    pub fn run(&mut self, text: &[Letter]) -> Vec<Letter> {
        text.iter().map(|&l| self.press(l)).collect()
    }

    pub fn run_into(&mut self, text: &[Letter], out: &mut [Letter]) {
        for (&l, slot) in text.iter().zip(out.iter_mut()) {
            *slot = self.press(l);
        }
    }

    pub fn aim(&mut self, settings: Settings, reflector: [u8; ALPHABET]) {
        self.rotor_ids = settings.rotors;
        for (slot, &r) in self.rotors.iter_mut().zip(settings.rotors.iter()) {
            *slot = WIRED[r % WIRED.len()];
        }
        self.reflector = reflector;
        self.rings = settings.rings;
        self.positions = settings.positions;
    }

    #[inline]
    pub fn restart(&mut self, positions: [Indicator; 3]) {
        self.positions = positions;
    }

    #[must_use]
    pub fn rotor_indices(&self) -> [usize; SLOTS] {
        self.rotor_ids
    }

    #[must_use]
    pub fn reflector(&self) -> [u8; ALPHABET] {
        self.reflector
    }

    #[must_use]
    pub fn plugboard(&self) -> Plugboard {
        self.plugboard
    }

    #[inline]
    pub fn replug(&mut self, plugboard: Plugboard) {
        self.plugboard = plugboard;
    }
}

#[must_use]
pub fn rotor_tables() -> (Vec<u8>, Vec<u8>, Vec<u32>) {
    let mut forward = Vec::with_capacity(ROTOR_COUNT * ALPHABET);
    let mut backward = Vec::with_capacity(ROTOR_COUNT * ALPHABET);
    let mut notches = Vec::with_capacity(ROTOR_COUNT);
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

#[must_use]
pub fn reflector_wiring(index: usize) -> [u8; ALPHABET] {
    REFLECTED[index % REFLECTED.len()]
}

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

#[must_use]
pub fn compatible(ct: &[Letter], pt: &[Letter]) -> bool {
    ct.iter().zip(pt).all(|(a, b)| a != b)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_plugboard_is_the_largest_part_of_the_key() {
        let ten = super::plugboard_bits(10);
        assert!(
            (ten - 47.10).abs() < 0.01,
            "ten leads should be 47.1 bits, got {ten}"
        );
        assert_eq!(super::plugboard_bits(0), 0.0, "no cables, no choice");
        assert_eq!(
            super::plugboard_bits(crate::alphabet::ALPHABET),
            0.0,
            "more cables than letters is not a board"
        );
        let peak = (1..=13)
            .max_by(|&a, &b| super::plugboard_bits(a).total_cmp(&super::plugboard_bits(b)))
            .expect("a peak");
        assert_eq!(
            peak, 11,
            "the board is most uncertain at eleven leads, not thirteen"
        );
    }

    #[test]
    fn a_naval_machine_offers_more_key_than_a_three_rotor_one() {
        let naval = super::key_bits(true, 10);
        let army = super::key_bits(false, 10);
        assert!(naval > army, "the fourth wheel adds key: {naval} vs {army}");
        assert!(
            (naval - 85.7).abs() < 0.5,
            "a naval M4 with ten leads is about 85.7 bits, got {naval}"
        );
    }

    use super::*;
    use crate::alphabet::{from_letters, to_letters};

    #[test]
    fn it_matches_the_textbook_vector() {
        let mut m = Enigma::new(Settings::new([0, 1, 2], 0), Plugboard::empty());
        assert_eq!(from_letters(&m.run(&to_letters("AAAAA"))), "BDZGO");
    }

    #[test]
    fn it_is_its_own_inverse() {
        let settings = Settings::at([2, 0, 3], 1, [4, 17, 9], [11, 2, 25]);
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
        let settings = Settings::at([0, 1, 2], 0, [0; 3], [0; 3]);
        let plain: Vec<u8> = (0..200).map(|i| (i % 26) as u8).collect();
        let ct = Enigma::new(settings, Plugboard::empty()).run(&plain);
        assert!(compatible(&ct, &plain));
    }

    #[test]
    fn the_middle_rotor_double_steps() {
        let settings = Settings::at([0, 1, 2], 0, [0; 3], [0, 4, 0]);
        let mut m = Enigma::new(settings, Plugboard::empty());
        let _ = m.press(0);
        assert_eq!(
            m.positions[0],
            Indicator::new(1),
            "the left rotor should have moved"
        );
        assert_eq!(
            m.positions[1],
            Indicator::new(5),
            "the middle rotor should have moved with it"
        );

        let quiet = Settings::at([0, 1, 2], 0, [0; 3], [0, 0, 0]);
        let mut still = Enigma::new(quiet, Plugboard::empty());
        let _ = still.press(0);
        assert_eq!(still.positions[0], Indicator::new(0));
        assert_eq!(still.positions[1], Indicator::new(0));
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
        assert_eq!(rotor_orders(5).len(), 5 * 4 * 3);
        assert_eq!(rotor_orders(ROTOR_COUNT).len(), 8 * 7 * 6);
    }

    #[test]
    fn the_counts_follow_the_tables() {
        assert_eq!(ROTOR_COUNT, 8);
        assert_eq!(REFLECTOR_COUNT, 2);
        assert_eq!(NAVAL_REFLECTOR_COUNT, naval_reflectors().len());
    }
}

pub const GREEK: [&str; 2] = ["LEYJVCNIXWPBQMDRTAKZGFUHOS", "FSOKANUERHMBTIYCWLQPZXVGJD"];

pub const THIN: [&str; 2] = ["ENKQAUYWJICOPBLMDXZVFTHRGS", "RDOBJNTKVEHMLFCWZAXGYIPSUQ"];

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
    #[must_use]
    pub fn with_reflector(
        settings: Settings,
        reflector: [u8; ALPHABET],
        plugboard: Plugboard,
    ) -> Enigma {
        Enigma {
            rotor_ids: settings.rotors,
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
        assert_eq!(naval_reflectors().len(), NAVAL_REFLECTOR_COUNT);
    }

    #[test]
    fn the_naval_machine_is_its_own_inverse() {
        let settings = Settings::at([0, 3, 6], 0, [2, 5, 11], [7, 19, 3]);
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
