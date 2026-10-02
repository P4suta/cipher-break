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
use crate::enigma_types::{Indicator, Offset, Ring};

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

/// How many historical rotors there are.
pub const ROTOR_COUNT: usize = ROTORS.len();

/// How many rotors a machine holds, Greek rotor aside.
pub const SLOTS: usize = 3;

/// How many reflectors a three-rotor machine can be fitted with.
pub const REFLECTOR_COUNT: usize = REFLECTORS.len();

/// How many reflectors a four-rotor machine presents once its Greek rotor and thin reflector are folded together: each Greek rotor, at each setting,
/// behind each thin reflector.
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

/// Every rotor's wiring, already shifted to every offset.
///
/// Entering a wiring at an offset is two modulo operations and a lookup, and a bombe does it six times for every letter it deduces — which measured as almost the whole cost of a crib sweep.
/// The shift depends only on the rotor and the offset, neither of which changes inside the sweep, so all 26 shifts of all eight rotors in both directions are built once: eleven kilobytes that turn six arithmetic sequences into six array reads.
///
/// Indexed `[rotor][offset][letter]`, forwards then backwards.
/// Every rotor, pre-shifted to every offset, in both directions.
///
/// A rotor at offset `o` is the rotor at rest conjugated by a rotation, so the whole family can be worked out once and read thereafter.
/// Nested [`ByLetter`] tables so that the address of an entry is shifts and an or, with no multiply by twenty-six and no bounds check at any level: this table is read seven times per letter and nothing else in the program is read as often.
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

/// The reflectors, wired once.
static REFLECTED: std::sync::LazyLock<[[u8; ALPHABET]; REFLECTOR_COUNT]> =
    std::sync::LazyLock::new(|| std::array::from_fn(|i| wiring(REFLECTORS[i])));

/// How many keys a wartime operator could have chosen from, in bits.
///
/// Not what any attack here searches — the attacks fix the rings, or the plugboard, or the reflector, and say so in their coverage — but what the machine itself offered.
/// It is the number that decides whether a message is long enough for its answer to be unique, and a search that cannot say it is a search whose terms nobody checked.
///
/// Rotor order, ring settings, starting positions, reflector, and a plugboard of `leads` cables, which is the largest part of it by far.
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
    // Rings on the two rotors that can never step past their own notch are the only ones that change anything.
    let rings = (ALPHABET as f64).powi(SLOTS as i32 - 1);
    (orders * reflectors * wheels * rings).log2() + plugboard_bits(leads)
}

/// Whether a rotor's notches come round every half turn, as the naval rotors' two do.
///
/// VI, VII and VIII turn their neighbour at M and at Z, thirteen letters apart.
/// Moving such a rotor's ring and its indicator on by thirteen together leaves its wiring where it was and its notches where they were, so the machine is the same machine from the first letter to the last, and half of that rotor's ring settings are the other half again.
#[must_use]
pub fn notches_repeat_by_half_turn(rotor: usize) -> bool {
    let notched = |at: u8| ROTORS[rotor].1.bytes().any(|c| c - b'A' == at);
    (0..ALPHABET as u8).all(|at| notched(at) == notched((at + 13) % ALPHABET as u8))
}

/// Whether a pair of ring settings only repeats a pair a sweep already covers.
///
/// Four ways, each exact over the `length` letters it is asked about:
/// a naval rotor's ring past the half turn, on the right or in the middle, repeats the ring thirteen before it;
/// a middle ring whose notch those letters never reach repeats the middle ring at A (see [`middle_ring_repeats`]);
/// and a right ring whose rotor turns nothing within them repeats every other such ring on the same wiring (see [`right_ring_repeats`]).
/// The last two are copies only over those letters, so a sweep that skips them has to try them again where it reads the whole message.
/// The device kernels apply the same rules, and a sweep on either side has to skip exactly the same settings for their counts to agree.
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

/// Whether the right rotor, starting at `indicator`, turns the middle one within `length` letters.
#[must_use]
pub fn right_turns_within(rotor: usize, indicator: u8, length: usize) -> bool {
    let notched = |at: u8| ROTORS[rotor].1.bytes().any(|c| c - b'A' == at);
    (0..length.min(ALPHABET)).any(|i| notched((indicator as usize + i) as u8 % ALPHABET as u8))
}

/// Whether a right ring only repeats another one over the first `length` letters.
///
/// The right ring decides one thing, when the middle rotor steps, and a right rotor that reaches no notch within the letters asked about steps nothing there.
/// Every ring that leaves it so, on the same wiring, is the same machine over those letters; the smallest of them stands for the rest.
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

/// Whether a middle-ring setting only repeats a setting with that ring at A.
///
/// The middle rotor's wiring is entered at its indicator less its ring, and its notch fires at the indicator whatever the ring.
/// So moving the ring and the indicator together leaves the wiring where it was and moves only the notch, which changes nothing unless the middle rotor reaches that notch — in this setting or in the copy with the ring at A — within `length` letters.
/// When neither does, the two decipher identically, and a sweep that covers the copy need not try this one.
/// The device kernels apply the same rule, and a sweep on either side has to skip exactly the same settings for their counts to agree.
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

/// How many ways `leads` cables can be laid across the board, in bits.
#[must_use]
pub fn plugboard_bits(leads: usize) -> f64 {
    if leads == 0 || leads * 2 > ALPHABET {
        return 0.0;
    }
    // 26!
    // / ((26 - 2n)!
    // * n! * 2^n): choose the letters, pair them, and forget the order of the cables.
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
    /// The nth historical rotor, counting from zero.
    #[must_use]
    pub fn new(index: usize) -> Rotor {
        WIRED[index % WIRED.len()]
    }
}

/// A plugboard: an involution on the alphabet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

    /// A board from a mapping a device computed.
    #[must_use]
    pub fn from_mapping(mapping: [u8; ALPHABET]) -> Self {
        Plugboard(mapping)
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
    pub rings: [Ring; 3],
    /// Where each rotor starts, left to right.
    pub positions: [Indicator; 3],
}

impl Settings {
    /// Settings with everything at its first value.
    #[must_use]
    pub fn new(rotors: [usize; 3], reflector: usize) -> Settings {
        Settings {
            rotors,
            reflector,
            rings: [Ring::new(0); 3],
            positions: [Indicator::new(0); 3],
        }
    }

    /// Settings written the way a key sheet writes them, as letters.
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

    /// The ring settings as plain letters, for printing.
    #[must_use]
    pub fn ring_letters(&self) -> [Letter; 3] {
        self.rings.map(Ring::value)
    }

    /// The starting positions as plain letters, for printing.
    #[must_use]
    pub fn position_letters(&self) -> [Letter; 3] {
        self.positions.map(Indicator::value)
    }
}

/// A machine, set up and ready to run.
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
    /// Assemble a machine.
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

    /// Advance the rotors, including the double step the middle one makes when it is sitting on its own notch.
    fn step(&mut self) {
        // A notch fires on the indicator, never on the ring or the offset.
        // The type of the argument is the whole guard.
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

    /// Where each rotor's wiring is entered, right now.
    #[inline]
    fn offsets(&self) -> [Offset; 3] {
        [
            self.positions[0].against(self.rings[0]),
            self.positions[1].against(self.rings[1]),
            self.positions[2].against(self.rings[2]),
        ]
    }

    /// Encipher one letter, advancing the machine first as a keypress does.
    ///
    /// Enigma is its own inverse, so this deciphers too.
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

    /// The wiring offsets the machine is at, position by position.
    ///
    /// A bombe needs to ask what one position does to one letter, tens of times per rotor setting and for letters it does not know in advance.
    /// Building the whole 26-letter permutation at every position to answer that would cost more than deciphering the message; recording where the rotors stand and evaluating on demand costs seven lookups an answer.
    #[must_use]
    pub fn offset_trace(&mut self, n: usize) -> Vec<[Offset; 3]> {
        let mut out = Vec::with_capacity(n);
        self.trace_into(n, &mut out);
        out
    }

    /// The same, written into a buffer the caller keeps.
    ///
    /// A crib sweep asks for this once per rotor setting and there are billions of settings, so the allocation is the cost rather than the trace.
    pub fn trace_into(&mut self, n: usize, out: &mut Vec<[Offset; 3]>) {
        out.clear();
        for _ in 0..n {
            self.step();
            out.push(self.offsets());
        }
    }

    /// What the rotors and reflector do to one letter at given offsets.
    ///
    /// The plugboard is not applied: a bombe reasons about the machine with the board taken off, which is the whole reason it can reason about a board it does not know.
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
        self.rotor_ids = settings.rotors;
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
    pub fn restart(&mut self, positions: [Indicator; 3]) {
        self.positions = positions;
    }

    /// Which of the historical rotors sits in each slot.
    ///
    /// Recorded so the shifted tables can be indexed without carrying the wirings around.
    #[must_use]
    pub fn rotor_indices(&self) -> [usize; SLOTS] {
        self.rotor_ids
    }

    /// The reflector in use.
    #[must_use]
    pub fn reflector(&self) -> [u8; ALPHABET] {
        self.reflector
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
    #[test]
    fn the_plugboard_is_the_largest_part_of_the_key() {
        // 26!
        // / (6! * 10!
        // * 2^10) ways to lay ten cables, which is where a bombe's whole difficulty lives.
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
        // More cables is more choice only up to eleven, and then less: pairing up twenty-four of twenty-six letters can be done fewer ways than pairing twenty-two, because the cables stop being distinguishable from each other faster than the letters run out.
        // The wartime standard of ten sits just below the peak.
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
        // Enough that seventy-odd letters of German is about what it takes to pin one down.
        // Eight rotors taken three at a time, a Greek wheel and a thin reflector, four starting positions, the two ring settings that can change anything, and ten cables.
        assert!(
            (naval - 85.7).abs() < 0.5,
            "a naval M4 with ten leads is about 85.7 bits, got {naval}"
        );
    }

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
        // The famous anomaly: a rotor sitting on its own notch takes the one to its left with it, and moves again itself.
        // Rotor II notches at E,
        // so a middle rotor resting there carries the left rotor on the very next keypress.
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

        // And without the middle rotor on its notch, the left one stays put.
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
