// SPDX-License-Identifier: MIT OR Apache-2.0

//! Turing's bombe: the attack that does not care how many plugs there are.
//!
//! Every other Enigma attack here weighs evidence, and on a short message with a full plugboard there is not enough of it.
//! A decipherment with the rotors right and the board empty has twenty of its twenty-six letters wrong, which no n-gram model can recognise.
//!
//! The bombe does not look at the plaintext at all.
//! Given a crib — a guess at what some stretch of the message says — it asks a different question: is there *any* plugboard under which this rotor setting turns the ciphertext into the crib?
//! Assume one lead, follow where the crib forces the rest, and see whether the forcing contradicts itself.
//! A contradiction refutes the setting outright, whatever the board, and a setting that survives hands back most of the board as a by-product.
//!
//! Two properties make it work.
//! The reflector makes every position's transformation an involution with no fixed point, so a deduction can be followed in either direction.
//! And the plugboard is an involution too, which is what Turing's diagonal board exploits: knowing that `A` is plugged to `Q` is knowing that `Q` is plugged to `A`, and half the contradictions come from that alone.

use crate::alphabet::{ALPHABET, Letter};
use crate::ciphers::enigma::{Enigma, Plugboard, Settings};

/// A crib placed against a ciphertext, as the graph the bombe walks.
///
/// Each edge is one position of the message: the letter the crib says was typed, the letter that came out, and where in the message it happened.
#[derive(Clone, Debug)]
pub struct Menu {
    /// Where the crib starts in the ciphertext.
    pub offset: usize,
    /// One per crib position: the message index, the crib letter, the cipher letter.
    pub edges: Vec<(usize, Letter, Letter)>,
    /// The letter to start every hypothesis from.
    ///
    /// The one on the most edges.
    /// A deduction about it immediately forces everything around it, so a wrong setting contradicts in fewer steps than it would from a letter on the edge of the graph.
    hub: Letter,
    /// For each letter, the edges that touch it, as (position, other letter), laid end to end.
    ///
    /// A deduction about one letter only travels along the edges that letter is on.
    /// Walking the whole menu for each of them costs the length of the crib per deduction where this costs the two or three edges that actually meet there, and a naval sweep makes that difference tens of billions of times.
    ///
    /// One run of memory rather than twenty-six: a sweep holds every menu at once and reads them in turn, and twenty-six separately allocated lists per menu scatter across the cache the one structure the inner loop never stops touching.
    incident: Vec<(u32, Letter)>,
    /// Where each letter's edges begin in `incident`, with a final entry for the end.
    starts: [u32; ALPHABET + 1],
}

/// Where a true rotor setting sits when the whole naval space is scored at the length this tool was built for.
///
/// Measured rather than assumed: `where_the_true_setting_ranks` plants a known setting in a message of about seventy letters and finds it a hundred and forty-sixth of six hundred million.
/// A short message simply does not carry enough German for the score to put the truth first, and that is the whole reason a bombe earns its place — it throws away the accidents before the score has to choose between them.
pub const RANK_OF_TRUTH_WHEN_SHORT: u64 = 146;

impl Menu {
    /// Place a crib and build its menu.
    ///
    /// Returns `None` when the placement is impossible — a letter over itself,
    /// which no Enigma can produce.
    #[must_use]
    pub fn place(ct: &[Letter], crib: &[Letter], offset: usize) -> Option<Menu> {
        if crib.is_empty() || offset + crib.len() > ct.len() {
            return None;
        }
        let edges: Vec<(usize, Letter, Letter)> = crib
            .iter()
            .enumerate()
            .map(|(i, &p)| (offset + i, p, ct[offset + i]))
            .collect();
        if edges.iter().any(|&(_, p, c)| p == c) {
            return None;
        }
        // Counted first so the run can be filled in one pass with no growing and no gaps.
        let mut degree = [0u32; ALPHABET];
        for &(_, p, c) in &edges {
            degree[p as usize] += 1;
            degree[c as usize] += 1;
        }
        let mut starts = [0u32; ALPHABET + 1];
        for l in 0..ALPHABET {
            starts[l + 1] = starts[l] + degree[l];
        }
        let mut at = starts;
        let mut incident = vec![(0u32, 0u8); edges.len() * 2];
        for &(i, p, c) in &edges {
            for (from, to) in [(p, c), (c, p)] {
                incident[at[from as usize] as usize] = (i as u32, to);
                at[from as usize] += 1;
            }
        }
        let hub = (0..ALPHABET as u8)
            .max_by_key(|&l| degree[l as usize])
            .unwrap_or(0);
        Some(Menu {
            offset,
            edges,
            hub,
            incident,
            starts,
        })
    }

    /// The most settings that could survive this menu for no reason at all, out of `settings` swept.
    ///
    /// Each closure forces a letter that is already forced, and two forcings agree by chance one time in twenty-six, so the loops alone let through at most one setting in `26^(c-1)`.
    ///
    /// A loose bound and not a prediction: it counts only the loops, and Turing's diagonal board forces the other end of every lead it sets, which contradicts far more often than the loops can account for.
    /// Measured on this tool's own sweeps, the bound overshoots by twenty times to a hundred thousand, and a menu with a single closure — which the bound says refutes nothing whatever — refuted every one of the seventeen thousand settings it was shown.
    /// So a stop against a small bound is worth a great deal, and a large bound is worth nothing at all: it says only that the loops did not settle the matter, not that the sweep will not.
    #[must_use]
    pub fn chance_stops(&self, settings: u64) -> f64 {
        let exponent = self.closures().saturating_sub(1) as i32;
        settings as f64 / (ALPHABET as f64).powi(exponent)
    }

    /// Whether a stop from this menu would mean something on its own.
    ///
    /// True when the sweep is expected to leave nothing standing by chance, so that anything still standing is standing for a reason and needs no score to vouch for it.
    #[must_use]
    pub fn decisive_over(&self, settings: u64) -> bool {
        self.chance_stops(settings) < 1.0
    }

    /// Where a true setting would sit among this menu's survivors, once they are scored.
    ///
    /// The bombe leaves `chance_stops` settings standing for no reason, and a known fraction of the whole space outscores a true setting at this length, so the accidents that both survive and outscore it are what stand between the truth and the top of the report.
    #[must_use]
    pub fn expected_rank_of_truth(&self, settings: u64, rank_over_all: u64) -> f64 {
        1.0 + rank_over_all as f64 * self.chance_stops(settings) / settings as f64
    }

    /// How many times the menu forces a letter that something else has already forced.
    ///
    /// The cycle rank of the graph the crib and its ciphertext make together, and the only thing that gives a bombe anything to contradict: every closure is a place where two chains of deduction must agree, and disagreeing is how a setting is refuted.
    #[must_use]
    pub fn closures(&self) -> usize {
        let mut parent: [usize; ALPHABET] = std::array::from_fn(|i| i);
        let mut loops = 0;
        for &(_, p, c) in &self.edges {
            let (a, b) = (find(&mut parent, p as usize), find(&mut parent, c as usize));
            if a == b {
                loops += 1;
            } else {
                parent[a] = b;
            }
        }
        loops
    }

    /// The letter every hypothesis starts from: the one on the most edges.
    #[must_use]
    pub fn hub(&self) -> Letter {
        self.hub
    }

    /// The letters the menu touches.
    #[must_use]
    pub fn letters(&self) -> Vec<Letter> {
        let mut seen = [false; ALPHABET];
        for &(_, p, c) in &self.edges {
            seen[p as usize] = true;
            seen[c as usize] = true;
        }
        (0..ALPHABET as u8).filter(|&l| seen[l as usize]).collect()
    }
}

/// The representative of a letter's group, with the path flattened as it goes.
fn find(parent: &mut [usize; ALPHABET], mut x: usize) -> usize {
    while parent[x] != x {
        parent[x] = parent[parent[x]];
        x = parent[x];
    }
    x
}

/// What a scan of one rotor setting concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stop {
    /// Every hypothesis contradicted itself; the setting is refuted.
    Refuted,
    /// A hypothesis survived, with the plugboard it forces.
    ///
    /// The board is partial: it holds the leads the crib reached, and says nothing about letters the crib never used.
    Survived {
        /// The lead that was assumed.
        assumed: (Letter, Letter),
        /// What the crib then forced.
        board: Plugboard,
    },
}

/// The transformation one position of the message applies, with no plugboard.
///
/// Recorded ahead of the scan because a setting's rotors step the same way whatever is assumed about the board, so this is computed once and consulted 26 times.
#[derive(Clone, Debug)]
pub struct Positions {
    machine: Enigma,
    offsets: Vec<[crate::enigma_types::Offset; 3]>,
}

impl Positions {
    /// Record where the rotors stand at each of the first `length` positions.
    #[must_use]
    pub fn of(settings: Settings, reflector: [u8; ALPHABET], length: usize) -> Positions {
        let mut machine = Enigma::with_reflector(settings, reflector, Plugboard::empty());
        let offsets = machine.offset_trace(length);
        Positions { machine, offsets }
    }

    /// Point an existing record at a new setting, without rebuilding it.
    pub fn aim(&mut self, settings: Settings, reflector: [u8; ALPHABET], length: usize) {
        self.machine.aim(settings, reflector);
        self.retrace(settings, length);
    }

    /// Move only the starting positions, keeping the rotors and reflector.
    ///
    /// The inner loop of a crib sweep walks 17,576 starting positions with everything else held still, and re-copying three rotor wirings at each of them costs more than the trace it is preparing for.
    pub fn restart(&mut self, settings: Settings, length: usize) {
        self.machine.restart(settings.positions);
        self.retrace(settings, length);
    }

    fn retrace(&mut self, settings: Settings, length: usize) {
        self.machine.trace_into(length, &mut self.offsets);
        self.machine.restart(settings.positions);
    }

    /// What position `i` does to a letter.
    ///
    /// Answered on demand rather than tabulated. Building all twenty-six
    /// answers per position was measured and is a loss below about twenty
    /// menus: the table costs more to fill than the questions cost to ask.
    #[inline]
    #[must_use]
    pub fn at(&self, i: usize, l: Letter) -> Letter {
        self.machine.transform_at(self.offsets[i], l)
    }
}

/// Room for one scan, kept between scans.
///
/// A hypothesis needs to know, for each letter, whether anything has forced it yet and to what.
/// Clearing that between hypotheses is 52 bytes a time, which is twenty-two menus times twenty-six hypotheses times six hundred million settings of pure zeroing — eighteen terabytes of it on one naval crib.
///
/// A generation counter removes the clearing entirely: a slot counts as known only if it was stamped this time round, so the previous round's contents need not be touched.
pub struct Scratch {
    generation: u32,
    stamp: [u32; ALPHABET],
    value: [Letter; ALPHABET],
    pending: [Letter; ALPHABET],
}

impl Default for Scratch {
    fn default() -> Self {
        Scratch::new()
    }
}

impl Scratch {
    /// Somewhere to work.
    #[must_use]
    pub fn new() -> Scratch {
        Scratch {
            generation: 0,
            stamp: [0; ALPHABET],
            value: [0; ALPHABET],
            pending: [0; ALPHABET],
        }
    }

    #[inline]
    fn begin(&mut self) {
        // On the one wrap in four billion, clear rather than let a stale stamp read as fresh.
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.stamp = [0; ALPHABET];
            self.generation = 1;
        }
    }

    #[inline]
    fn known(&self, l: Letter) -> Option<Letter> {
        // The modulo is free — the compiler folds it away on a letter — and earns its place by being what tells the compiler the index is in bounds, so the check goes too.
        let i = l as usize % ALPHABET;
        if self.stamp[i] == self.generation {
            Some(self.value[i])
        } else {
            None
        }
    }

    #[inline]
    fn set(&mut self, l: Letter, v: Letter) {
        let i = l as usize % ALPHABET;
        self.stamp[i] = self.generation;
        self.value[i] = v;
    }
}

/// Scan one rotor setting against a menu.
///
/// Assumes each possible lead for the menu's first letter in turn, follows the
/// crib wherever it leads, and reports the first assumption that does not
/// contradict itself.
#[must_use]
pub fn scan(menu: &Menu, positions: &Positions) -> Stop {
    scan_with(menu, positions, &mut Scratch::new())
}

/// The same, reusing a caller's workspace.
#[must_use]
pub fn scan_with(menu: &Menu, positions: &Positions, scratch: &mut Scratch) -> Stop {
    if menu.edges.is_empty() {
        return Stop::Refuted;
    }
    let start = menu.hub;
    for guess in 0..ALPHABET as u8 {
        if follow(menu, positions, start, guess, scratch) {
            let mut board = Plugboard::empty();
            for l in 0..ALPHABET as u8 {
                if let Some(p) = scratch.known(l) {
                    board.connect(l, p);
                }
            }
            return Stop::Survived {
                assumed: (start, guess),
                board,
            };
        }
    }
    Stop::Refuted
}

/// Follow one assumption through the menu.
///
/// Answers whether the forcing held together; the workspace holds what it
/// forced.
///
/// Deductions are driven from a worklist rather than by sweeping every edge
/// until nothing changes, and each one travels only the edges its letter is
/// actually on.
fn follow(
    menu: &Menu,
    positions: &Positions,
    start: Letter,
    guess: Letter,
    scratch: &mut Scratch,
) -> bool {
    scratch.begin();
    let mut waiting = 0usize;

    // A lead is an involution, so setting one end sets the other, and either end may be the one that disagrees.
    // That is Turing's diagonal board, and half the contradictions come from it alone.
    macro_rules! settle {
        ($a:expr, $b:expr) => {{
            let mut ok = true;
            for (x, y) in [($a, $b), ($b, $a)] {
                match scratch.known(x) {
                    Some(v) if v != y => {
                        ok = false;
                        break;
                    }
                    Some(_) => {}
                    None => {
                        scratch.set(x, y);
                        scratch.pending[waiting] = x;
                        waiting += 1;
                    }
                }
            }
            ok
        }};
    }

    if !settle!(start, guess) {
        return false;
    }

    while waiting > 0 {
        waiting -= 1;
        let from = scratch.pending[waiting];
        let Some(u) = scratch.known(from) else {
            continue;
        };
        // Each edge joins its two letters through the machine at that position, in either direction, because the machine there is an involution.
        let l = from as usize % ALPHABET;
        let (first, last) = (menu.starts[l] as usize, menu.starts[l + 1] as usize);
        for &(i, to) in &menu.incident[first..last] {
            let v = positions.at(i as usize, u);
            match scratch.known(to) {
                Some(w) if w != v => return false,
                Some(_) => {}
                None => {
                    if !settle!(to, v) {
                        return false;
                    }
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_menu_says_how_many_settings_it_lets_through_by_chance() {
        use crate::alphabet::to_letters;

        // Each closure divides the residue by twenty-six, and the first one buys nothing: it is what makes a stop possible at all.
        let ct =
            to_letters("JCRSAJTGSJEYEXYKKZZSHVUOCTRFRCRPFVYPLKPPLGRHVVBBTBRSXSWXGGTYTVKQNGSCHVGF");
        let crib = to_letters("KEINEBESONDERENVORKOMMNISSE");
        let menu = Menu::place(&ct, &crib, 0).expect("the crib fits at the front");
        let settings = 1_000_000u64;
        let expected = settings as f64 / 26f64.powi(menu.closures() as i32 - 1);
        assert!((menu.chance_stops(settings) - expected).abs() < 1e-6);

        // The bar is exactly where the residue falls below one whole setting.
        assert_eq!(
            menu.decisive_over(settings),
            menu.chance_stops(settings) < 1.0
        );
    }

    #[test]
    fn a_menu_with_one_closure_decides_nothing() {
        use crate::alphabet::to_letters;

        // One closure leaves the sweep exactly as it found it: every setting still standing.
        // This is the case the sweep used to run for an hour and report as though it had refuted something.
        let ct = to_letters("BCDEFG");
        let crib = to_letters("ABABAB");
        let Some(menu) = Menu::place(&ct, &crib, 0) else {
            return;
        };
        if menu.closures() == 1 {
            assert_eq!(menu.chance_stops(1_000_000), 1_000_000.0);
            assert!(!menu.decisive_over(1_000_000));
        }
    }

    use super::*;
    use crate::alphabet::to_letters;
    use crate::ciphers::enigma::{composite_reflector, reflector_wiring};
    use crate::enigma_types::{Indicator, Ring};

    const CRIB: &str = "VONVONJAWEGENDER";

    fn planted() -> (
        Settings,
        [u8; ALPHABET],
        Plugboard,
        Vec<Letter>,
        Vec<Letter>,
    ) {
        let settings = Settings {
            rotors: [3, 1, 6],
            reflector: 0,
            rings: [Ring::new(0); 3],
            positions: [11, 4, 22].map(Indicator::new),
        };
        let reflector = composite_reflector(0, 9, 0);
        let mut board = Plugboard::empty();
        for (a, b) in [(1u8, 20u8), (8, 15), (17, 2), (4, 19), (0, 25)] {
            board.connect(a, b);
        }
        let plain =
            to_letters("VONVONJAWEGENDERSITUATIONXXMELDEICHXXFEINDKONVOIINSICHTXXMARQUADRATBE");
        let ct = Enigma::with_reflector(settings, reflector, board).run(&plain);
        (settings, reflector, board, plain, ct)
    }

    #[test]
    fn a_placement_over_a_letters_own_image_is_refused() {
        let ct = to_letters("ABCDEF");
        assert!(Menu::place(&ct, &to_letters("A"), 0).is_none());
        assert!(Menu::place(&ct, &to_letters("B"), 0).is_some());
    }

    #[test]
    fn a_star_of_fresh_letters_has_no_loops() {
        // Every edge joins a letter seen for the first time to the same hub.
        // A star has no cycles, so nothing is ever forced twice and the menu refutes nothing — which is exactly what a bombe must not be handed.
        let ct = to_letters("ZZZZZZ");
        let menu = Menu::place(&ct, &to_letters("ABCDEF"), 0).expect("placed");
        assert_eq!(menu.closures(), 0);
    }

    #[test]
    fn a_repeated_pair_closes_a_loop() {
        // The same two letters meeting twice is one closure: the crib forces that pair around two different positions, and the two answers may disagree.
        let ct = to_letters("BABABA");
        let menu = Menu::place(&ct, &to_letters("ABABAB"), 0).expect("placed");
        assert_eq!(menu.closures(), 5);
    }

    #[test]
    fn a_menu_without_closures_refutes_nothing() {
        // Stated as a test because it is the trap: a crib of all-distinct letters will accept every rotor setting there is and look like a working attack while doing nothing.
        let (settings, reflector, _, _, ct) = planted();
        let star: Vec<Letter> = (0..6)
            .map(|i| {
                // Pick letters that differ from the ciphertext so the placement is legal.
                (0..ALPHABET as u8).find(|&l| l != ct[i]).expect("a letter")
            })
            .collect();
        if let Some(menu) = Menu::place(&ct, &star, 0)
            && menu.closures() == 0
        {
            let positions = Positions::of(settings, reflector, ct.len());
            assert!(matches!(scan(&menu, &positions), Stop::Survived { .. }));
        }
    }

    #[test]
    fn a_real_crib_closes_on_itself() {
        let (_, _, _, _, ct) = planted();
        let menu = Menu::place(&ct, &to_letters(CRIB), 0).expect("placed");
        assert!(
            menu.closures() > 0,
            "a menu with no closures refutes nothing"
        );
        assert!(menu.letters().len() <= ALPHABET);
    }

    #[test]
    fn the_true_setting_survives_its_own_crib() {
        let (settings, reflector, board, plain, ct) = planted();
        let menu = Menu::place(&ct, &to_letters(CRIB), 0).expect("placed");
        let positions = Positions::of(settings, reflector, ct.len());
        match scan(&menu, &positions) {
            Stop::Survived { board: found, .. } => {
                // Every lead the crib reached must be one that was really there.
                for (a, b) in found.pairs() {
                    assert_eq!(board.map(a), b, "invented a lead {a}-{b}");
                }
            }
            Stop::Refuted => panic!("the true setting was refuted by its own crib"),
        }
        let _ = plain;
    }

    #[test]
    fn a_wrong_setting_is_usually_refuted() {
        let (settings, reflector, _, _, ct) = planted();
        let menu = Menu::place(&ct, &to_letters(CRIB), 0).expect("placed");
        let mut refuted = 0;
        let mut tried = 0;
        for start in 0..ALPHABET as u8 {
            let wrong = Settings {
                positions: [
                    settings.positions[0],
                    settings.positions[1],
                    Indicator::new(start),
                ],
                ..settings
            };
            if wrong.positions == settings.positions {
                continue;
            }
            tried += 1;
            let positions = Positions::of(wrong, reflector, ct.len());
            if scan(&menu, &positions) == Stop::Refuted {
                refuted += 1;
            }
        }
        assert!(
            refuted * 2 > tried,
            "only {refuted} of {tried} wrong settings were refuted; the menu is too weak"
        );
    }

    #[test]
    fn positions_agree_with_the_machine() {
        let (settings, reflector, _, _, ct) = planted();
        let positions = Positions::of(settings, reflector, ct.len());
        let direct = Enigma::with_reflector(settings, reflector, Plugboard::empty()).run(&ct);
        for (i, &c) in ct.iter().enumerate() {
            assert_eq!(positions.at(i, c), direct[i], "position {i}");
        }
        let _ = reflector_wiring(0);
    }
}
