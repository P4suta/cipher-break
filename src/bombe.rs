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
}

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
        Some(Menu { offset, edges })
    }

    /// How many independent loops the menu contains.
    ///
    /// Loops are what make a menu bite.
    /// Each one is a path that returns to where it started, so the letters around it are forced twice and may disagree; a menu with none can never contradict anything and will accept every rotor setting there is.
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
        self.offsets.clear();
        self.offsets.extend(self.machine.offset_trace(length));
        self.machine.aim(settings, reflector);
    }

    /// What position `i` does to a letter.
    #[inline]
    #[must_use]
    pub fn at(&self, i: usize, l: Letter) -> Letter {
        self.machine.transform_at(self.offsets[i], l)
    }
}

/// Scan one rotor setting against a menu.
///
/// Assumes each possible lead for the menu's first letter in turn, follows the crib wherever it leads, and reports the first assumption that does not contradict itself.
#[must_use]
pub fn scan(menu: &Menu, positions: &Positions) -> Stop {
    let Some(&(_, start, _)) = menu.edges.first() else {
        return Stop::Refuted;
    };
    for guess in 0..ALPHABET as u8 {
        if let Some(board) = follow(menu, positions, start, guess) {
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
/// Returns the board it forces, or `None` if the forcing contradicts itself.
fn follow(menu: &Menu, positions: &Positions, start: Letter, guess: Letter) -> Option<Plugboard> {
    // `known[l]` is what `l` is plugged to, once something has forced it.
    let mut known: [Option<Letter>; ALPHABET] = [None; ALPHABET];
    let set = |known: &mut [Option<Letter>; ALPHABET], a: Letter, b: Letter| -> bool {
        // The diagonal board: a lead is an involution, so setting one end sets the other, and either end may be the one that disagrees.
        for (x, y) in [(a, b), (b, a)] {
            match known[x as usize % ALPHABET] {
                Some(v) if v != y => return false,
                _ => known[x as usize % ALPHABET] = Some(y),
            }
        }
        true
    };
    if !set(&mut known, start, guess) {
        return None;
    }

    // Keep walking the menu until nothing new is forced.
    // Edges may be reached in any order, so the whole menu is swept until it settles.
    loop {
        let mut changed = false;
        for &(i, p, c) in &menu.edges {
            for (from, to) in [(p, c), (c, p)] {
                let Some(u) = known[from as usize % ALPHABET] else {
                    continue;
                };
                let v = positions.at(i, u);
                match known[to as usize % ALPHABET] {
                    Some(w) if w != v => return None,
                    Some(_) => {}
                    None => {
                        if !set(&mut known, to, v) {
                            return None;
                        }
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    let mut board = Plugboard::empty();
    for (l, partner) in known.iter().enumerate() {
        if let Some(p) = partner {
            board.connect(l as u8, *p);
        }
    }
    Some(board)
}

#[cfg(test)]
mod tests {
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
