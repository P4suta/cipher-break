// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::alphabet::{ALPHABET, Letter};
use crate::ciphers::enigma::{Enigma, Plugboard, Settings};

#[derive(Clone, Debug)]
pub struct Menu {
    pub offset: usize,
    pub edges: Vec<(usize, Letter, Letter)>,
    hub: Letter,
    incident: Vec<(u32, Letter)>,
    starts: [u32; ALPHABET + 1],
}

pub const RANK_OF_TRUTH_WHEN_SHORT: u64 = 146;

impl Menu {
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

    #[must_use]
    pub fn chance_stops(&self, settings: u64) -> f64 {
        let exponent = self.closures().saturating_sub(1) as i32;
        settings as f64 / (ALPHABET as f64).powi(exponent)
    }

    #[must_use]
    pub fn decisive_over(&self, settings: u64) -> bool {
        self.chance_stops(settings) < 1.0
    }

    #[must_use]
    pub fn expected_rank_of_truth(&self, settings: u64, rank_over_all: u64) -> f64 {
        1.0 + rank_over_all as f64 * self.chance_stops(settings) / settings as f64
    }

    #[must_use]
    pub fn survival_rate(&self, rotors: [usize; 3], reflector: [u8; ALPHABET]) -> f64 {
        let span = (ALPHABET as u32).pow(3);
        let reach = self.offset + self.edges.len();
        let mut positions =
            Positions::of(Settings::at(rotors, 0, [0; 3], [0; 3]), reflector, reach);
        let mut scratch = Scratch::new();
        let mut survived = 0u32;
        for index in 0..span {
            let settings = Settings::at(
                rotors,
                0,
                [0; 3],
                [
                    (index / (ALPHABET as u32 * ALPHABET as u32)) as u8,
                    ((index / ALPHABET as u32) % ALPHABET as u32) as u8,
                    (index % ALPHABET as u32) as u8,
                ],
            );
            positions.restart(settings, reach);
            if matches!(
                scan_with(self, &positions, &mut scratch),
                Stop::Survived { .. }
            ) {
                survived += 1;
            }
        }
        f64::from(survived) / f64::from(span)
    }

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

    #[must_use]
    pub fn hub(&self) -> Letter {
        self.hub
    }

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

fn find(parent: &mut [usize; ALPHABET], mut x: usize) -> usize {
    while parent[x] != x {
        parent[x] = parent[parent[x]];
        x = parent[x];
    }
    x
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stop {
    Refuted,
    Survived {
        assumed: (Letter, Letter),
        board: Plugboard,
        known: u32,
    },
}

#[derive(Clone, Debug)]
pub struct Positions {
    machine: Enigma,
    offsets: Vec<[crate::enigma_types::Offset; 3]>,
}

impl Positions {
    #[must_use]
    pub fn of(settings: Settings, reflector: [u8; ALPHABET], length: usize) -> Positions {
        let mut machine = Enigma::with_reflector(settings, reflector, Plugboard::empty());
        let offsets = machine.offset_trace(length);
        Positions { machine, offsets }
    }

    pub fn aim(&mut self, settings: Settings, reflector: [u8; ALPHABET], length: usize) {
        self.machine.aim(settings, reflector);
        self.retrace(settings, length);
    }

    pub fn restart(&mut self, settings: Settings, length: usize) {
        self.machine.restart(settings.positions);
        self.retrace(settings, length);
    }

    fn retrace(&mut self, settings: Settings, length: usize) {
        self.machine.trace_into(length, &mut self.offsets);
        self.machine.restart(settings.positions);
    }

    #[inline]
    #[must_use]
    pub fn at(&self, i: usize, l: Letter) -> Letter {
        self.machine.transform_at(self.offsets[i], l)
    }
}

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
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.stamp = [0; ALPHABET];
            self.generation = 1;
        }
    }

    #[inline]
    fn known(&self, l: Letter) -> Option<Letter> {
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

#[must_use]
pub fn scan(menu: &Menu, positions: &Positions) -> Stop {
    scan_with(menu, positions, &mut Scratch::new())
}

#[must_use]
pub fn scan_with(menu: &Menu, positions: &Positions, scratch: &mut Scratch) -> Stop {
    if menu.edges.is_empty() {
        return Stop::Refuted;
    }
    let start = menu.hub;
    for guess in 0..ALPHABET as u8 {
        if follow(menu, positions, start, guess, scratch) {
            return survived(scratch, start, guess);
        }
    }
    Stop::Refuted
}

#[must_use]
pub fn scan_all_with(menu: &Menu, positions: &Positions, scratch: &mut Scratch) -> Vec<Stop> {
    if menu.edges.is_empty() {
        return Vec::new();
    }
    let start = menu.hub;
    let mut out = Vec::new();
    for guess in 0..ALPHABET as u8 {
        if follow(menu, positions, start, guess, scratch) {
            out.push(survived(scratch, start, guess));
        }
    }
    out
}

pub fn complete_menu<'a>(
    menu: &'a Menu,
    positions: &'a Positions,
    (board, known): (Plugboard, u32),
    leads: usize,
) -> impl Iterator<Item = (Plugboard, u32)> + 'a {
    let mut pending = vec![(board, known)];
    let letters = menu.letters();
    std::iter::from_fn(move || {
        while let Some((mut board, mut known)) = pending.pop() {
            if !propagate(menu, positions, &mut board, &mut known) || board.pairs().len() > leads {
                continue;
            }
            let next = letters
                .iter()
                .copied()
                .filter(|&l| known & (1 << l) == 0)
                .max_by_key(|&l| menu.starts[l as usize + 1] - menu.starts[l as usize]);
            let Some(next) = next else {
                return Some((board, known));
            };
            for guess in (0..ALPHABET as u8).rev() {
                let (mut trial, mut fixed) = (board, known);
                if fix_lead(&mut trial, &mut fixed, next, guess) {
                    pending.push((trial, fixed));
                }
            }
        }
        None
    })
}

fn fix_lead(board: &mut Plugboard, known: &mut u32, a: Letter, b: Letter) -> bool {
    if (*known & (1 << a) != 0 && board.map(a) != b)
        || (*known & (1 << b) != 0 && board.map(b) != a)
    {
        return false;
    }
    board.connect(a, b);
    *known |= (1 << a) | (1 << b);
    true
}

fn propagate(menu: &Menu, positions: &Positions, board: &mut Plugboard, known: &mut u32) -> bool {
    loop {
        let before = *known;
        for &(i, p, c) in &menu.edges {
            let pair = if *known & (1 << p) != 0 {
                Some((c, positions.at(i, board.map(p))))
            } else if *known & (1 << c) != 0 {
                Some((p, positions.at(i, board.map(c))))
            } else {
                None
            };
            if let Some((a, b)) = pair
                && !fix_lead(board, known, a, b)
            {
                return false;
            }
        }
        if before == *known {
            return true;
        }
    }
}

fn survived(scratch: &Scratch, start: Letter, guess: Letter) -> Stop {
    let mut board = Plugboard::empty();
    let mut known = 0u32;
    for l in 0..ALPHABET as u8 {
        if let Some(p) = scratch.known(l) {
            board.connect(l, p);
            known |= 1 << l;
        }
    }
    Stop::Survived {
        assumed: (start, guess),
        board,
        known,
    }
}

fn follow(
    menu: &Menu,
    positions: &Positions,
    start: Letter,
    guess: Letter,
    scratch: &mut Scratch,
) -> bool {
    scratch.begin();
    let mut waiting = 0usize;

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

        let ct =
            to_letters("JCRSAJTGSJEYEXYKKZZSHVUOCTRFRCRPFVYPLKPPLGRHVVBBTBRSXSWXGGTYTVKQNGSCHVGF");
        let crib = to_letters("KEINEBESONDERENVORKOMMNISSE");
        let menu = Menu::place(&ct, &crib, 0).expect("the crib fits at the front");
        let settings = 1_000_000u64;
        let expected = settings as f64 / 26f64.powi(menu.closures() as i32 - 1);
        assert!((menu.chance_stops(settings) - expected).abs() < 1e-6);

        assert_eq!(
            menu.decisive_over(settings),
            menu.chance_stops(settings) < 1.0
        );
    }

    #[test]
    fn a_menu_with_one_closure_decides_nothing() {
        use crate::alphabet::to_letters;

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
        let ct = to_letters("ZZZZZZ");
        let menu = Menu::place(&ct, &to_letters("ABCDEF"), 0).expect("placed");
        assert_eq!(menu.closures(), 0);
    }

    #[test]
    fn a_repeated_pair_closes_a_loop() {
        let ct = to_letters("BABABA");
        let menu = Menu::place(&ct, &to_letters("ABABAB"), 0).expect("placed");
        assert_eq!(menu.closures(), 5);
    }

    #[test]
    fn a_menu_without_closures_refutes_nothing() {
        let (settings, reflector, _, _, ct) = planted();
        let star: Vec<Letter> = (0..6)
            .map(|i| (0..ALPHABET as u8).find(|&l| l != ct[i]).expect("a letter"))
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
                for (a, b) in found.pairs() {
                    assert_eq!(board.map(a), b, "invented a lead {a}-{b}");
                }
            }
            Stop::Refuted => panic!("the true setting was refuted by its own crib"),
        }
        let _ = plain;
    }

    #[test]
    fn completing_components_preserves_the_key_and_every_menu_edge() {
        let (settings, reflector, truth, plain, ct) = planted();
        let menu = Menu::place(&ct, &plain[..16], 0).expect("true crib");
        let positions = Positions::of(settings, reflector, menu.edges.len());
        let found: Vec<_> = scan_all_with(&menu, &positions, &mut Scratch::new())
            .into_iter()
            .filter_map(|stop| match stop {
                Stop::Survived { board, known, .. } => Some((board, known)),
                Stop::Refuted => None,
            })
            .flat_map(|partial| complete_menu(&menu, &positions, partial, 10))
            .collect();
        assert!(!found.is_empty());
        assert!(found.iter().any(|(board, known)| {
            (0..26u8).all(|l| known & (1 << l) == 0 || board.map(l) == truth.map(l))
        }));
        for (board, known) in found {
            assert!(board.pairs().len() <= 10);
            assert!(menu.letters().iter().all(|&l| known & (1 << l) != 0));
            let read = Enigma::with_reflector(settings, reflector, board).run(&ct);
            assert_eq!(read[..16], plain[..16]);
            for l in 0..26u8 {
                assert_eq!(board.map(board.map(l)), l);
                if known & (1 << l) != 0 {
                    assert_ne!(known & (1 << board.map(l)), 0);
                }
            }
        }
    }

    #[test]
    fn a_fixed_complete_board_still_checks_edges_and_the_lead_limit() {
        let (settings, reflector, truth, plain, ct) = planted();
        let menu = Menu::place(&ct, &plain[..16], 0).expect("true crib");
        let positions = Positions::of(settings, reflector, menu.edges.len());
        let known = (1 << ALPHABET) - 1;
        assert_eq!(
            complete_menu(&menu, &positions, (truth, known), 5).count(),
            1
        );
        assert_eq!(
            complete_menu(&menu, &positions, (truth, known), 4).count(),
            0
        );
        let mut wrong = settings;
        wrong.positions[2] = Indicator::new((wrong.positions[2].value() + 1) % 26);
        let wrong_positions = Positions::of(wrong, reflector, menu.edges.len());
        assert_eq!(
            complete_menu(&menu, &wrong_positions, (truth, known), 5).count(),
            0
        );
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
