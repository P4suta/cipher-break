// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::alphabet::Letter;

#[derive(Clone, Debug)]
pub struct Crib {
    pub word: Vec<Letter>,
    pub offsets: Vec<usize>,
}

#[must_use]
pub fn placements(ct: &[Letter], word: &[Letter]) -> Vec<usize> {
    if word.is_empty() || word.len() > ct.len() {
        return Vec::new();
    }
    (0..=ct.len() - word.len())
        .filter(|&offset| word.iter().zip(&ct[offset..]).all(|(a, b)| a != b))
        .collect()
}

impl Crib {
    #[must_use]
    pub fn against(ct: &[Letter], word: &[Letter]) -> Crib {
        Crib {
            word: word.to_vec(),
            offsets: placements(ct, word),
        }
    }

    #[must_use]
    pub fn cut(&self, ct_len: usize) -> f64 {
        let total = ct_len.saturating_sub(self.word.len()) + 1;
        if total == 0 {
            return 0.0;
        }
        1.0 - self.offsets.len() as f64 / total as f64
    }
}

pub const BOMBE_MINIMUM: usize = 20;

pub const KRIEGSMARINE_LONG: &[&str] = &[
    "VONVONJAWEGENDERSITUATION",
    "ANBDUXXFEINDKONVOIINSICHT",
    "KEINEBESONDERENVORKOMMNISSE",
    "NICHTSZUMELDENXXENDEXX",
    "WETTERBERICHTXXWINDXX",
    "STANDORTMARQUADRATXX",
    "FEINDKONVOIINSICHTXXGREIFEAN",
    "MELDEICHXXSTANDORTXX",
    "ANALLEBOOTEXXBEFEHLXX",
    "FUNKSPRUCHNUMMEREINS",
    "BEIMORGENGRAUENANGRIFF",
    "ERBITTEUNTERSTUETZUNG",
];

pub const KRIEGSMARINE: &[&str] = &[
    "VONVON",
    "ANBDU",
    "UBOOT",
    "FEINDKONVOI",
    "MARQUADRAT",
    "STANDORT",
    "WETTER",
    "MELDE",
    "ANGRIFF",
    "TORPEDO",
    "GESENKT",
    "NICHTSZUMELDEN",
    "FUNKSPRUCH",
    "KEINEBESONDEREN",
    "EINSEINS",
    "ZWOZWO",
    "QUADRAT",
    "GELEITZUG",
    "ZERSTOERER",
    "TAUCHE",
    "BEGINN",
    "ENDEXX",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alphabet::to_letters;
    use crate::ciphers::enigma::{Enigma, Plugboard, Settings};

    #[test]
    fn a_letter_over_itself_refutes_a_placement() {
        let ct = to_letters("ABCDEF");
        assert!(!placements(&ct, &to_letters("A")).contains(&0));
        assert!(placements(&ct, &to_letters("A")).contains(&1));
    }

    #[test]
    fn a_crib_longer_than_the_text_sits_nowhere() {
        assert!(placements(&to_letters("AB"), &to_letters("ABC")).is_empty());
    }

    #[test]
    fn an_empty_crib_sits_nowhere() {
        assert!(placements(&to_letters("ABC"), &[]).is_empty());
    }

    #[test]
    fn the_true_placement_is_never_refuted() {
        let settings = Settings::new([0, 1, 2], 0);
        let plain = to_letters("VONVONJAWEGENDERSITUATIONXXMELDEICHXX");
        let ct = Enigma::new(settings, Plugboard::empty()).run(&plain);
        for start in [0usize, 3, 7, 11] {
            let word = &plain[start..start + 6];
            assert!(
                placements(&ct, word).contains(&start),
                "the true placement at {start} was refuted"
            );
        }
    }

    #[test]
    fn a_longer_crib_cuts_more() {
        let settings = Settings::new([0, 1, 2], 0);
        let plain = to_letters("VONVONJAWEGENDERSITUATIONXXMELDEICHXXFEINDKONVOIINSICHT");
        let ct = Enigma::new(settings, Plugboard::empty()).run(&plain);
        let short = Crib::against(&ct, &to_letters("VON"));
        let long = Crib::against(&ct, &to_letters("VONVONJAWEGEN"));
        assert!(long.cut(ct.len()) > short.cut(ct.len()));
    }

    #[test]
    fn a_crib_the_length_of_the_text_has_one_offset_to_test() {
        let ct = to_letters("ABC");
        assert_eq!(placements(&ct, &to_letters("BCA")).len(), 1);
        assert!(placements(&ct, &to_letters("ABC")).is_empty());
    }

    #[test]
    fn a_crib_that_fits_nowhere_cuts_everything() {
        let ct = to_letters("AAAA");
        let crib = Crib::against(&ct, &to_letters("A"));
        assert!(crib.offsets.is_empty());
        assert!((crib.cut(ct.len()) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn a_crib_that_fits_everywhere_cuts_nothing() {
        let ct = to_letters("AAAA");
        let crib = Crib::against(&ct, &to_letters("B"));
        assert_eq!(crib.offsets.len(), 4);
        assert!(crib.cut(ct.len()).abs() < 1e-12);
    }

    #[test]
    fn the_naval_cribs_are_letters_only() {
        for word in KRIEGSMARINE.iter().chain(KRIEGSMARINE_LONG) {
            assert_eq!(to_letters(word).len(), word.len(), "{word}");
        }
    }

    #[test]
    fn the_long_cribs_are_long_enough_for_a_bombe() {
        for word in KRIEGSMARINE_LONG {
            assert!(
                word.len() >= BOMBE_MINIMUM,
                "{word} is {} letters, below the {BOMBE_MINIMUM} a menu needs to close",
                word.len()
            );
        }
    }

    #[test]
    fn the_short_cribs_are_below_that_bar() {
        assert!(KRIEGSMARINE.iter().all(|w| w.len() < BOMBE_MINIMUM));
    }
}
