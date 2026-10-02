// SPDX-License-Identifier: MIT OR Apache-2.0

pub type Letter = u8;

pub type Text = Vec<Letter>;

pub const ALPHABET: usize = 26;

#[must_use]
pub fn char_letter(c: char) -> Option<Letter> {
    match c {
        'A'..='Z' => Some(c as u8 - b'A'),
        'a'..='z' => Some(c as u8 - b'a'),
        _ => None,
    }
}

#[must_use]
pub fn letter_char(l: Letter) -> char {
    (b'A' + (l % ALPHABET as u8)) as char
}

#[must_use]
pub fn to_letters(s: &str) -> Text {
    s.chars().filter_map(char_letter).collect()
}

#[must_use]
pub fn from_letters(ls: &[Letter]) -> String {
    ls.iter().map(|&l| letter_char(l)).collect()
}

#[inline]
#[must_use]
pub fn add(a: Letter, b: Letter) -> Letter {
    (a + b) % ALPHABET as u8
}

#[inline]
#[must_use]
pub fn sub(a: Letter, b: Letter) -> Letter {
    (a + ALPHABET as u8 - b % ALPHABET as u8) % ALPHABET as u8
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn keeps_letters_and_drops_the_rest() {
        assert_eq!(to_letters("Attack at dawn!"), to_letters("ATTACKATDAWN"));
    }

    #[test]
    fn rendering_inverts_parsing() {
        assert_eq!(from_letters(&to_letters("Attack at dawn!")), "ATTACKATDAWN");
    }

    #[test]
    fn arithmetic_wraps() {
        assert_eq!(add(25, 1), 0);
        assert_eq!(sub(0, 1), 25);
    }

    #[test]
    fn arithmetic_is_arithmetic_away_from_the_wrap() {
        assert_eq!(add(1, 2), 3);
        assert_eq!(add(10, 7), 17);
        assert_eq!(sub(9, 4), 5);
        assert_eq!(sub(20, 3), 17);
    }
}
