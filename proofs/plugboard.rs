// SPDX-License-Identifier: MIT OR Apache-2.0

#[path = "../src/alphabet.rs"]
mod alphabet;
#[path = "../src/enigma_types.rs"]
mod enigma_types;

mod machine {
    include!("../src/ciphers/enigma.rs");

    #[kani::proof]
    #[kani::unwind(27)]
    fn connecting_leads_preserves_every_valid_plugboard_involution() {
        let mapping: [u8; 26] = kani::any();
        for &letter in &mapping {
            kani::assume(letter < 26);
        }
        for (i, &partner) in mapping.iter().enumerate() {
            kani::assume(mapping[usize::from(partner)] == i as u8);
        }
        let a = kani::any::<u8>() % 26;
        let b = kani::any::<u8>() % 26;
        let letter = kani::any::<u8>() % 26;
        let old_a = mapping[usize::from(a)];
        let old_b = mapping[usize::from(b)];
        let mut board = Plugboard::from_mapping(mapping);
        board.connect(a, b);
        assert_eq!(board.map(a), b);
        assert_eq!(board.map(b), a);
        assert!(board.map(letter) < 26);
        assert_eq!(board.map(board.map(letter)), letter);
        if ![a, b, old_a, old_b].contains(&letter) {
            assert_eq!(board.map(letter), mapping[usize::from(letter)]);
        }
        kani::cover!(a == 0 && b == 25 && old_a != a);
        kani::cover!(a == b && old_a != a);
    }
}
