// SPDX-License-Identifier: MIT OR Apache-2.0

#![feature(stmt_expr_attributes)]
#![feature(proc_macro_hygiene)]

#[path = "../src/alphabet.rs"]
mod alphabet;
#[path = "../src/enigma_types.rs"]
mod enigma_types;

mod ciphers {
    pub mod enigma {
        include!("../src/ciphers/enigma.rs");
    }
}

mod bombe {
    include!("../src/bombe.rs");

    #[kani::proof]
    fn placement_bounds_match_checked_addition_for_every_machine_integer() {
        let ciphertext_length: usize = kani::any();
        let crib_length: usize = kani::any();
        let offset: usize = kani::any();
        let fits = placement_fits(ciphertext_length, crib_length, offset);
        let end = offset.checked_add(crib_length);
        assert_eq!(
            fits,
            crib_length != 0 && end.is_some_and(|end| end <= ciphertext_length)
        );
        kani::cover!(fits && ciphertext_length == usize::MAX && offset == usize::MAX - 1);
        kani::cover!(!fits && offset == usize::MAX && crib_length == 1);
        kani::cover!(!fits && ciphertext_length == 0 && crib_length == 0);
    }

    #[kani::proof]
    #[kani::unwind(27)]
    fn an_out_of_range_crib_offset_is_rejected_without_overflow() {
        let offset: usize = kani::any();
        kani::assume(offset >= 2);
        assert!(Menu::place(&[0, 1], &[2], offset).is_none());
        kani::cover!(offset == usize::MAX);
        kani::cover!(offset == 2);
    }

    #[kani::proof]
    #[kani::unwind(27)]
    fn a_single_letter_crib_is_refuted_exactly_when_it_enciphers_itself() {
        let ciphertext = kani::any::<u8>() % 26;
        let plaintext = kani::any::<u8>() % 26;
        let placed = Menu::place(&[ciphertext], &[plaintext], 0);
        assert_eq!(placed.is_none(), ciphertext == plaintext);
        if let Some(menu) = placed {
            assert_eq!(menu.edges, vec![(0, plaintext, ciphertext)]);
            assert_eq!(menu.incident.len(), 2);
        }
        kani::cover!(ciphertext == plaintext);
        kani::cover!(ciphertext != plaintext);
    }
}
