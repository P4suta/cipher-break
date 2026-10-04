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
    include!("queue-contract.rs");
    include!("settle-contract.rs");

    const EDGES: usize = 4;

    #[kani::proof]
    #[kani::unwind(105)]
    fn a_consistent_plugboard_guess_is_never_refuted_by_propagation() {
        let mapping: [u8; 26] = kani::any();
        for &letter in &mapping {
            kani::assume(letter < 26);
        }
        for (i, &partner) in mapping.iter().enumerate() {
            kani::assume(mapping[usize::from(partner)] == i as u8);
        }
        let plaintext = kani::any::<[u8; EDGES]>().map(|l| l % 26);
        let ciphertext = kani::any::<[u8; EDGES]>().map(|l| l % 26);
        for i in 0..EDGES {
            kani::assume(plaintext[i] != ciphertext[i]);
        }
        let truth = Plugboard::from_mapping(mapping);
        let starts: [u32; 27] = kani::any();
        kani::assume(starts[0] == 0 && starts[26] == (EDGES * 2) as u32);
        for letter in 0..26 {
            kani::assume(starts[letter] <= starts[letter + 1]);
        }
        let incident: [(u32, Letter); EDGES * 2] = kani::any();
        for &(edge, to) in &incident {
            kani::assume(edge < EDGES as u32 && to < 26);
        }
        for letter in 0..26 {
            for j in 0..EDGES * 2 {
                if starts[letter] as usize <= j && j < starts[letter + 1] as usize {
                    let (edge, to) = incident[j];
                    let edge = edge as usize;
                    kani::assume(
                        (plaintext[edge] == letter as u8 && ciphertext[edge] == to)
                            || (ciphertext[edge] == letter as u8 && plaintext[edge] == to),
                    );
                }
            }
        }
        let start = kani::any::<u8>() % 26;
        let menu = Menu {
            offset: 0,
            edges: Vec::new(),
            hub: start,
            incident: incident.to_vec(),
            starts,
        };
        let mut scratch = Scratch::new();
        scratch.assigned = kani::any();
        scratch.value = kani::any();
        scratch.pending = kani::any();
        let before = scratch.assigned;
        let at = |i: usize, letter| {
            let from = truth.map(plaintext[i]);
            let to = truth.map(ciphertext[i]);
            if letter == from {
                to
            } else if letter == to {
                from
            } else {
                kani::any::<u8>() % 26
            }
        };
        assert!(follow_with(
            &menu,
            at,
            start,
            truth.map(start),
            &mut scratch,
            &mapping,
        ));
        for letter in 0..26 {
            if let Some(known) = scratch.known(letter) {
                assert_eq!(known, truth.map(letter));
            }
        }
        kani::cover!(before == (1u32 << ALPHABET) - 1);
        kani::cover!(start == plaintext[0] && plaintext[0] == plaintext[1] && ciphertext[0] == ciphertext[1] && mapping[usize::from(start)] != start);
    }
}
