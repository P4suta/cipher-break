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
    #[kani::unwind(27)]
    fn a_new_scratch_run_forgets_every_mapping_and_preserves_stored_values() {
        let assigned = kani::any::<u32>();
        let value = kani::any();
        let pending = kani::any();
        let mut scratch = Scratch {
            assigned,
            value,
            pending,
        };
        scratch.begin();
        assert_eq!(scratch.assigned, 0);
        for letter in 0..26 {
            assert!(scratch.known(letter).is_none());
        }
        assert_eq!(scratch.value, value);
        assert_eq!(scratch.pending, pending);
        kani::cover!(assigned == (1u32 << ALPHABET) - 1);
        kani::cover!(assigned == 0);
    }
}
