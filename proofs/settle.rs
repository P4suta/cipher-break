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
}
