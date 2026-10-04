// SPDX-License-Identifier: MIT OR Apache-2.0

#[path = "../src/alphabet.rs"]
mod alphabet;
#[path = "../src/enigma_types.rs"]
mod enigma_types;

mod machine {
    include!("../src/ciphers/enigma.rs");

    #[kani::proof]
    #[kani::unwind(27)]
    fn every_published_rotor_inverts_at_every_offset() {
        let rotor = usize::from(kani::any::<u8>()) % ROTOR_COUNT;
        let letter = kani::any::<u8>() % ALPHABET as u8;
        let offset = Offset::new(kani::any());
        let forward = wiring(ROTORS[rotor].0);
        let backward = inverse(&forward);
        let encoded = offset.through(&forward, letter);
        assert_eq!(offset.through(&backward, encoded), letter);
        kani::cover!(rotor == 7 && letter == 25 && offset.value() == 25);
    }

    #[kani::proof]
    #[kani::unwind(27)]
    fn every_naval_reflector_is_an_involution_without_a_fixed_point() {
        let greek = usize::from(kani::any::<u8>()) % 2;
        let thin = usize::from(kani::any::<u8>()) % 2;
        let setting = kani::any::<u8>() % ALPHABET as u8;
        let letter = kani::any::<u8>() % ALPHABET as u8;
        let reflected = composite_reflector(greek, setting, thin);
        let image = reflected[usize::from(letter)];
        assert_ne!(image, letter);
        assert_eq!(reflected[usize::from(image)], letter);
        kani::cover!(greek == 1 && thin == 1 && setting == 25 && letter == 25);
    }
}
