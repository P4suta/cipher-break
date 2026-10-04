// SPDX-License-Identifier: MIT OR Apache-2.0

#[path = "../src/alphabet.rs"]
mod alphabet;
#[path = "../src/enigma_types.rs"]
mod enigma_types;

mod machine {
    include!("../src/ciphers/enigma.rs");

    fn state(positions: [Indicator; 3], middle: [bool; 26], right: [bool; 26]) -> Enigma {
        let identity = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25,
        ];
        let rotor = Rotor {
            forward: identity,
            backward: identity,
            notches: [false; 26],
        };
        Enigma {
            rotor_ids: [0, 1, 2],
            rotors: [
                rotor,
                Rotor {
                    notches: middle,
                    ..rotor
                },
                Rotor {
                    notches: right,
                    ..rotor
                },
            ],
            reflector: [
                25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4,
                3, 2, 1, 0,
            ],
            rings: [Ring::new(0); 3],
            positions,
            plugboard: Plugboard::empty(),
        }
    }

    #[kani::proof]
    fn one_press_obeys_the_notches_before_stepping() {
        let positions = [
            Indicator::new(kani::any()),
            Indicator::new(kani::any()),
            Indicator::new(kani::any()),
        ];
        let middle: [bool; 26] = kani::any();
        let right: [bool; 26] = kani::any();
        let carry_left = middle[positions[1].index()];
        let carry_middle = carry_left || right[positions[2].index()];
        let mut machine = state(positions, middle, right);
        machine.step();
        assert_eq!(machine.positions[2], positions[2].step());
        assert_eq!(
            machine.positions[1],
            if carry_middle {
                positions[1].step()
            } else {
                positions[1]
            }
        );
        assert_eq!(
            machine.positions[0],
            if carry_left {
                positions[0].step()
            } else {
                positions[0]
            }
        );
        kani::cover!(carry_left && !right[positions[2].index()]);
        kani::cover!(!carry_left && right[positions[2].index()]);
        kani::cover!(!carry_middle);
    }

    #[kani::proof]
    fn a_notch_reached_by_the_right_carry_causes_a_double_step() {
        let left = Indicator::new(kani::any());
        let notch = Indicator::new(kani::any());
        let before = Indicator::new((notch.value() + 25) % 26);
        let right_position = Indicator::new(kani::any());
        let middle: [bool; 26] = kani::any();
        let right: [bool; 26] = kani::any();
        kani::assume(!middle[before.index()]);
        kani::assume(middle[notch.index()]);
        kani::assume(right[right_position.index()]);
        let mut machine = state([left, before, right_position], middle, right);
        machine.step();
        assert_eq!(machine.positions, [left, notch, right_position.step()]);
        machine.step();
        assert_eq!(
            machine.positions,
            [left.step(), notch.step(), right_position.step().step()]
        );
        kani::cover!(left.value() == 25 && notch.value() == 0);
        kani::cover!(right_position.value() == 25);
    }

    #[kani::proof]
    fn normalizing_the_left_ring_preserves_offsets_and_one_step() {
        let positions = [
            Indicator::new(kani::any()),
            Indicator::new(kani::any()),
            Indicator::new(kani::any()),
        ];
        let mut original = state(positions, kani::any(), kani::any());
        original.rings = [
            Ring::new(kani::any()),
            Ring::new(kani::any()),
            Ring::new(kani::any()),
        ];
        let mut normalized = original.clone();
        normalized.rings[0] = Ring::new(0);
        normalized.positions[0] = positions[0]
            .against(original.rings[0])
            .with_ring(normalized.rings[0]);
        assert_eq!(original.offsets(), normalized.offsets());
        original.step();
        normalized.step();
        assert_eq!(original.offsets(), normalized.offsets());
        assert_eq!(original.positions[1..], normalized.positions[1..]);
        assert_eq!(
            normalized.positions[0],
            original.positions[0]
                .against(original.rings[0])
                .with_ring(Ring::new(0))
        );
        kani::cover!(positions[0].value() == 25 && original.rings[0].value() == 25);
    }
}
