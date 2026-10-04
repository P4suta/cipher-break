// SPDX-License-Identifier: MIT OR Apache-2.0

#[kani::proof_for_contract(Scratch::queue)]
#[kani::unwind(105)]
fn queue_checks_existing_partners_and_frames_every_new_assignment() {
    let mut scratch: Scratch = kani::any();
    let mut waiting: usize = kani::any();
    let letter: Letter = kani::any();
    let partner: Letter = kani::any();
    let before = scratch.known(letter);
    let count = waiting;
    let result = scratch.queue(&mut waiting, letter, partner);
    assert_eq!(result, before.is_none_or(|value| value == partner));
    assert_eq!(waiting, count + usize::from(before.is_none()));
    kani::cover!(before.is_none() && count == ALPHABET - 1);
    kani::cover!(before.is_some_and(|value| value != partner));
    kani::cover!(before == Some(partner) && scratch.assigned == (1u32 << ALPHABET) - 1);
}
