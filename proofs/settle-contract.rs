// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Clone, Copy, PartialEq, Eq)]
enum PairCase {
    Same,
    BothNew,
    FirstNew,
    SecondNew,
    BothKnown,
}

fn pair_case(same: bool, first_missing: bool, second_missing: bool) -> PairCase {
    if same {
        PairCase::Same
    } else {
        match (first_missing, second_missing) {
            (true, true) => PairCase::BothNew,
            (true, false) => PairCase::FirstNew,
            (false, true) => PairCase::SecondNew,
            (false, false) => PairCase::BothKnown,
        }
    }
}

#[kani::proof]
#[kani::unwind(6)]
fn reciprocal_cases_partition_every_pair_of_assignment_states() {
    let same: bool = kani::any();
    let first_missing: bool = kani::any();
    let second_missing: bool = kani::any();
    let selected = pair_case(same, first_missing, second_missing);
    let cases = [
        (PairCase::Same, same),
        (PairCase::BothNew, !same && first_missing && second_missing),
        (PairCase::FirstNew, !same && first_missing && !second_missing),
        (PairCase::SecondNew, !same && !first_missing && second_missing),
        (PairCase::BothKnown, !same && !first_missing && !second_missing),
    ];
    for (case, admitted) in cases {
        assert_eq!(selected == case, admitted);
    }
    assert_eq!(cases.into_iter().filter(|(_, admitted)| *admitted).count(), 1);
    kani::cover!(selected == PairCase::Same && first_missing);
    kani::cover!(selected == PairCase::BothNew);
}

fn check_reciprocal_case(selected: PairCase) {
    let mut scratch: Scratch = kani::any();
    let mut waiting: usize = kani::any();
    let a: Letter = kani::any();
    let b: Letter = if selected == PairCase::Same { a } else { kani::any() };
    kani::assume(usize::from(a) < ALPHABET && usize::from(b) < ALPHABET);
    kani::assume(waiting <= ALPHABET && missing_pair(&scratch, a, b) <= ALPHABET - waiting);
    let first = scratch.known(a);
    let second = scratch.known(b);
    kani::assume(pair_case(a == b, first.is_none(), second.is_none()) == selected);
    let assigned = scratch.assigned;
    let values = scratch.value;
    let pending = scratch.pending;
    let count = waiting;
    let index: usize = kani::any();
    kani::assume(index < ALPHABET);
    let first_added = first.is_none();
    let first_agrees = first.is_none_or(|value| value == b);
    let second_added = first_agrees && a != b && second.is_none();
    let result = scratch.settle(&mut waiting, a, b);
    assert_eq!(result, first.is_none_or(|value| value == b) && second.is_none_or(|value| value == a));
    assert!(!result || (scratch.known(a) == Some(b) && scratch.known(b) == Some(a)));
    assert_eq!(waiting, count + usize::from(first_added) + usize::from(second_added));
    assert_eq!(scratch.assigned, assigned | if first_added { 1 << a } else { 0 } | if second_added { 1 << b } else { 0 });
    assert_eq!(scratch.value[index], if first_added && index == usize::from(a) { b } else if second_added && index == usize::from(b) { a } else { values[index] });
    assert_eq!(scratch.pending[index], if first_added && index == count { a } else if second_added && index == count + usize::from(first_added) { b } else { pending[index] });
    kani::cover!(result);
    kani::cover!(if selected == PairCase::BothNew { waiting == ALPHABET } else { !result });
}

#[kani::proof]
#[kani::unwind(105)]
fn reciprocal_assignments_of_the_same_letter() {
    check_reciprocal_case(PairCase::Same);
}

#[kani::proof]
#[kani::unwind(105)]
fn reciprocal_assignments_of_two_new_letters() {
    check_reciprocal_case(PairCase::BothNew);
}

#[kani::proof]
#[kani::unwind(105)]
fn reciprocal_assignments_with_only_the_first_letter_new() {
    check_reciprocal_case(PairCase::FirstNew);
}

#[kani::proof]
#[kani::unwind(105)]
fn reciprocal_assignments_with_only_the_second_letter_new() {
    check_reciprocal_case(PairCase::SecondNew);
}

#[kani::proof]
#[kani::unwind(105)]
fn reciprocal_assignments_of_two_known_letters() {
    check_reciprocal_case(PairCase::BothKnown);
}
