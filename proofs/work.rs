// SPDX-License-Identifier: MIT OR Apache-2.0

#[path = "../xtask/src/proof_work.rs"]
mod proof_work;

use proof_work::{Evidence, Obligation, Selection, Workload, admitted, completed, experiment_command, needs_proof_tools, needs_run, placement_selected, planned, proof_command};

#[kani::proof]
fn explicit_placements_preserve_valid_offsets_without_overflow_or_fallback() {
    let length: usize = kani::any();
    let crib: usize = kani::any();
    let actual: usize = kani::any();
    let requested: Option<usize> = kani::any();
    let selected = placement_selected(length, crib, actual, requested);
    let fits = actual.checked_add(crib).is_some_and(|end| end <= length);
    assert!(!selected || crib <= length);
    assert!(!selected || fits);
    assert!(!selected || requested.is_none_or(|expected| actual == expected));
    assert_eq!(selected, fits && requested.is_none_or(|expected| actual == expected));
    kani::cover!(selected && requested.is_none());
    kani::cover!(selected && requested.is_some());
    kani::cover!(!selected && fits);
    kani::cover!(!selected && !fits);
}

#[kani::proof]
fn requested_proofs_include_their_contract_prerequisites() {
    let selection: Selection = kani::any();
    let kind: Obligation = kani::any();
    let requested: bool = kani::any();
    let current: bool = kani::any();
    assert!(planned(Selection::All, kind, requested));
    assert!(planned(Selection::Reciprocal, Obligation::Queue, requested));
    assert!(planned(Selection::Reciprocal, Obligation::Partition, requested));
    assert!(planned(Selection::One(Obligation::Reciprocal), Obligation::Queue, requested));
    assert!(planned(Selection::One(Obligation::Propagation), Obligation::Queue, requested));
    assert!(planned(Selection::One(Obligation::Propagation), Obligation::Partition, requested)
        && planned(Selection::One(Obligation::Propagation), Obligation::Reciprocal, requested));
    assert_eq!(needs_run(requested, current), requested || !current);
    kani::cover!(planned(selection, kind, requested) && needs_run(requested, current));
    kani::cover!(planned(selection, kind, requested) && !needs_run(requested, current));
    kani::cover!(!planned(selection, kind, requested));
}

#[kani::proof]
fn verification_bootstrap_cannot_authorize_an_unproved_ciphertext_search() {
    let workload: Workload = kani::any();
    let evidence: Evidence = kani::any();
    let permitted = admitted(workload, evidence);
    assert!(!permitted || evidence != Evidence::Missing);
    assert!(!permitted || workload != Workload::Search || evidence == Evidence::Search);
    assert!(permitted || workload != Workload::Verification || evidence == Evidence::Missing);
    assert!(!permitted || workload != Workload::Experiment || matches!(evidence, Evidence::Recovered | Evidence::Search));
    let passed: bool = kani::any();
    assert_eq!(admitted(workload, completed(workload, passed)), passed);
    kani::cover!(workload == Workload::Verification && evidence == Evidence::Bootstrap && permitted);
    kani::cover!(workload == Workload::Search && evidence == Evidence::Bootstrap && !permitted);
    kani::cover!(workload == Workload::Recovery && evidence == Evidence::Bootstrap && permitted);
    kani::cover!(workload == Workload::Experiment && evidence == Evidence::Bootstrap && !permitted);
    let full: bool = kani::any();
    let tools = needs_proof_tools(workload, full);
    assert!(!tools || workload == Workload::Verification || workload == Workload::Recovery && full);
    assert!(workload != Workload::Verification || tools);
    assert!(workload != Workload::Recovery || tools == full);
    kani::cover!(workload == Workload::Recovery && full && tools);
    kani::cover!(workload == Workload::Recovery && !full && !tools);
}

#[kani::proof]
#[kani::unwind(20)]
fn verification_commands_require_every_fixed_argument_and_a_registered_case() {
    let length: usize = kani::any();
    let registered: bool = kani::any();
    let slots: [Option<&[u8]>; 7] = std::array::from_fn(|_| {
        if kani::any::<bool>() { Some(kani::arbitrary::any_slice_ref_unbounded()) } else { None }
    });
    let permitted = proof_command(length, slots, registered);
    assert!(!permitted || length == 7);
    assert!(!permitted || registered);
    assert!(!permitted || slots[4].is_some());
    assert!(!permitted || slots[0] == Some(b"cargo".as_slice()));
    assert!(!permitted || slots[1] == Some(b"xtask".as_slice()));
    assert!(!permitted || slots[2] == Some(b"prove".as_slice()));
    assert!(!permitted || slots[3] == Some(b"--case".as_slice()));
    assert!(!permitted || slots[5] == Some(b"--max-seconds".as_slice()));
    assert!(!permitted || slots[6] == Some(b"3300".as_slice()));
    kani::cover!(permitted);
    kani::cover!(!permitted && length == 7 && !registered);
    let experiment_slots: [Option<&[u8]>; 12] = std::array::from_fn(|_| {
        if kani::any::<bool>() { Some(kani::arbitrary::any_slice_ref_unbounded()) } else { None }
    });
    let experiment = experiment_command(length, experiment_slots);
    assert!(!experiment || (8..=12).contains(&length));
    assert!(!experiment || experiment_slots[0] == Some(b"cargo".as_slice()) && experiment_slots[1] == Some(b"xtask".as_slice()) && experiment_slots[2] == Some(b"p1030680".as_slice()) && experiment_slots[3] == Some(b"campaign".as_slice()));
    assert!(!experiment || matches!(experiment_slots[5], Some(b"C01" | b"C03" | b"C04" | b"C06")) && matches!(experiment_slots[7], Some(b"90" | b"100")));
    assert!(!experiment || experiment_slots[4] == Some(b"--candidate".as_slice()) && experiment_slots[6] == Some(b"--max-minutes".as_slice()));
    assert!(!experiment || experiment_slots[8] != Some(b"--at".as_slice()) || experiment_slots[5] == Some(b"C06".as_slice()) && matches!(experiment_slots[9], Some(b"0" | b"4" | b"5" | b"14" | b"18" | b"19" | b"24" | b"29" | b"33" | b"39" | b"42")));
    kani::cover!(experiment);
    kani::cover!(experiment && experiment_slots[8] == Some(b"--at".as_slice()));
    kani::cover!(!experiment && length == 10);
}
