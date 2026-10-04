// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Workload {
    Verification,
    Recovery,
    Measurement,
    Experiment,
    Search,
}

pub fn needs_proof_tools(workload: Workload, full_recovery: bool) -> bool {
    workload == Workload::Verification || (workload == Workload::Recovery && full_recovery)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Evidence {
    Missing,
    Bootstrap,
    Recovered,
    Search,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Obligation {
    Independent,
    Queue,
    Partition,
    Reciprocal,
    Propagation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Selection {
    All,
    Reciprocal,
    One(Obligation),
}

pub fn prerequisite(target: Obligation, dependency: Obligation) -> bool {
    match target {
        Obligation::Reciprocal => dependency == Obligation::Queue,
        Obligation::Propagation => matches!(
            dependency,
            Obligation::Queue | Obligation::Partition | Obligation::Reciprocal
        ),
        _ => false,
    }
}

pub fn planned(selection: Selection, kind: Obligation, requested: bool) -> bool {
    match selection {
        Selection::All => true,
        Selection::Reciprocal => matches!(
            kind,
            Obligation::Queue | Obligation::Partition | Obligation::Reciprocal
        ),
        Selection::One(target) => requested || prerequisite(target, kind),
    }
}

pub fn needs_run(requested: bool, current: bool) -> bool {
    requested || !current
}

pub fn completed(workload: Workload, passed: bool) -> Evidence {
    if passed {
        match workload {
            Workload::Verification | Workload::Recovery | Workload::Measurement => {
                Evidence::Bootstrap
            }
            Workload::Experiment => Evidence::Recovered,
            Workload::Search => Evidence::Search,
        }
    } else {
        Evidence::Missing
    }
}

pub fn admitted(workload: Workload, evidence: Evidence) -> bool {
    match (workload, evidence) {
        (_, Evidence::Missing)
        | (Workload::Search, Evidence::Bootstrap | Evidence::Recovered)
        | (Workload::Experiment, Evidence::Bootstrap) => false,
        (
            Workload::Verification | Workload::Recovery | Workload::Measurement,
            Evidence::Bootstrap,
        )
        | (_, Evidence::Recovered | Evidence::Search) => true,
    }
}

#[cfg(any(feature = "gpu", test, kani))]
pub fn placement_selected(
    length: usize,
    crib: usize,
    actual: usize,
    requested: Option<usize>,
) -> bool {
    length
        .checked_sub(crib)
        .is_some_and(|last| actual <= last && requested.is_none_or(|expected| actual == expected))
}

pub fn experiment_command(length: usize, slots: [Option<&[u8]>; 12]) -> bool {
    let fixed = slots[0] == Some(b"cargo".as_slice())
        && slots[1] == Some(b"xtask".as_slice())
        && slots[2] == Some(b"p1030680".as_slice())
        && slots[3] == Some(b"campaign".as_slice())
        && slots[4] == Some(b"--candidate".as_slice())
        && matches!(slots[5], Some(b"C01" | b"C03" | b"C04" | b"C06"))
        && slots[6] == Some(b"--max-minutes".as_slice())
        && matches!(slots[7], Some(b"90" | b"100"));
    let tail = if slots[8] == Some(b"--at".as_slice()) {
        if slots[5] != Some(b"C06".as_slice())
            || !matches!(
                slots[9],
                Some(
                    b"0" | b"4"
                        | b"5"
                        | b"14"
                        | b"18"
                        | b"19"
                        | b"24"
                        | b"29"
                        | b"33"
                        | b"39"
                        | b"42"
                )
            )
        {
            return false;
        }
        10
    } else {
        8
    };
    fixed
        && match length.checked_sub(tail) {
            Some(0) => true,
            Some(1) => matches!(slots[tail], Some(b"--control-only" | b"--reuse-recovery")),
            Some(2) => {
                slots[tail] == Some(b"--control-only".as_slice())
                    && slots[tail + 1] == Some(b"--reuse-recovery".as_slice())
            }
            _ => false,
        }
}

pub fn proof_command(length: usize, slots: [Option<&[u8]>; 7], registered: bool) -> bool {
    length == 7
        && registered
        && slots[4].is_some()
        && slots[0] == Some(b"cargo".as_slice())
        && slots[1] == Some(b"xtask".as_slice())
        && slots[2] == Some(b"prove".as_slice())
        && slots[3] == Some(b"--case".as_slice())
        && slots[5] == Some(b"--max-seconds".as_slice())
        && slots[6] == Some(b"3300".as_slice())
}

pub fn measurement_command(length: usize, slots: [Option<&[u8]>; 5]) -> bool {
    slots[0] == Some(b"cargo".as_slice())
        && slots[1] == Some(b"xtask".as_slice())
        && slots[2] == Some(b"bench".as_slice())
        && (length == 3
            || (length == 5
                && slots[3] == Some(b"--period".as_slice())
                && matches!(slots[4], Some(b"1" | b"2" | b"3" | b"4" | b"5" | b"6"))))
}
