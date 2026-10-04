// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intent {
    Prove,
    Refute,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    Passed,
    AssertionPassed,
    CoverSatisfied,
    UnreachableSafety,
    ExpectedRefutation,
    Rejected,
}

#[derive(Clone, Copy, Debug)]
pub struct Completion {
    pub total: u64,
    pub executed: u64,
    pub successful: u64,
    pub failed: u64,
    pub completed: bool,
    pub exit_code: i32,
    pub timed_out: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Boundary {
    Native,
    External,
    Empirical,
    UnsupportedModel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Substitute {
    Missing,
    Passed,
    Controlled,
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct AssessmentEvidence {
    pub current: bool,
    pub core_proved: bool,
    pub justified: bool,
    pub substitute: Substitute,
}

#[must_use]
pub fn assessed(boundary: Boundary, evidence: AssessmentEvidence) -> bool {
    evidence.current
        && evidence.core_proved
        && match boundary {
            Boundary::Native => true,
            Boundary::External | Boundary::UnsupportedModel => {
                evidence.justified && evidence.substitute != Substitute::Missing
            }
            Boundary::Empirical => {
                evidence.justified && evidence.substitute == Substitute::Controlled
            }
        }
}

#[must_use]
pub fn accepts(intent: Intent, completion: Completion, checks: &[Check]) -> bool {
    if !completion.completed
        || completion.timed_out
        || completion.total != 1
        || completion.executed != 1
        || checks.is_empty()
        || checks.contains(&Check::Rejected)
    {
        return false;
    }
    match intent {
        Intent::Prove => {
            completion.exit_code == 0
                && completion.successful == 1
                && completion.failed == 0
                && checks.contains(&Check::AssertionPassed)
                && checks.contains(&Check::CoverSatisfied)
                && !checks.contains(&Check::ExpectedRefutation)
        }
        Intent::Refute => {
            completion.exit_code == 1
                && completion.successful == 0
                && completion.failed == 1
                && checks
                    .iter()
                    .filter(|&&check| check == Check::ExpectedRefutation)
                    .count()
                    == 1
        }
    }
}
