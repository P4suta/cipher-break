// SPDX-License-Identifier: MIT OR Apache-2.0

#[path = "../xtask/src/proof_gate.rs"]
mod proof_gate;

#[path = "../xtask/src/agreement.rs"]
mod agreement;

use proof_gate::{AssessmentEvidence, Boundary, Check, Completion, Intent, Substitute, accepts, assessed};

fn completion() -> Completion {
    Completion {
        total: kani::any(),
        executed: kani::any(),
        successful: kani::any(),
        failed: kani::any(),
        completed: kani::any(),
        exit_code: kani::any(),
        timed_out: kani::any(),
    }
}

fn check() -> Check {
    match kani::any::<u8>() % 6 {
        0 => Check::Passed,
        1 => Check::AssertionPassed,
        2 => Check::CoverSatisfied,
        3 => Check::UnreachableSafety,
        4 => Check::ExpectedRefutation,
        _ => Check::Rejected,
    }
}

#[kani::proof]
#[kani::unwind(5)]
fn an_accepted_proof_excludes_missing_failed_and_vacuous_evidence() {
    let result = completion();
    let checks = [check(), check(), check()];
    let accepted = accepts(Intent::Prove, result, &checks);
    if accepted {
        assert!(result.completed && !result.timed_out);
        assert_eq!(result.total, 1);
        assert_eq!(result.executed, 1);
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.successful, 1);
        assert_eq!(result.failed, 0);
        assert!(checks.contains(&Check::AssertionPassed));
        assert!(checks.contains(&Check::CoverSatisfied));
        assert!(!checks.contains(&Check::ExpectedRefutation));
        assert!(!checks.contains(&Check::Rejected));
    }
    kani::cover!(accepted);
    kani::cover!(!accepted && result.timed_out);
    let broken = [
        Check::AssertionPassed,
        Check::CoverSatisfied,
        Check::Rejected,
    ];
    assert!(!accepts(Intent::Prove, result, &broken));
    assert!(!accepts(Intent::Prove, result, &[]));
    let boundary: Boundary = kani::any();
    let evidence: AssessmentEvidence = kani::any();
    let admitted = assessed(boundary, evidence);
    assert!(!admitted || evidence.current && evidence.core_proved);
    assert!(!admitted || boundary == Boundary::Native || evidence.justified && evidence.substitute != Substitute::Missing);
    assert!(!admitted || boundary != Boundary::Empirical || evidence.substitute == Substitute::Controlled);
    assert_eq!(assessed(Boundary::Native, evidence), evidence.current && evidence.core_proved);
    assert!(!assessed(boundary, AssessmentEvidence { current:false, ..evidence }));
    assert!(!assessed(boundary, AssessmentEvidence { core_proved:false, ..evidence }));
    kani::cover!(admitted && boundary == Boundary::Native);
    kani::cover!(admitted && boundary == Boundary::Empirical);
}

#[kani::proof]
#[kani::unwind(5)]
fn a_negative_control_requires_one_actual_expected_refutation() {
    let result = completion();
    let checks = [check(), check(), check()];
    let accepted = accepts(Intent::Refute, result, &checks);
    if accepted {
        assert!(result.completed && !result.timed_out);
        assert_eq!(result.total, 1);
        assert_eq!(result.executed, 1);
        assert_eq!(result.exit_code, 1);
        assert_eq!(result.successful, 0);
        assert_eq!(result.failed, 1);
        assert_eq!(
            checks
                .iter()
                .filter(|&&c| c == Check::ExpectedRefutation)
                .count(),
            1
        );
        assert!(!checks.contains(&Check::Rejected));
    }
    kani::cover!(accepted);
    kani::cover!(!accepted && result.exit_code == 101);
    let compiler_failure = [Check::Passed, Check::UnreachableSafety, Check::Rejected];
    assert!(!accepts(Intent::Refute, result, &compiler_failure));
}

#[kani::proof]
#[kani::unwind(7)]
fn both_implementations_must_report_the_known_fixture_ic() {
    let rust: Option<[u8; 6]> = kani::any();
    let reference: Option<[u8; 6]> = kani::any();
    let accepted = agreement::matches_fixture(rust, reference);
    if accepted {
        assert_eq!(rust, Some(*b"0.0438"));
        assert_eq!(reference, Some(*b"0.0438"));
    }
    assert!(rust != Some(*b"0.0438") || reference != Some(*b"0.0438") || accepted);
    kani::cover!(accepted);
    kani::cover!(!accepted && rust.is_none() && reference.is_some());
}
