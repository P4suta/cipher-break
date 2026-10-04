// SPDX-License-Identifier: MIT OR Apache-2.0

#[path = "../xtask/src/completion.rs"]
mod completion;

#[kani::proof]
#[kani::unwind(6)]
fn cleanup_records_are_attempted_before_returning_the_first_failure() {
    let results: [Result<(), u8>; 4] = std::array::from_fn(|_| kani::any());
    let recorded: Result<(), u8> = kani::any();
    let expected = recorded.and(
        results
            .iter()
            .find(|result| result.is_err())
            .copied()
            .unwrap_or(Ok(())),
    );
    let mut calls = 0;
    let actual = completion::persist(results, || {
        calls += 1;
        recorded
    });
    assert_eq!(calls, 1);
    assert_eq!(actual, expected);
    kani::cover!(recorded.is_err());
    kani::cover!(recorded.is_ok() && results[0].is_err() && results[1].is_err());
    kani::cover!(recorded.is_ok() && results[0].is_ok() && results[1].is_err());
    kani::cover!(recorded.is_ok() && results[..3].iter().all(Result::is_ok) && results[3].is_err());
    kani::cover!(recorded.is_ok() && results.iter().all(Result::is_ok));
}
