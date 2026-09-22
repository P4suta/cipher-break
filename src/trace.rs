// SPDX-License-Identifier: MIT OR Apache-2.0

//! What each stage of an attack did, recorded while it does it.
//!
//! An attack that returns the wrong answer has several places the answer could have been lost, and guessing between them is how an afternoon disappears.
//! This module exists because that happened here three times: the rotor sweep was blamed when the plugboard stage was at fault, the plugboard kernel was blamed when the ranking was at fault, and a planted test was blamed when the test itself was outside the search space.
//!
//! Each of those was settled by writing a throwaway diagnostic.
//! A trace is the same information, kept, and available from the command line rather than from a new test each time.
//!
//! It is free when off: a disabled trace takes a reference and returns.

use std::fmt::Write as _;
use std::sync::Mutex;
use std::time::Instant;

/// One thing that happened.
#[derive(Clone, Debug)]
pub struct Event {
    /// Which stage of which attack.
    pub stage: String,
    /// What happened, in words.
    pub detail: String,
    /// Seconds since the trace began.
    pub at: f64,
}

/// A record of an attack's progress.
///
/// Shared across the threads an attack runs on, so the lock is held only long enough to push, and never while anything is computed.
pub struct Trace {
    enabled: bool,
    started: Instant,
    events: Mutex<Vec<Event>>,
}

impl Default for Trace {
    fn default() -> Self {
        Trace::new(false)
    }
}

/// A trace that records nothing, for the runs that should not be traced.
///
/// The nulls are run with this: they repeat the whole attack on shuffled text and would bury the real run's events in copies of themselves.
pub static QUIET: std::sync::LazyLock<Trace> = std::sync::LazyLock::new(|| Trace::new(false));

impl Trace {
    /// A trace that records, or one that does not.
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Trace {
            enabled,
            started: Instant::now(),
            events: Mutex::new(Vec::new()),
        }
    }

    /// Whether anything is being recorded.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Record something.
    ///
    /// Takes the detail as a closure so that a disabled trace costs nothing but the call — the formatting never happens.
    pub fn note<F, S>(&self, stage: &str, detail: F)
    where
        F: FnOnce() -> S,
        S: Into<String>,
    {
        if !self.enabled {
            return;
        }
        let event = Event {
            stage: stage.to_string(),
            detail: detail().into(),
            at: self.started.elapsed().as_secs_f64(),
        };
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }

    /// Everything recorded so far.
    #[must_use]
    pub fn events(&self) -> Vec<Event> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }

    /// The trace as a table.
    #[must_use]
    pub fn render(&self) -> String {
        let events = self.events();
        if events.is_empty() {
            return String::new();
        }
        let width = events.iter().map(|e| e.stage.len()).max().unwrap_or(0);
        let mut out = String::new();
        for e in &events {
            let _ = writeln!(out, "  {:>7.3}s  {:<width$}  {}", e.at, e.stage, e.detail);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disabled_trace_records_nothing() {
        let trace = Trace::new(false);
        trace.note("stage", || "something");
        assert!(trace.events().is_empty());
        assert!(trace.render().is_empty());
    }

    #[test]
    fn an_enabled_trace_keeps_what_it_is_told() {
        let trace = Trace::new(true);
        trace.note("sweep", || "kept 400");
        trace.note("climb", || "best -9.5");
        let events = trace.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].stage, "sweep");
        assert!(trace.render().contains("kept 400"));
    }

    #[test]
    fn a_disabled_trace_does_not_run_its_closure() {
        let trace = Trace::new(false);
        let mut ran = false;
        trace.note("stage", || {
            ran = true;
            "x"
        });
        assert!(!ran, "the detail closure should not have run");
    }

    #[test]
    fn events_carry_a_time() {
        let trace = Trace::new(true);
        trace.note("a", || "first");
        assert!(trace.events()[0].at >= 0.0);
    }
}
