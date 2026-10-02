// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::Write as _;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Clone, Debug)]
pub struct Event {
    pub stage: String,
    pub detail: String,
    pub at: f64,
}

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

pub static QUIET: std::sync::LazyLock<Trace> = std::sync::LazyLock::new(|| Trace::new(false));

impl Trace {
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Trace {
            enabled,
            started: Instant::now(),
            events: Mutex::new(Vec::new()),
        }
    }

    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

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

    #[must_use]
    pub fn events(&self) -> Vec<Event> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }

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
