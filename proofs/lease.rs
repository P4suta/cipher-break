// SPDX-License-Identifier: MIT OR Apache-2.0

#[path = "../xtask/src/lease.rs"]
mod lease;

use std::cell::Cell;

struct Backend<'a> {
    held: &'a Cell<bool>,
    attempts: &'a Cell<u8>,
    releases: &'a Cell<u8>,
    grant: bool,
    release_succeeds: bool,
}

impl lease::Backend for Backend<'_> {
    type Error = ();

    fn acquire(&self) -> Result<(), Self::Error> {
        self.attempts.set(self.attempts.get() + 1);
        if self.grant && !self.held.get() {
            self.held.set(true);
            Ok(())
        } else {
            Err(())
        }
    }

    fn release(&self) {
        self.releases.set(self.releases.get() + 1);
        if self.release_succeeds {
            self.held.set(false);
        }
    }
}

#[kani::proof]
fn ownership_releases_exactly_once_and_failed_acquisition_never_releases() {
    let initial: bool = kani::any();
    let grant: bool = kani::any();
    let release_succeeds: bool = kani::any();
    let held = Cell::new(initial);
    let attempts = Cell::new(0);
    let releases = Cell::new(0);
    let backend = |grant| Backend {
        held: &held,
        attempts: &attempts,
        releases: &releases,
        grant,
        release_succeeds,
    };
    let result = lease::Lease::acquire(backend(grant));
    let accepted = result.is_ok();
    assert_eq!(accepted, grant && !initial);
    assert_eq!(attempts.get(), 1);
    if let Ok(owner) = result {
        assert!(held.get());
        assert_eq!(releases.get(), 0);
        assert!(lease::Lease::acquire(backend(true)).is_err());
        assert_eq!(attempts.get(), 2);
        assert_eq!(releases.get(), 0);
        drop(owner);
        assert_eq!(releases.get(), 1);
        assert_eq!(held.get(), !release_succeeds);
    } else {
        assert_eq!(releases.get(), 0);
        assert_eq!(held.get(), initial);
    }
    kani::cover!(initial && !accepted);
    kani::cover!(accepted && release_succeeds);
    kani::cover!(accepted && !release_succeeds);
    kani::cover!(!initial && !grant && !accepted);
}
