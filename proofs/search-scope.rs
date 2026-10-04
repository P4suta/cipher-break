// SPDX-License-Identifier: MIT OR Apache-2.0

#[path = "../xtask/src/search_scope.rs"]
mod search_scope;

use search_scope::{MAX_CASES, Scope, complete};

#[kani::proof]
#[kani::unwind(33)]
fn local_lemmas_cannot_replace_a_required_search_contract() {
    let entries: [Scope; MAX_CASES] = kani::any();
    let length: usize = kani::any();
    kani::assume(length <= MAX_CASES);
    let scopes = &entries[..length];
    let accepted = complete(scopes);
    let required: Scope = kani::any();
    if required != Scope::LocalLemma {
        assert!(scopes.contains(&required) || !accepted);
    }
    assert!(!complete(&[]));
    assert!(!complete(&[Scope::LocalLemma; MAX_CASES]));
    kani::cover!(accepted);
    kani::cover!(!accepted && scopes.contains(&Scope::LocalLemma));
}
