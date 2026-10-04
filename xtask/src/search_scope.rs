// SPDX-License-Identifier: MIT OR Apache-2.0

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Scope {
    LocalLemma,
    MenuPropagation,
    RingTraces,
    CandidateRetention,
    GpuEquivalence,
    WorkerScheduling,
    ControllerLifecycle,
    InputValidation,
}

impl Scope {
    const fn bit(self) -> u8 {
        match self {
            Self::LocalLemma => 0,
            Self::MenuPropagation => 1,
            Self::RingTraces => 2,
            Self::CandidateRetention => 4,
            Self::GpuEquivalence => 8,
            Self::WorkerScheduling => 16,
            Self::ControllerLifecycle => 32,
            Self::InputValidation => 64,
        }
    }
}

pub const MAX_CASES: usize = 32;

pub const REQUIRED: [Scope; 7] = [
    Scope::MenuPropagation,
    Scope::RingTraces,
    Scope::CandidateRetention,
    Scope::GpuEquivalence,
    Scope::WorkerScheduling,
    Scope::ControllerLifecycle,
    Scope::InputValidation,
];

pub fn complete(scopes: &[Scope]) -> bool {
    let present = scopes.iter().fold(0, |bits, scope| bits | scope.bit());
    let required = REQUIRED.iter().fold(0, |bits, scope| bits | scope.bit());
    present == required
}
