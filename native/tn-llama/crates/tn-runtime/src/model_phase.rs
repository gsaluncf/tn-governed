#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Phase {
    /// Reserved wire identifier; the runtime admits governance without inference.
    GovernanceRead = 1,
    /// Reserved wire identifier; model results never serve as governance verification.
    CommitmentEcho = 2,
    SectionSelection = 3,
    GovernedAction = 4,
}

impl From<Phase> for u32 {
    fn from(phase: Phase) -> Self {
        phase as Self
    }
}

impl serde::Serialize for Phase {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32((*self).into())
    }
}
