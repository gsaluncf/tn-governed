//! Admission capacity: each governed session holds one active-session reservation while it runs.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::error::{AdmissionStage, TnLlamaError};

#[derive(Debug)]
struct ActiveSessions {
    max: usize,
    ids: HashSet<String>,
}

#[derive(Clone, Debug)]
pub struct AdmissionController {
    state: Arc<Mutex<ActiveSessions>>,
}

impl AdmissionController {
    #[must_use]
    pub fn new(max_active_sessions: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(ActiveSessions {
                max: max_active_sessions,
                ids: HashSet::new(),
            })),
        }
    }

    pub(crate) fn admit_governed(
        &self,
        request: crate::AcceptedGovernedRequest,
        session_id: &str,
    ) -> Result<AdmittedGovernedRequest, TnLlamaError> {
        let mut state = self.state.lock().map_err(|_| {
            TnLlamaError::new(
                "tn_admission_state_poisoned",
                AdmissionStage::Admission,
                "admission state lock is poisoned",
            )
        })?;
        if session_id.is_empty() || state.ids.contains(session_id) || state.ids.len() >= state.max {
            return Err(TnLlamaError::new(
                "tn_active_session_limit",
                AdmissionStage::Admission,
                "active session limit reached or session identity already reserved",
            ));
        }
        state.ids.insert(session_id.to_owned());
        Ok(AdmittedGovernedRequest {
            request,
            _reservation: ActiveSessionReservation {
                state: Arc::clone(&self.state),
                session_id: session_id.to_owned(),
            },
        })
    }

    #[must_use]
    pub fn active_sessions(&self) -> usize {
        lock_recover(&self.state).ids.len()
    }
}

/// An admitted request; dropping it releases its active-session capacity.
pub(crate) struct AdmittedGovernedRequest {
    pub request: crate::AcceptedGovernedRequest,
    _reservation: ActiveSessionReservation,
}

#[derive(Debug)]
struct ActiveSessionReservation {
    state: Arc<Mutex<ActiveSessions>>,
    session_id: String,
}

impl Drop for ActiveSessionReservation {
    fn drop(&mut self) {
        lock_recover(&self.state).ids.remove(&self.session_id);
    }
}

fn lock_recover(lock: &Mutex<ActiveSessions>) -> MutexGuard<'_, ActiveSessions> {
    lock.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
