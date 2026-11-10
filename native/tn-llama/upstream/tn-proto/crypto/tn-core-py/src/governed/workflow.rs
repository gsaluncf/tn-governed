//! Create, receive, and release entry points shared by `Session` and `Workflow`.
//!
//! Receipt and release take a complete use. A configured route or release plan,
//! named by its purpose, supplies one; the operation-only mode is native only.
use super::dataset::PyDatasetSelection;
use super::objects::{PyGovernance, PyObject};
use super::session::PySession;
use super::use_context::PyUseContext;
use super::{codec, guard, to_py, GovernedError};
#[allow(unused_imports)]
use super::data::*;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::sync::{Arc, MutexGuard};
use tn_core::governed::{DataObject, Governance, ReleaseContext, UseContext};
use tn_core::runtime::{Publication, ReleasePlan};

/// What one release publishes: its type, complete use, and destination.
pub(super) struct ReleaseTarget {
    object_type: Option<String>,
    use_context: UseContext,
    to: String,
}

impl ReleaseTarget {
    /// The type, use, and destination a configured plan fixes.
    pub(super) fn planned(plan: &ReleasePlan) -> Self {
        Self {
            object_type: Some(plan.object_type().to_owned()),
            use_context: plan.use_context().clone(),
            to: plan.destination().to_owned(),
        }
    }
}

pub(super) fn release(
    publisher: &PySession,
    data: &PyData,
    py: Python<'_>,
    use_context: Option<&PyUseContext>,
    purpose: Option<&str>,
    to: Option<&str>,
    decide: Option<&Bound<'_, PyAny>>,
    object_type: Option<&str>,
) -> PyResult<PyObject> {
    guard(|| {
        release_requested(data, py, &publisher.context, purpose, use_context, to, decide, object_type)
    })
}

/// A configured release names its plan by purpose and may add a decision; an
/// explicit release gives the complete use, the destination, and the decision.
pub(super) fn release_requested(
    data: &PyData,
    py: Python<'_>,
    publisher: &SessionState,
    purpose: Option<&str>,
    r#use: Option<&PyUseContext>,
    to: Option<&str>,
    decide: Option<&Bound<'_, PyAny>>,
    object_type: Option<&str>,
) -> PyResult<PyObject> {
    let Some(to) = to else {
        if r#use.is_some() || object_type.is_some() {
            return Err(PyTypeError::new_err(
                "configured release takes purpose; explicit use/type requires to and decide",
            ));
        }
        let purpose = purpose.ok_or_else(|| PyTypeError::new_err("release requires purpose"))?;
        let plan = session(publisher)?.release_plan(purpose).map_err(to_py)?;
        return release_data(data, py, publisher, ReleaseTarget::planned(&plan), Some(plan), decide);
    };
    if purpose.is_some() {
        return Err(PyTypeError::new_err("explicit release takes use, not purpose"));
    }
    let (Some(use_context), Some(decide)) = (r#use, decide) else {
        return Err(PyTypeError::new_err("explicit release requires use and decide"));
    };
    let target = ReleaseTarget {
        object_type: object_type.map(str::to_owned),
        use_context: use_context.inner.clone(),
        to: to.to_owned(),
    };
    release_data(data, py, publisher, target, None, Some(decide))
}

/// Sign `data`'s successor under `target`. No object lock is held while
/// application code decides; once the decision holds, the object stays locked,
/// unchanged since the decision began, until the signed successor is installed.
pub(super) fn release_data(
    data: &PyData,
    py: Python<'_>,
    publisher: &SessionState,
    target: ReleaseTarget,
    plan: Option<Arc<ReleasePlan>>,
    decide: Option<&Bound<'_, PyAny>>,
) -> PyResult<PyObject> {
    let context = session(publisher)?;
    let mut candidate = data.read()?;
    let revision = candidate.revision();
    let object_type = target
        .object_type
        .unwrap_or_else(|| candidate.object_type().to_owned());
    let callback = decide.map(|value| value.clone().unbind());
    let (result, error) = py.allow_threads(|| {
        let mut decision = ReleaseDecision {
            data,
            publisher,
            plan: plan.as_deref(),
            callback: callback.as_ref(),
            revision,
            error: None,
            accepted: None,
        };
        let result = context.release_for(
            &mut candidate,
            &object_type,
            &target.use_context,
            &target.to,
            |native| decision.decide(native),
        );
        if result.is_ok() {
            if let Some(mut accepted) = decision.accepted.take() {
                *accepted = candidate;
            }
        }
        (result, decision.error)
    });
    if let Some(error) = error {
        return Err(error);
    }
    result.map(|inner| PyObject { inner }).map_err(to_py)
}

/// The plan's authority, then the Python decision; an accepted release keeps the object locked.
struct ReleaseDecision<'a> {
    data: &'a PyData,
    publisher: &'a SessionState,
    plan: Option<&'a ReleasePlan>,
    callback: Option<&'a Py<PyAny>>,
    revision: u64,
    error: Option<PyErr>,
    accepted: Option<MutexGuard<'a, DataObject>>,
}

impl ReleaseDecision<'_> {
    fn decide(&mut self, native: &ReleaseContext<'_>) -> tn_core::Result<bool> {
        if let Some(plan) = self.plan {
            if !plan.authorize(native)? {
                return Ok(false);
            }
        }
        let (data, publisher, callback, revision) = (self.data, self.publisher, self.callback, self.revision);
        let accepted = &mut self.accepted;
        native_decision(&mut self.error, || {
            let allow = Python::with_gil(|py| {
                let allow = match callback {
                    Some(callback) => decision(
                        callback.bind(py),
                        Py::new(py, PyRelease::from_native(native))?.into_any(),
                    )?,
                    None => true,
                };
                session(publisher)?;
                Ok::<_, PyErr>(allow)
            })?;
            if allow {
                let current = data
                    .inner
                    .lock()
                    .map_err(|_| GovernedError::new_err("data lock poisoned"))?;
                if current.revision() != revision {
                    return Err(GovernedError::new_err(
                        "object changed during governance decision; evaluate its current state again",
                    ));
                }
                *accepted = Some(current);
            }
            Ok(allow)
        })
    }
}

pub(super) fn create(
    session: &PySession,
    py: Python<'_>,
    fields: &Bound<'_, PyDict>,
    policy: &PyGovernance,
    object_type: Option<&str>,
    group: &str,
) -> PyResult<PyData> {
    guard(|| {
        let context = session.context()?;
        let fields = codec::fields(fields)?;
        let policy = policy.inner.clone();
        let inner = py
            .allow_threads(|| match object_type {
                Some(name) => context.objects().create_obj(name, policy, group, fields),
                None if group == "default" => context.create(fields, policy),
                None => context.create_selected(fields, policy, group),
            })
            .map_err(to_py)?;
        Ok(PyData::new(
            inner,
            session.context.clone(),
            group.to_owned(),
        ))
    })
}
pub(super) fn create_with_groups(
    session: &PySession,
    py: Python<'_>,
    groups: &Bound<'_, PyDict>,
    policy: &PyGovernance,
    object_type: Option<&str>,
    primary_group: &str,
) -> PyResult<PyData> {
    guard(|| {
        let context = session.context()?;
        let groups = codec::fields(groups)?;
        if !groups.contains_key(primary_group) {
            return Err(PyValueError::new_err(
                "primary_group must name a supplied business group",
            ));
        }
        let policy = policy.inner.clone();
        let inner = py
            .allow_threads(|| match object_type {
                Some(name) => context.create_obj_with_groups(name, policy, groups),
                None => context.create_selected_groups(groups, policy),
            })
            .map_err(to_py)?;
        Ok(PyData::new(
            inner,
            session.context.clone(),
            primary_group.to_owned(),
        ))
    })
}
/// The verified object behind a working copy, an object, or exact wire text.
/// Only text is parsed, once, here; an object is never re-serialized and parsed again.
pub(super) fn publication_object(source: &Bound<'_, PyAny>) -> PyResult<tn_core::governed::GovernedObject> {
    if let Ok(data) = source.extract::<PyRef<'_, PyData>>() {
        let current = data.read()?;
        return current.publication().map(Clone::clone).map_err(to_py);
    }
    if let Ok(object) = source.extract::<PyRef<'_, PyObject>>() {
        return Ok(object.inner.clone());
    }
    tn_core::governed::GovernedObject::parse(&codec::wire(source)?).map_err(to_py)
}

/// No selection, one, or a sequence of them; each pins the object it selects.
pub(super) fn selections(value: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<tn_core::governed::DatasetSelection>> {
    let Some(value) = value.filter(|value| !value.is_none()) else {
        return Ok(Vec::new());
    };
    if let Ok(one) = value.extract::<PyRef<'_, PyDatasetSelection>>() {
        return Ok(vec![one.inner.clone()]);
    }
    value
        .try_iter()?
        .map(|item| Ok(item?.extract::<PyRef<'_, PyDatasetSelection>>()?.inner.clone()))
        .collect()
}

/// Strict receipt: verify, ask every object on the route under the complete use, then open.
pub(super) fn receive(
    session: &PySession,
    py: Python<'_>,
    source: &Bound<'_, PyAny>,
    use_context: &PyUseContext,
    groups: Vec<String>,
    selection: Option<&Bound<'_, PyAny>>,
    decide: &Bound<'_, PyAny>,
) -> PyResult<PyData> {
    guard(|| {
        let context = session.context()?;
        let object = publication_object(source)?;
        let selection = selections(selection)?;
        let use_context = use_context.inner.clone();
        let default_group = primary(&groups);
        let inner = with_admission(session, py, decide, |decide_native| {
            context.receive_for(&object, &use_context, &groups, &selection, decide_native)
        })?;
        Ok(PyData::new(inner, session.context.clone(), default_group))
    })
}

/// A strict receipt every object on its route accepted, not yet opened. Receiving
/// it under the same session asks each object again, then opens without parsing
/// the source or decrypting any governance again.
#[pyclass(frozen, module = "tn.governed", name = "AdmittedRoute")]
pub(super) struct PyAdmittedRoute {
    pub(super) inner: Arc<tn_core::governed::AdmittedRoute>,
    policies: Vec<Governance>,
    default_group: String,
}
#[pymethods]
impl PyAdmittedRoute {
    /// The policies the received working copy holds.
    #[getter]
    fn policies(&self) -> Vec<PyGovernance> {
        self.policies.iter().cloned().map(|inner| PyGovernance { inner }).collect()
    }
    /// The received object.
    #[getter]
    fn object(&self) -> PyObject {
        let (direct, _) = self.inner.stops().next().expect("a route starts at its source");
        PyObject { inner: direct.object().clone() }
    }
}

/// Decide a strict receipt without opening anything: the same route, selections,
/// and acceptances as `receive`, needing no group key.
pub(super) fn admit(
    session: &PySession,
    py: Python<'_>,
    source: &Bound<'_, PyAny>,
    use_context: &PyUseContext,
    groups: Vec<String>,
    selection: Option<&Bound<'_, PyAny>>,
    decide: &Bound<'_, PyAny>,
) -> PyResult<PyAdmittedRoute> {
    guard(|| {
        let reader = session.cached_reader()?;
        let object = publication_object(source)?;
        let selection = selections(selection)?;
        let use_context = use_context.inner.clone();
        let default_group = primary(&groups);
        let route = with_admission(session, py, decide, |decide_native| {
            reader.admit_route(&object, &use_context, &groups, &selection, decide_native)
        })?;
        let policies = route.policies().map_err(to_py)?;
        Ok(PyAdmittedRoute { inner: Arc::new(route), policies, default_group })
    })
}

/// Open a route this session admitted, after each object on it confirms again.
pub(super) fn receive_admitted(
    session: &PySession,
    py: Python<'_>,
    admitted: &PyAdmittedRoute,
    decide: &Bound<'_, PyAny>,
) -> PyResult<PyData> {
    guard(|| {
        let reader = session.cached_reader()?;
        let route = Arc::clone(&admitted.inner);
        let inner = with_admission(session, py, decide, |decide_native| {
            reader.receive_admitted(&route, decide_native)
        })?;
        Ok(PyData::new(inner, session.context.clone(), admitted.default_group.clone()))
    })
}

fn primary(groups: &[String]) -> String {
    groups.first().cloned().unwrap_or_else(|| "default".to_owned())
}

/// Run `native` with the Python `decide` callback as its admission decision. An
/// exception the callback raises is returned instead of the native refusal.
pub(super) fn with_admission<T: Send>(
    session: &PySession,
    py: Python<'_>,
    decide: &Bound<'_, PyAny>,
    native: impl FnOnce(
            &mut dyn FnMut(&tn_core::governed::AdmissionContext<'_>) -> tn_core::Result<bool>,
        ) -> tn_core::Result<T>
        + Send,
) -> PyResult<T> {
    let callback = decide.clone().unbind();
    let mut callback_error = None;
    let result = py.allow_threads(|| {
        let mut decide_native = |context: &tn_core::governed::AdmissionContext<'_>| {
            native_decision(&mut callback_error, || {
                Python::with_gil(|py| {
                    let allow = decision(
                        callback.bind(py),
                        Py::new(py, PyAdmission::from_native(context))?.into_any(),
                    )?;
                    session.context()?;
                    Ok(allow)
                })
            })
        };
        native(&mut decide_native)
    });
    if let Some(error) = callback_error {
        return Err(error);
    }
    result.map_err(to_py)
}
pub(super) fn receive_configured(
    session: &PySession,
    py: Python<'_>,
    source: &Bound<'_, PyAny>,
    purpose: &str,
    selection: Option<&Bound<'_, PyAny>>,
) -> PyResult<PyData> {
    guard(|| {
        let context = session.context()?;
        let object = publication_object(source)?;
        let selection = selections(selection)?;
        let inner = py
            .allow_threads(|| context.receive_selected(&object, purpose, &selection))
            .map_err(to_py)?;
        let primary = context
            .primary_group(purpose, object.object_type())
            .map_err(to_py)?;
        Ok(PyData::new(inner, session.context.clone(), primary))
    })
}
/// Python owns a native workflow and the originating session lifecycle.
#[pyclass(frozen, module = "tn.governed", name = "Workflow")]
pub(super) struct PyWorkflow {
    pub(super) native: Arc<tn_core::runtime::Workflow<'static>>,
    pub(super) state: SessionState,
}
impl PyWorkflow {
    pub(super) fn bind(owner: &PySession, receive: &str, release: &str) -> PyResult<Self> {
        Ok(Self {
            native: Arc::new(owner.context()?.workflow(receive, release).map_err(to_py)?),
            state: owner.context.clone(),
        })
    }
}
#[pymethods]
impl PyWorkflow {
    #[pyo3(signature = (source, *, selection=None))]
    fn receive(
        &self,
        py: Python<'_>,
        source: &Bound<'_, PyAny>,
        selection: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<PyData> {
        guard(|| {
            session(&self.state)?;
            let object = publication_object(source)?;
            let selection = selections(selection)?;
            let inner = py
                .allow_threads(|| self.native.receive_selected(&object, &selection))
                .map_err(to_py)?;
            session(&self.state)?;
            let primary = self
                .native
                .primary_group(object.object_type())
                .map_err(to_py)?
                .to_owned();
            Ok(PyData::new(inner, self.state.clone(), primary))
        })
    }
    fn attach(&self, py: Python<'_>, data: &PyData, policy: &PyGovernance) -> PyResult<()> {
        guard(|| {
            session(&self.state)?;
            let mut candidate = data.read()?;
            let revision = candidate.revision();
            py.allow_threads(|| self.native.attach(&mut candidate, policy.inner.clone()))
                .map_err(to_py)?;
            session(&self.state)?;
            data.checked(revision, |current| {
                *current = candidate;
                Ok(())
            })
        })
    }
    #[pyo3(signature = (data, *, decide=None))]
    fn release(
        &self,
        py: Python<'_>,
        data: &PyData,
        decide: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<PyObject> {
        guard(|| {
            let plan = self.native.release_plan();
            release_data(data, py, &self.state, ReleaseTarget::planned(&plan), Some(plan), decide)
        })
    }
}
