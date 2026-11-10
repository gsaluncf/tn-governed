//! Mutable governed data bound to a session; Python callbacks see detached snapshots.
use super::dataset::PyDatasetBinding;
use super::objects::{PyGovernance, PyObject};
use super::use_context::PyUseContext;
use super::{codec, guard, to_py, GovernedError, SessionClosed};
pub(super) use super::contexts::*;
pub(super) use super::workflow::*;
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use serde_json::Value;
use std::sync::{Arc, Mutex, MutexGuard};
use tn_core::governed::{DataObject, Inclusion};
use tn_core::runtime::{Publication, Session};

pub(super) type SessionState = Arc<Mutex<Option<Arc<Session<'static>>>>>;

pub(super) fn session(state: &SessionState) -> PyResult<Arc<Session<'static>>> {
    state
        .lock()
        .map_err(|_| GovernedError::new_err("session lock poisoned"))?
        .clone()
        .ok_or_else(|| SessionClosed::new_err("this governed session is closed"))
}
pub(super) fn path(value: &Bound<'_, PyAny>) -> PyResult<Vec<Value>> {
    json_list(value, "data path requires a list or tuple")
}
/// A Python list or tuple as JSON values; anything else is a `TypeError`.
fn json_list(value: &Bound<'_, PyAny>, refusal: &'static str) -> PyResult<Vec<Value>> {
    match codec::to_json(value, 0)? {
        Value::Array(items) => Ok(items),
        _ => Err(PyTypeError::new_err(refusal)),
    }
}
/// `tn.governed._views.view`, looked up once per interpreter.
fn views(py: Python<'_>) -> PyResult<&Bound<'_, PyAny>> {
    static VIEW: pyo3::sync::GILOnceCell<Py<PyAny>> = pyo3::sync::GILOnceCell::new();
    VIEW.get_or_try_init(py, || Ok::<_, PyErr>(py.import("tn.governed._views")?.getattr("view")?.unbind()))
        .map(|view| view.bind(py))
}
#[pyclass(frozen, module = "tn.governed", name = "DataObject")]
pub(super) struct PyData {
    pub(super) inner: Arc<Mutex<DataObject>>,
    pub(super) session: SessionState,
    pub(super) default_group: String,
}
impl PyData {
    pub(super) fn new(inner: DataObject, session: SessionState, default_group: String) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
            session,
            default_group,
        }
    }
    /// Borrow the object for one statement. Python code must not run under this lock.
    fn locked(&self) -> PyResult<MutexGuard<'_, DataObject>> {
        self.inner.try_lock().map_err(|_| {
            GovernedError::new_err("object is busy publishing or its data lock is poisoned")
        })
    }
    pub(super) fn read(&self) -> PyResult<DataObject> {
        self.inner.try_lock().map(|v| v.clone()).map_err(|_| {
            GovernedError::new_err("object is busy publishing or its data lock is poisoned")
        })
    }
    fn inclusion(&self) -> PyResult<Inclusion> {
        self.locked()?.inclusion().map_err(to_py)
    }
    fn mutate<T>(&self, f: impl FnOnce(&mut DataObject) -> tn_core::Result<T>) -> PyResult<T> {
        let mut data = self.inner.try_lock().map_err(|_| {
            GovernedError::new_err("object is busy publishing or its data lock is poisoned")
        })?;
        f(&mut data).map_err(to_py)
    }
    pub(super) fn checked<T>(
        &self,
        revision: u64,
        f: impl FnOnce(&mut DataObject) -> tn_core::Result<T>,
    ) -> PyResult<T> {
        let mut data = self.inner.try_lock().map_err(|_| {
            GovernedError::new_err("object is busy publishing or its data lock is poisoned")
        })?;
        if data.revision() != revision {
            return Err(GovernedError::new_err(
                "object changed during governance decision; evaluate its current state again",
            ));
        }
        f(&mut data).map_err(to_py)
    }

}
#[pymethods]
impl PyData {
    fn inspect(&self) -> PyResult<PyDataState> {
        guard(|| {
            Ok(PyDataState {
                inner: self.locked()?.inspect(),
            })
        })
    }
    #[pyo3(signature = (name=None, *, group=None))]
    fn get<'py>(
        &self,
        py: Python<'py>,
        name: Option<&str>,
        group: Option<&str>,
    ) -> PyResult<Bound<'py, PyAny>> {
        guard(|| {
            let value = self
                .locked()?
                .get(group.unwrap_or(&self.default_group), name)
                .map_err(to_py)?;
            codec::to_python(py, &value)
        })
    }
    #[pyo3(signature = (name, value, *, group=None))]
    fn set(
        &self,
        name: Option<&str>,
        value: &Bound<'_, PyAny>,
        group: Option<&str>,
    ) -> PyResult<()> {
        guard(|| {
            let value = codec::to_json(value, 0)?;
            self.mutate(|data| data.set(group.unwrap_or(&self.default_group), name, value))
        })
    }
    #[pyo3(signature = (groups, *, fields=None))]
    fn select(
        &self,
        groups: Vec<String>,
        fields: Option<std::collections::BTreeMap<String, Vec<String>>>,
    ) -> PyResult<()> {
        guard(|| self.mutate(|data| data.select(groups, fields.as_ref())))
    }
    fn forward<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, pyo3::types::PyBytes>> {
        guard(|| {
            Ok(pyo3::types::PyBytes::new(
                py,
                self.locked()?.forward().map_err(to_py)?,
            ))
        })
    }
    fn write(&self, py: Python<'_>, destination: &Bound<'_, PyAny>) -> PyResult<()> {
        guard(|| {
            let data = self.read()?;
            let publication = data.publication().map_err(to_py)?;
            super::objects::write_publication(py, publication, destination)
        })
    }
    fn copy(&self) -> PyResult<Self> {
        guard(|| {
            Ok(Self::new(
                self.read()?,
                self.session.clone(),
                self.default_group.clone(),
            ))
        })
    }
    /// Make a fresh working value in this session, under all the inputs' rules.
    /// The caller supplies the output fields; no input values or publications are copied.
    #[pyo3(signature = (object_type, groups, *, inputs=None, primary_group=None))]
    fn policy_output(
        &self,
        object_type: &str,
        groups: &Bound<'_, pyo3::types::PyDict>,
        inputs: Option<Vec<PyRef<'_, Self>>>,
        primary_group: Option<&str>,
    ) -> PyResult<Self> {
        guard(|| {
            session(&self.session)?;
            let groups = codec::fields(groups)?;
            let default = primary_group.or_else(|| {
                if groups.contains_key(&self.default_group) {
                    Some(self.default_group.as_str())
                } else {
                    groups.keys().next().map(String::as_str)
                }
            }).filter(|name| groups.contains_key(*name))
              .ok_or_else(|| PyTypeError::new_err("primary_group must name an output group"))?
              .to_owned();
            let additional = inputs.unwrap_or_default().iter()
                .map(|input| Ok(input.locked()?.governance().clone()))
                .collect::<PyResult<Vec<_>>>()?;
            let policy = self.locked()?.governance().for_output(&additional).map_err(to_py)?;
            let inner = DataObject::new_with_groups(object_type, policy, groups).map_err(to_py)?;
            Ok(Self::new(inner, self.session.clone(), default))
        })
    }
    #[getter]
    fn dataset_bindings(&self) -> PyResult<Vec<PyDatasetBinding>> {
        dataset_bindings(&*self.locked()?)
    }
    fn retain_groups(&self, groups: Vec<String>) -> PyResult<()> {
        guard(|| self.mutate(|data| data.retain_groups(groups)))
    }
    /// Name the opened group every data group of the next release is bound to.
    fn bind_manifest(&self, group: &str) -> PyResult<()> {
        guard(|| self.mutate(|data| data.set_manifest(group)))
    }
    #[getter]
    fn manifest(&self) -> PyResult<Option<String>> {
        Ok(self.locked()?.manifest().map(str::to_owned))
    }
    #[getter]
    fn object_type(&self) -> PyResult<String> {
        Ok(self.locked()?.object_type().to_owned())
    }
    #[getter]
    fn governance(&self) -> PyResult<PyGovernance> {
        Ok(PyGovernance {
            inner: self.locked()?.governance().clone(),
        })
    }
    #[getter]
    fn policies(&self) -> PyResult<Vec<PyGovernance>> {
        policies(&*self.locked()?)
    }
    #[getter]
    fn sources(&self) -> PyResult<Vec<PySource>> {
        Ok(sources(&*self.locked()?))
    }
    #[getter]
    fn history(&self) -> PyResult<Vec<PyObject>> {
        Ok(self
            .locked()?
            .history()
            .iter()
            .cloned()
            .map(|inner| PyObject { inner })
            .collect())
    }
    #[getter]
    fn snapshot(&self) -> PyResult<PyObject> {
        self.locked()?
            .snapshot()
            .cloned()
            .map(|inner| PyObject { inner })
            .ok_or_else(|| {
                GovernedError::new_err("created or received object requires its signed snapshot")
            })
    }
    #[getter]
    fn hidden_groups(&self) -> PyResult<Vec<String>> {
        Ok(hidden_groups(&*self.locked()?))
    }
    #[getter]
    fn register_error(&self) -> PyResult<Option<String>> {
        Ok(self.locked()?.register_error().map(str::to_owned))
    }
    #[getter]
    fn revision(&self) -> PyResult<u64> {
        Ok(self.locked()?.revision())
    }
    #[getter]
    fn has_unreleased_changes(&self) -> PyResult<bool> {
        Ok(self.locked()?.has_unreleased_changes())
    }
    #[getter]
    fn state(&self) -> PyResult<PyDataState> {
        Ok(PyDataState {
            inner: self.read()?,
        })
    }
    #[getter]
    fn groups(slf: PyRef<'_, Self>) -> PyResult<Bound<'_, PyAny>> {
        let py = slf.py();
        views(py)?.call1((slf, Vec::<String>::new()))
    }
    #[getter]
    fn data(slf: PyRef<'_, Self>) -> PyResult<Bound<'_, PyAny>> {
        let py = slf.py();
        let name = slf.default_group.clone();
        views(py)?.call1((slf, vec![name]))
    }
    fn _get<'py>(&self, py: Python<'py>, keys: &Bound<'_, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        guard(|| {
            let value = self.locked()?.get_path(&path(keys)?).map_err(to_py)?;
            codec::to_python(py, &value)
        })
    }
    fn _set(&self, keys: &Bound<'_, PyAny>, value: &Bound<'_, PyAny>) -> PyResult<()> {
        guard(|| {
            let keys = path(keys)?;
            let value = codec::to_json(value, 0)?;
            self.mutate(|data| data.set_path(&keys, value))
        })
    }
    fn _delete(&self, keys: &Bound<'_, PyAny>) -> PyResult<()> {
        guard(|| {
            let keys = path(keys)?;
            self.mutate(|data| data.delete_path(&keys))
        })
    }
    fn _append(&self, keys: &Bound<'_, PyAny>, value: &Bound<'_, PyAny>) -> PyResult<()> {
        guard(|| {
            let keys = path(keys)?;
            let value = codec::to_json(value, 0)?;
            self.mutate(|data| data.append_path(&keys, value))
        })
    }
    fn _insert(&self, keys: &Bound<'_, PyAny>, index: isize, value: &Bound<'_, PyAny>) -> PyResult<()> {
        guard(|| {
            let keys = path(keys)?;
            let value = codec::to_json(value, 0)?;
            self.mutate(|data| data.insert_path(&keys, index, value))
        })
    }
    fn _take<'py>(&self, py: Python<'py>, keys: &Bound<'_, PyAny>) -> PyResult<Bound<'py, PyAny>> {
        guard(|| {
            let keys = path(keys)?;
            let value = self.mutate(|data| data.take_path(&keys))?;
            codec::to_python(py, &value)
        })
    }
    fn _reverse(&self, keys: &Bound<'_, PyAny>) -> PyResult<()> {
        guard(|| {
            let keys = path(keys)?;
            self.mutate(|data| data.reverse_path(&keys))
        })
    }
    fn _extend(&self, keys: &Bound<'_, PyAny>, values: &Bound<'_, PyAny>) -> PyResult<()> {
        guard(|| {
            let keys = path(keys)?;
            let values = json_list(values, "extend requires an array")?;
            self.mutate(|data| data.extend_path(&keys, values))
        })
    }
    /// Python slice assignment or deletion; the native operation owns every index rule.
    #[pyo3(signature=(keys, start, stop, step, values, delete))]
    fn _slice(
        &self,
        keys: &Bound<'_, PyAny>,
        start: Option<isize>,
        stop: Option<isize>,
        step: isize,
        values: &Bound<'_, PyAny>,
        delete: bool,
    ) -> PyResult<()> {
        guard(|| {
            let keys = path(keys)?;
            let values = json_list(values, "slice assignment requires an array")?;
            self.mutate(|data| data.slice_path(&keys, start, stop, step, values, delete))
        })
    }
    fn include(&self, other: &Self) -> PyResult<()> {
        guard(|| {
            let other = other.inclusion()?;
            self.mutate(|data| data.include_all([other]))
        })
    }
    /// Include several inputs with one merge over their references.
    fn include_all(&self, others: Vec<PyRef<'_, Self>>) -> PyResult<()> {
        guard(|| {
            let inputs = others
                .iter()
                .map(|other| other.inclusion())
                .collect::<PyResult<Vec<_>>>()?;
            self.mutate(|data| data.include_all(inputs))
        })
    }
    #[pyo3(signature=(policy, *, decide=None))]
    fn attach(
        &self,
        py: Python<'_>,
        policy: &PyGovernance,
        decide: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        guard(|| {
            let context = session(&self.session)?;
            let before = self.read()?;
            let revision = before.revision();
            let policy = policy.inner.clone();
            if decide.is_none() {
                let mut candidate = before;
                py.allow_threads(|| context.attach(&mut candidate, policy))
                    .map_err(to_py)?;
                session(&self.session)?;
                return self.checked(revision, |data| {
                    *data = candidate;
                    Ok(())
                });
            }
            let mut candidate = before;
            let mut callback_error = None;
            let result = context.objects().attach(&mut candidate, policy, |native| {
                native_decision(&mut callback_error, || {
                    decision(
                        decide.expect("explicit decision"),
                        Py::new(py, PyAttachment::from_native(native))?.into_any(),
                    )
                })
            });
            if let Some(error) = callback_error {
                return Err(error);
            }
            result.map_err(to_py)?;
            session(&self.session)?;
            self.checked(revision, |data| {
                *data = candidate;
                Ok(())
            })
        })
    }
    #[pyo3(signature=(*, to=None, decide=None, purpose=None, r#use=None, object_type=None))]
    #[pyo3(text_signature="($self, *, to=None, decide=None, purpose=None, use=None, object_type=None)")]
    fn release(
        &self,
        py: Python<'_>,
        to: Option<&str>,
        decide: Option<&Bound<'_, PyAny>>,
        purpose: Option<&str>,
        r#use: Option<&PyUseContext>,
        object_type: Option<&str>,
    ) -> PyResult<PyObject> {
        guard(|| {
            release_requested(
                self,
                py,
                &self.session,
                purpose,
                r#use,
                to,
                decide,
                object_type,
            )
        })
    }
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!(
            "DataObject(type={:?}, revision={})",
            self.object_type()?,
            self.revision()?
        ))
    }
}

pub(super) fn populate(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyWorkflow>()?;
    m.add_class::<PyAdmittedRoute>()?;
    m.add_class::<PyData>()?;
    m.add_class::<PyDataState>()?;
    m.add_class::<PySource>()?;
    m.add_class::<PyAdmission>()?;
    m.add_class::<PyAttachment>()?;
    m.add_class::<PyRelease>()?;
    m.add_class::<PyPublication>()?;
    Ok(())
}
