//! Python callback context snapshots and detached state views.
use super::dataset::PyDatasetBinding;
use super::objects::{PyGovernance, PyObject};
use super::use_context::PyUseContext;
use super::{codec, to_py};
#[allow(unused_imports)]
use super::data::*;
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyBool;
use tn_core::governed::{
    DataObject, OwnedAdmissionContext, PublicationReport, SourceReference, UseContext,
};

pub(super) fn decision(callback: &Bound<'_, PyAny>, context: Py<PyAny>) -> PyResult<bool> {
    let answer = callback.call1((context,))?;
    if !answer.is_instance_of::<PyBool>() {
        return Err(PyTypeError::new_err("governance decision must return bool"));
    }
    answer.extract()
}
pub(super) fn native_decision(
    error: &mut Option<PyErr>,
    callback: impl FnOnce() -> PyResult<bool>,
) -> tn_core::Result<bool> {
    callback().map_err(|failure| {
        *error = Some(failure);
        tn_core::Error::InvalidConfig("Python governance decision failed".to_owned())
    })
}
pub(super) fn policies(data: &DataObject) -> PyResult<Vec<PyGovernance>> {
    data.policies()
        .map(|items| {
            items
                .into_iter()
                .map(|inner| PyGovernance { inner })
                .collect()
        })
        .map_err(to_py)
}
pub(super) fn dataset_bindings(data: &DataObject) -> PyResult<Vec<PyDatasetBinding>> {
    data.dataset_bindings()
        .map(|items| items.into_iter().map(|inner| PyDatasetBinding { inner }).collect())
        .map_err(to_py)
}
pub(super) fn hidden_groups(data: &DataObject) -> Vec<String> {
    data.hidden_groups().into_iter().map(str::to_owned).collect()
}
pub(super) fn sources(data: &DataObject) -> Vec<PySource> {
    data.sources()
        .iter()
        .cloned()
        .map(|inner| PySource { inner })
        .collect()
}

#[pyclass(frozen, module = "tn.governed", name = "SourceReference")]
pub(super) struct PySource {
    pub inner: SourceReference,
}
#[pymethods]
impl PySource {
    #[getter]
    fn revision_id(&self) -> Option<&str> {
        self.inner.revision_id()
    }
    #[getter]
    fn object_id(&self) -> &str {
        self.inner.object_id()
    }
    #[getter]
    fn object_type(&self) -> &str {
        self.inner.object_type()
    }
    #[getter]
    fn writer(&self) -> &str {
        self.inner.writer()
    }
    #[getter]
    fn governed_by(&self) -> &str {
        self.inner.governed_by()
    }
    #[getter]
    fn policy_ref(&self) -> &str {
        self.inner.policy_ref()
    }
    #[getter]
    fn groups(&self) -> Vec<String> {
        self.inner.groups().to_vec()
    }
    #[getter]
    fn operation(&self) -> &str {
        self.inner.operation()
    }
    fn references(&self, object: &PyObject) -> bool {
        self.inner.references(&object.inner)
    }
    fn references_with_policy(&self, object: &PyObject, accepted_policy: &PyGovernance) -> bool {
        self.inner
            .references_with_policy(&object.inner, &accepted_policy.inner)
    }
}

/// Frozen owned view: dictionaries returned here are detached copies.
#[pyclass(frozen, module = "tn.governed", name = "DataState")]
pub(super) struct PyDataState {
    pub(super) inner: DataObject,
}
#[pymethods]
impl PyDataState {
    #[getter]
    fn dataset_bindings(&self) -> PyResult<Vec<PyDatasetBinding>> {
        dataset_bindings(&self.inner)
    }
    #[getter]
    fn hidden_groups(&self) -> Vec<String> {
        hidden_groups(&self.inner)
    }
    #[getter]
    fn object_type(&self) -> &str {
        self.inner.object_type()
    }
    #[getter]
    fn governance(&self) -> PyGovernance {
        PyGovernance {
            inner: self.inner.governance().clone(),
        }
    }
    #[getter]
    fn policies(&self) -> PyResult<Vec<PyGovernance>> {
        policies(&self.inner)
    }
    #[getter]
    fn sources(&self) -> Vec<PySource> {
        sources(&self.inner)
    }
    #[getter]
    fn revision(&self) -> u64 {
        self.inner.revision()
    }
    #[getter]
    fn has_unreleased_changes(&self) -> bool {
        self.inner.has_unreleased_changes()
    }
    #[getter]
    fn groups<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        codec::to_python(py, &self.inner.get_path(&[]).map_err(to_py)?)
    }
    #[getter]
    fn snapshot(&self) -> Option<PyObject> {
        self.inner
            .snapshot()
            .cloned()
            .map(|inner| PyObject { inner })
    }
}

#[pyclass(frozen, module = "tn.governed", name = "AdmissionContext")]
pub(super) struct PyAdmission {
    pub inner: OwnedAdmissionContext,
}
impl PyAdmission {
    pub(super) fn from_native(context: &tn_core::governed::AdmissionContext<'_>) -> Self {
        Self {
            inner: context.to_owned(),
        }
    }
}
#[pymethods]
impl PyAdmission {
    #[getter]
    fn object(&self) -> PyObject {
        PyObject {
            inner: self.inner.context().object().clone(),
        }
    }
    #[getter]
    fn writer(&self) -> String {
        self.inner.context().object().writer().to_owned()
    }
    #[getter]
    fn object_type(&self) -> String {
        self.inner.context().object().object_type().to_owned()
    }
    #[getter]
    fn governance(&self) -> PyGovernance {
        PyGovernance {
            inner: self.inner.context().governance().clone(),
        }
    }
    #[getter]
    fn operation(&self) -> String {
        self.inner.context().operation().to_owned()
    }
    #[getter]
    fn purpose(&self) -> String {
        let context = self.inner.context();
        context
            .use_context()
            .map(UseContext::purpose)
            .unwrap_or(context.operation())
            .to_owned()
    }
    #[getter]
    fn use_context(&self) -> Option<PyUseContext> {
        self.inner
            .context()
            .use_context()
            .cloned()
            .map(|inner| PyUseContext { inner })
    }
    #[getter]
    fn groups(&self) -> Option<Vec<String>> {
        self.inner.context().groups().map(<[String]>::to_vec)
    }
    #[getter]
    fn policies(&self) -> PyResult<Vec<PyGovernance>> {
        self.inner
            .context()
            .policies()
            .map(|items| {
                items
                    .into_iter()
                    .map(|inner| PyGovernance { inner })
                    .collect()
            })
            .map_err(to_py)
    }
    #[getter]
    fn sources(&self) -> PyResult<Vec<PySource>> {
        self.inner
            .context()
            .sources()
            .map(|items| items.into_iter().map(|inner| PySource { inner }).collect())
            .map_err(to_py)
    }
}

#[pyclass(frozen, module = "tn.governed", name = "AttachmentContext")]
pub(super) struct PyAttachment {
    pub inner: tn_core::governed::OwnedAttachmentContext,
}
impl PyAttachment {
    pub(super) fn from_native(context: &tn_core::governed::AttachmentContext<'_>) -> Self {
        Self {
            inner: context.to_owned(),
        }
    }
}
#[pymethods]
impl PyAttachment {
    #[getter]
    fn authority(&self) -> String {
        self.inner.context().authority().to_owned()
    }
    #[getter]
    fn data(&self) -> PyDataState {
        PyDataState {
            inner: self.inner.context().data().clone(),
        }
    }
    #[getter]
    fn policy(&self) -> PyGovernance {
        PyGovernance {
            inner: self.inner.context().policy().clone(),
        }
    }
    #[getter]
    fn policies(&self) -> PyResult<Vec<PyGovernance>> {
        policies(self.inner.context().data())
    }
}

#[pyclass(frozen, module = "tn.governed", name = "ReleaseContext")]
pub(super) struct PyRelease {
    pub inner: tn_core::governed::OwnedReleaseContext,
}
impl PyRelease {
    pub(super) fn from_native(context: &tn_core::governed::ReleaseContext<'_>) -> Self {
        Self {
            inner: context.to_owned(),
        }
    }
}
#[pymethods]
impl PyRelease {
    #[getter]
    fn use_context(&self) -> Option<PyUseContext> {
        self.inner
            .context()
            .use_context()
            .cloned()
            .map(|inner| PyUseContext { inner })
    }
    #[getter]
    fn writer(&self) -> String {
        self.inner.context().writer().to_owned()
    }
    #[getter]
    fn data(&self) -> PyDataState {
        PyDataState {
            inner: self.inner.context().data().clone(),
        }
    }
    #[getter]
    fn object_type(&self) -> String {
        self.inner.context().object_type().to_owned()
    }
    #[getter]
    fn purpose(&self) -> String {
        self.inner.context().purpose().to_owned()
    }
    #[getter]
    fn destination(&self) -> String {
        self.inner.context().destination().to_owned()
    }
    #[getter]
    fn policies(&self) -> PyResult<Vec<PyGovernance>> {
        policies(self.inner.context().data())
    }
    #[getter]
    fn sources(&self) -> Vec<PySource> {
        sources(self.inner.context().data())
    }
}

#[pyclass(frozen, module = "tn.governed", name = "PublicationReport")]
pub(super) struct PyPublication {
    pub inner: PublicationReport,
}
#[pymethods]
impl PyPublication {
    #[getter]
    fn required_groups(&self) -> Vec<String> {
        self.inner.required_groups().to_vec()
    }
    #[getter]
    fn supported_groups(&self) -> Vec<String> {
        self.inner.supported_groups().to_vec()
    }
    #[getter]
    fn missing_groups(&self) -> Vec<String> {
        self.inner.missing_groups().to_vec()
    }
    #[getter]
    fn unavailable_groups(&self) -> Vec<String> {
        self.inner.unavailable_groups().to_vec()
    }
    #[getter]
    fn unknown_groups(&self) -> Vec<String> {
        self.inner.unknown_groups().to_vec()
    }
    #[getter]
    fn is_ready(&self) -> bool {
        self.inner.is_ready()
    }
}
