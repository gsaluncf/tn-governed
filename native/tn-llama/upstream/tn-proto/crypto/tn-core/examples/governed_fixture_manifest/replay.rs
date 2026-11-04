//! Replay: rebuild admission state from a retained manifest and check every case.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::Value;
use tn_core::governed::*;
use tn_core::{DeviceKey, Error, Result};

use crate::{metadata, reader, Case, ExpectedRelease, Manifest, INDEX_MASTER, SCHEMA, TEST_SEED};

pub(crate) fn verify(manifest: &Manifest) -> Result<()> {
    assert_eq!(manifest.schema, SCHEMA);
    assert!(manifest.test_only);
    assert_eq!(manifest.private_seed_hex, hex::encode(TEST_SEED));
    assert_eq!(manifest.index_master_hex, hex::encode(INDEX_MASTER));
    assert_eq!(
        manifest.writer,
        DeviceKey::from_private_bytes(&TEST_SEED)?.did()
    );
    let replay = Replay::new(manifest)?;
    for (name, expected) in &manifest.expected_releases {
        replay.check_release(name, expected)?;
    }
    for case in &manifest.cases {
        replay.check_case(case)?;
    }
    Ok(())
}

/// A retained manifest replayed against admission state rebuilt from its own publications.
struct Replay<'m> {
    manifest: &'m Manifest,
    reader: GovernedReader,
    business: Arc<AtomicUsize>,
    objects: BTreeMap<String, GovernedObject>,
    dag: PolicyDag,
    catalog: DatasetCatalog,
    selections: BTreeMap<&'static str, DatasetSelection>,
}

impl<'m> Replay<'m> {
    fn new(manifest: &'m Manifest) -> Result<Self> {
        let (reader, business) = reader(&manifest.groups)?;
        let objects = manifest
            .publications
            .iter()
            .map(|(name, publication)| {
                let object = GovernedObject::parse(&publication.wire)?;
                assert_eq!(object.id(), publication.object_id);
                assert_eq!(object.writer(), publication.writer);
                assert_eq!(object.object_type(), publication.object_type);
                assert_eq!(object.writer(), manifest.writer);
                Ok((name.clone(), object))
            })
            .collect::<Result<_>>()?;
        let mut replay = Self {
            manifest,
            reader,
            business,
            objects,
            dag: PolicyDag::new(),
            catalog: DatasetCatalog::new(),
            selections: BTreeMap::new(),
        };
        for name in ["earlier", "later"] {
            replay.admit_edition(name)?;
        }
        Ok(replay)
    }

    /// Admit one retained policy revision and dataset edition, and select the edition.
    fn admit_edition(&mut self, name: &'static str) -> Result<()> {
        let manifest = self.manifest;
        let revision = PolicyRevision::from_opened(&metadata(
            &self.reader,
            &self.objects[&format!("policy_{name}")],
            POLICY_REVISION_GROUP,
        )?)?;
        self.dag
            .admit(revision, |record, _| Ok(record.writer() == manifest.writer))?;
        let edition = DatasetEdition::from_opened(&metadata(
            &self.reader,
            &self.objects[&format!("edition_{name}")],
            DATASET_EDITION_GROUP,
        )?)?;
        let (dataset, edition_name, record_id) = (
            edition.dataset().to_owned(),
            edition.edition().to_owned(),
            edition.id().to_owned(),
        );
        self.catalog.admit(edition, &self.dag, |record| {
            Ok(record.writer() == manifest.writer)
        })?;
        let selection = self.catalog.select(
            &dataset,
            &edition_name,
            &record_id,
            &manifest.uses["source"],
        )?;
        self.selections.insert(name, selection);
        Ok(())
    }

    fn resolve(&self, id: &str) -> Result<GovernanceView> {
        self.reader.governance(
            self.objects
                .values()
                .find(|object| object.id() == id)
                .expect("retained parent"),
        )
    }

    /// A retained release has the recorded lineage, dataset bindings, contracts, and parents.
    fn check_release(&self, name: &str, expected: &ExpectedRelease) -> Result<()> {
        let view = self.reader.governance(&self.objects[name])?;
        let proof = LineageVerifier::default()
            .verify(&view, &self.catalog, &self.dag, |id| self.resolve(id))?;
        assert_eq!(proof.object_ids(), expected.lineage_object_ids);
        let governance = view.governance();
        assert_eq!(governance.dataset_bindings()?, expected.dataset_bindings);
        assert_eq!(
            governance
                .policies()?
                .iter()
                .map(|p| p.revision_id().unwrap().to_owned())
                .collect::<Vec<_>>(),
            expected.contracts
        );
        assert_eq!(
            governance
                .source_references()?
                .iter()
                .map(|r| r.object_id().to_owned())
                .collect::<Vec<_>>(),
            expected.parent_ids
        );
        Ok(())
    }

    /// One case's admission: its outcome, decision calls, business decrypts, and opened values.
    fn check_case(&self, case: &Case) -> Result<()> {
        let object = &self.objects[&case.publication];
        let view = self.reader.governance(object)?;
        let selection = case
            .selection
            .as_ref()
            .map(|name| &self.selections[name.as_str()]);
        self.business.store(0, Ordering::SeqCst);
        let mut calls = 0;
        let opened = self.reader.receive_for(
            object.wire(),
            &self.manifest.uses[&case.use_name],
            &case.groups,
            selection,
            |context| {
                calls += 1;
                self.decide(case, &view, selection.is_none(), context)
            },
        );
        assert_eq!(
            opened.is_ok(),
            case.allowed,
            "{}: {:?}",
            case.name,
            opened.as_ref().err()
        );
        assert_eq!(calls, case.decision_calls, "{} decision calls", case.name);
        assert_eq!(
            self.business.load(Ordering::SeqCst),
            case.business_decrypts,
            "{} business decrypts",
            case.name
        );
        match opened {
            Ok(data) => self.check_opened(case, selection, &data),
            Err(error) => {
                assert!(
                    error
                        .to_string()
                        .contains(case.error_contains.as_ref().expect("refusal reason")),
                    "{}: {error}",
                    case.name
                );
                Ok(())
            }
        }
    }

    /// The case's callback: an error, a refusal, or acceptance through lineage and the catalog.
    fn decide(
        &self,
        case: &Case,
        view: &GovernanceView,
        unselected: bool,
        context: &AdmissionContext<'_>,
    ) -> Result<bool> {
        if case.decision == "error" {
            return Err(Error::Malformed {
                kind: "fixture",
                reason: "fixture callback error".into(),
            });
        }
        if case.decision == "refuse" {
            return Ok(false);
        }
        assert_eq!(case.decision, "accept");
        if unselected {
            LineageVerifier::default()
                .verify(view, &self.catalog, &self.dag, |id| self.resolve(id))?;
            return self.catalog.accepts(context, &self.dag);
        }
        Ok(context.object().writer() == self.manifest.writer)
    }

    fn check_opened(
        &self,
        case: &Case,
        selection: Option<&DatasetSelection>,
        data: &DataObject,
    ) -> Result<()> {
        if let Some(selection) = selection {
            assert_eq!(data.dataset_bindings()?, [selection.binding()]);
        }
        if let Some(expected) = self.manifest.expected_releases.get(&case.publication) {
            assert_eq!(
                Value::Object(data.group("finance").unwrap().clone()),
                expected.finance
            );
        }
        Ok(())
    }
}
