//! Export: sign fresh randomized M1 publications and record their admission cases.
use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tn_core::governed::*;
use tn_core::{DeviceKey, Result};

use crate::{
    metadata, reader, writer, Case, ExpectedRelease, GroupMaterial, Manifest, Publication, GROUPS,
    INDEX_MASTER, POLICY, SCHEMA, TEST_SEED,
};

/// An admission case: name, publication, selection, use, decision, allowed, decision calls,
/// and the refusal reason a denied case must report.
type CaseRow = (
    &'static str,
    &'static str,
    Option<&'static str>,
    &'static str,
    &'static str,
    bool,
    usize,
    Option<&'static str>,
);

#[rustfmt::skip]
const USES: [(&str, &str, &str, &str); 6] = [
    ("source", "analytics", "portfolio_analysis", "compare_editions"),
    ("deepvest", "deepvest", "portfolio_analysis", "calculate"),
    ("model", "tn-llama", "portfolio_analysis", "generate_report"),
    ("wrong_application", "unapproved-app", "portfolio_analysis", "compare_editions"),
    ("wrong_purpose", "analytics", "advertising", "compare_editions"),
    ("wrong_operation", "analytics", "portfolio_analysis", "redistribute"),
];

#[rustfmt::skip]
const CASES: [CaseRow; 14] = [
    ("earlier_edition", "source_earlier", Some("earlier"), "source", "accept", true, 1, None),
    ("later_edition", "source_later", Some("later"), "source", "accept", true, 1, None),
    ("source_substitution", "source_later", Some("earlier"), "source", "accept", false, 0,
     Some("selected source identity")),
    ("wrong_application", "source_earlier", Some("earlier"), "wrong_application", "accept", false, 0,
     Some("application refused operation")),
    ("wrong_purpose", "source_earlier", Some("earlier"), "wrong_purpose", "accept", false, 0,
     Some("application refused operation")),
    ("wrong_operation", "source_earlier", Some("earlier"), "wrong_operation", "accept", false, 0,
     Some("application refused operation")),
    ("callback_refusal", "source_earlier", Some("earlier"), "source", "refuse", false, 1,
     Some("application refused operation")),
    ("callback_error", "source_earlier", Some("earlier"), "source", "error", false, 1,
     Some("fixture callback error")),
    ("deepvest_receives_joined", "joined", None, "deepvest", "accept", true, 1, None),
    ("model_receives_exact_deepvest", "deepvest", None, "model", "accept", true, 1, None),
    ("derived_wrong_use", "deepvest", None, "wrong_application", "accept", false, 1,
     Some("application refused operation")),
    ("omitted_contributing_contract", "lost_contract", None, "model", "accept", false, 1,
     Some("every parent contract")),
    ("omitted_dataset_binding", "lost_binding", None, "model", "accept", false, 1,
     Some("every parent dataset binding")),
    ("unreached_declared_origins", "unreached_origins", None, "model", "accept", false, 1,
     Some("reached origins")),
];

fn make_case(row: CaseRow) -> Case {
    let (name, publication, selection, use_name, decision, allowed, calls, error) = row;
    Case {
        name: name.into(),
        publication: publication.into(),
        selection: selection.map(str::to_owned),
        use_name: use_name.into(),
        groups: vec!["finance".into()],
        decision: decision.into(),
        allowed,
        decision_calls: calls,
        business_decrypts: usize::from(allowed),
        error_contains: error.map(str::to_owned),
    }
}

fn fixture_cases() -> Vec<Case> {
    let mut cases: Vec<Case> = CASES.into_iter().map(make_case).collect();
    let mut wrong_group = make_case((
        "unselected_business_group",
        "source_earlier",
        Some("earlier"),
        "source",
        "accept",
        false,
        0,
        Some("supplied by the selected edition"),
    ));
    wrong_group.groups = vec!["audit".into()];
    cases.push(wrong_group);
    cases
}

fn group_materials() -> Result<BTreeMap<String, GroupMaterial>> {
    let mut groups = BTreeMap::new();
    for name in GROUPS {
        let mut state = tn_btn::PublisherState::setup(tn_btn::Config)?;
        let kit = state.mint()?;
        groups.insert(
            name.to_owned(),
            GroupMaterial {
                publisher_state_base64: STANDARD.encode(state.to_bytes()),
                reader_kit_base64: STANDARD.encode(kit.to_bytes()),
            },
        );
    }
    Ok(groups)
}

fn fixture_uses() -> Result<BTreeMap<String, UseContext>> {
    USES.into_iter()
        .map(
            |(name, application, purpose, operation)| -> Result<(String, UseContext)> {
                Ok((
                    name.to_owned(),
                    UseContext::new(application, purpose, operation)?,
                ))
            },
        )
        .collect()
}

fn wealth_path() -> Value {
    json!({"wealth_path": [100,120,90,135], "units":"index", "synthetic":true})
}

fn calculation_result() -> Value {
    json!({"calculation":{
        "function":"max_drawdown", "engine":"m1-fixture-arithmetic", "version":"1",
        "method":"maximum peak-to-trough fractional decline", "units":"fraction",
        "arguments":{"wealth_path":[100,120,90,135]}, "result":0.25
    }, "synthetic":true})
}

/// The publications an export signs, and the policy DAG and dataset catalog that admit them.
struct Fixture<'a> {
    device: &'a DeviceKey,
    writer: GovernedWriter<'a>,
    reader: GovernedReader,
    uses: BTreeMap<String, UseContext>,
    administration: Governance,
    dag: PolicyDag,
    catalog: DatasetCatalog,
    objects: BTreeMap<String, GovernedObject>,
    inputs: Vec<DataObject>,
}

impl<'a> Fixture<'a> {
    fn new(device: &'a DeviceKey, groups: &BTreeMap<String, GroupMaterial>) -> Result<Self> {
        Ok(Self {
            device,
            writer: writer(device, groups)?,
            reader: reader(groups)?.0,
            uses: fixture_uses()?,
            administration: Governance::from_markdown(
                device.did(),
                POLICY,
                "fixture.admin.md",
                "finance.wealth_path",
            )?,
            dag: PolicyDag::new(),
            catalog: DatasetCatalog::new(),
            objects: BTreeMap::new(),
            inputs: Vec::new(),
        })
    }

    /// Sign one policy revision, its source, and its dataset edition; then receive the source.
    fn edition(&mut self, name: &str, version: &str, edition: &str) -> Result<()> {
        let (policy_object, revision_id) = self.policy_revision(version)?;
        let policy = self
            .dag
            .select(&revision_id, "finance.wealth_path", |_| Ok(true))?;
        let source = self.writer.seal(
            GovernedDraft::new("finance.wealth_path", policy)?
                .group("finance", wealth_path())?
                .group("audit", json!({"fixture":"M1", "edition":edition}))?,
        )?;
        let edition_object =
            self.writer
                .seal(self.edition_draft(&source, &revision_id, edition)?)?;
        let record = DatasetEdition::from_opened(&metadata(
            &self.reader,
            &edition_object,
            DATASET_EDITION_GROUP,
        )?)?;
        let device = self.device;
        self.catalog.admit(record, &self.dag, |record| {
            Ok(record.writer() == device.did())
        })?;
        let selection = self.catalog.select(
            "finance.wealth_path",
            edition,
            edition_object.id(),
            &self.uses["source"],
        )?;
        let input = self.reader.receive_for(
            source.wire(),
            &self.uses["source"],
            ["finance"],
            Some(&selection),
            |_| Ok(true),
        )?;
        self.inputs.push(input);
        self.objects.insert(format!("policy_{name}"), policy_object);
        self.objects
            .insert(format!("edition_{name}"), edition_object);
        self.objects.insert(format!("source_{name}"), source);
        Ok(())
    }

    /// Sign the wealth-path policy at `version` and admit its revision to the DAG.
    fn policy_revision(&mut self, version: &str) -> Result<(GovernedObject, String)> {
        let policy_object = self.writer.seal(
            PolicyRevisionDraft::from_markdown(
                self.device.did(),
                &POLICY.replace("version: 1", &format!("version: {version}")),
                "fixture.wealth.md",
                "finance.wealth_path",
                "finance.wealth_path",
            )?
            .into_draft(self.administration.clone())?,
        )?;
        let revision = PolicyRevision::from_opened(&metadata(
            &self.reader,
            &policy_object,
            POLICY_REVISION_GROUP,
        )?)?;
        let revision_id = revision.id().to_owned();
        let device = self.device;
        self.dag
            .admit(revision, |record, _| Ok(record.writer() == device.did()))?;
        Ok((policy_object, revision_id))
    }

    fn edition_draft(
        &self,
        source: &GovernedObject,
        revision_id: &str,
        edition: &str,
    ) -> Result<GovernedDraft> {
        let artifacts = EvaluatorArtifactSet::new(
            revision_id,
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
            &"d".repeat(64),
        )?;
        DatasetEditionDraft::new(
            "finance.wealth_path",
            edition,
            source,
            ["finance"],
            vec![ContractBinding::new(revision_id, "finance.wealth_path")?],
            vec![
                self.uses["source"].clone(),
                self.uses["deepvest"].clone(),
                self.uses["model"].clone(),
            ],
            "grant:synthetic-m1",
            vec![artifacts],
        )?
        .into_draft(self.administration.clone())
    }

    /// Join both editions for deepvest, release its calculation to the model, and sign the
    /// negative declarations derived from them.
    fn releases(&mut self) -> Result<()> {
        let mut joined_data = self.inputs[0].clone();
        joined_data.include(&self.inputs[1])?;
        joined_data.set_field("finance", "editions_compared", json!(2))?;
        let joined = self.writer.release_for(
            &mut joined_data,
            "finance.prepared",
            &self.uses["source"],
            "deepvest",
            |_| Ok(true),
        )?;
        let mut calculation = self.reader.receive_for(
            joined.wire(),
            &self.uses["deepvest"],
            ["finance"],
            None,
            |context| self.catalog.accepts(context, &self.dag),
        )?;
        calculation.set_group("finance", calculation_result())?;
        let deepvest = self.writer.release_for(
            &mut calculation,
            "deepvest.calculation",
            &self.uses["deepvest"],
            "tn-llama",
            |_| Ok(true),
        )?;
        let negatives = self.negatives(&joined, &joined_data, &calculation)?;
        self.objects.insert("joined".into(), joined);
        self.objects.insert("deepvest".into(), deepvest);
        for (name, object) in negatives {
            self.objects.insert(name.into(), object);
        }
        Ok(())
    }

    /// Ordinary signing of deliberate negative declarations. These remain valid TN
    /// objects; their failures must occur at lineage/admission, not signature verification.
    fn negatives(
        &self,
        joined: &GovernedObject,
        joined_data: &DataObject,
        calculation: &DataObject,
    ) -> Result<[(&'static str, GovernedObject); 3]> {
        let parents = [metadata(&self.reader, joined, "finance")?.source_reference()?];
        let lost_contract = self.writer.seal(
            GovernedDraft::new("deepvest.calculation", self.inputs[0].governance().clone())?
                .with_source_lineage(&parents)?
                .group("finance", json!({"result":0.25}))?,
        )?;
        let policies = calculation.policies()?;
        let mut unbound = DataObject::new(
            "deepvest.calculation",
            policies[0].clone(),
            "finance",
            json!({"result":0.25}),
        )?;
        for policy in &policies[1..] {
            unbound.attach(self.device.did(), policy.clone(), |_| Ok(true))?;
        }
        let lost_binding = self.writer.seal(
            GovernedDraft::new("deepvest.calculation", unbound.governance().clone())?
                .with_source_lineage(&parents)?
                .group("finance", json!({"result":0.25}))?,
        )?;
        let unreached = self.writer.seal(
            GovernedDraft::new("finance.prepared", joined_data.governance().clone())?
                .group("finance", json!({"wealth_path":[100,120,90,135]}))?,
        )?;
        Ok([
            ("lost_contract", lost_contract),
            ("lost_binding", lost_binding),
            ("unreached_origins", unreached),
        ])
    }

    fn expected_release(&self, object: &GovernedObject) -> Result<ExpectedRelease> {
        let view = self.reader.governance(object)?;
        let proof = LineageVerifier::default().verify(&view, &self.catalog, &self.dag, |id| {
            self.reader.governance(
                self.objects
                    .values()
                    .find(|object| object.id() == id)
                    .expect("retained parent"),
            )
        })?;
        let governance = view.governance();
        Ok(ExpectedRelease {
            contracts: governance
                .policies()?
                .iter()
                .map(|p| p.revision_id().unwrap().into())
                .collect(),
            dataset_bindings: governance.dataset_bindings()?,
            parent_ids: governance
                .source_references()?
                .iter()
                .map(|r| r.object_id().into())
                .collect(),
            lineage_object_ids: proof.object_ids().to_vec(),
            finance: metadata(&self.reader, object, "finance")?.groups()["finance"].clone(),
        })
    }
}

/// One digest over the exporter's three source files, in module order.
fn example_sha256() -> String {
    let mut digest = Sha256::new();
    for source in [
        include_bytes!("main.rs").as_slice(),
        include_bytes!("export.rs").as_slice(),
        include_bytes!("replay.rs").as_slice(),
    ] {
        digest.update(source);
    }
    hex::encode(digest.finalize())
}

fn producer() -> Value {
    json!({"example":"crypto/tn-core/examples/governed_fixture_manifest",
        "example_sha256":example_sha256(),
        "sdk_commit": std::process::Command::new("git").args(["rev-parse", "HEAD"])
            .output().ok().filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok()).map(|head| head.trim().to_owned()),
        "tn_core_version":env!("CARGO_PKG_VERSION"),
        "regeneration":"fresh randomized publications; replay this retained manifest with --verify"})
}

pub(crate) fn export() -> Result<Manifest> {
    let device = DeviceKey::from_private_bytes(&TEST_SEED)?;
    let groups = group_materials()?;
    let mut fixture = Fixture::new(&device, &groups)?;
    fixture.edition("earlier", "1", "history-2026-09-08")?;
    fixture.edition("later", "2", "close-2026-09-09")?;
    fixture.releases()?;
    let mut expected_releases = BTreeMap::new();
    for name in ["joined", "deepvest"] {
        expected_releases.insert(
            name.into(),
            fixture.expected_release(&fixture.objects[name])?,
        );
    }
    Ok(Manifest {
        schema: SCHEMA.into(),
        test_only: true,
        producer: producer(),
        private_seed_hex: hex::encode(TEST_SEED),
        index_master_hex: hex::encode(INDEX_MASTER),
        writer: device.did().into(),
        publications: fixture
            .objects
            .iter()
            .map(|(name, object)| (name.clone(), Publication::from(object)))
            .collect(),
        uses: fixture.uses,
        groups,
        expected_releases,
        cases: fixture_cases(),
    })
}
