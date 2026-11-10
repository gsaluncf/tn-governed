//! Exact standalone TN publications, admitted under receiver-held authority.
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde_json::{json, Map, Value};
use tn_core::governed::{
    AdmissionContext, AdmittedObject, AdmittedRoute, DataObject, DatasetCatalog, DatasetEdition,
    GovernanceView, GovernedObject, GovernedReader, LineageVerifier, PolicyDag, PolicyRevision,
    UseContext,
};

use crate::config::RequestLimits;
use crate::governance::{field_hashes, VerifiedGovernance, GOVERNANCE_GROUP};
use crate::model_protocol::{digest_bytes, session_error};
use crate::strict_json::parse_duplicate_safe_json;
use crate::TnLlamaError;

pub const GOVERNED_REQUEST_PROTOCOL: &str = "tn.llama.request.v2";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractPermission {
    pub revision_id: String,
    pub scope: String,
    pub allowed_uses: BTreeSet<UseContext>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceContractPermission {
    pub governed_by: String,
    pub fields: Map<String, Value>,
    pub allowed_uses: BTreeSet<UseContext>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedInputConfig {
    /// Admit the current publisher's signed policy carrier and its attached evidence.
    #[serde(default)]
    pub carried_policy: bool,
    /// Exact catalog edition for an original publication issued before its edition was signed.
    #[serde(default)]
    pub source_edition_id: Option<String>,
    #[serde(
        default = "crate::config::default_lineage_max_objects",
        deserialize_with = "crate::config::deserialize_lineage_max_objects"
    )]
    pub lineage_max_objects: usize,
    #[serde(
        default = "crate::config::default_lineage_max_depth",
        deserialize_with = "crate::config::deserialize_lineage_max_depth"
    )]
    pub lineage_max_depth: usize,
    #[serde(default)]
    pub report_contract: Option<tn_core::governed::ContractBinding>,
    pub native_reader_config_path: PathBuf,
    pub metadata_store_path: PathBuf,
    pub use_context: UseContext,
    pub destinations: BTreeSet<String>,
    pub trusted_writers: BTreeSet<String>,
    pub authority_writers: BTreeSet<String>,
    pub contracts: Vec<ContractPermission>,
    #[serde(default)]
    pub evidence_contracts: Vec<EvidenceContractPermission>,
}

impl GovernedInputConfig {
    pub fn lineage_verifier(&self) -> tn_core::Result<LineageVerifier> {
        LineageVerifier::new(self.lineage_max_objects, self.lineage_max_depth)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug)]
pub struct AcceptedGovernedRequest {
    pub object: GovernedObject,
    pub use_context: UseContext,
    pub destination: String,
    pub messages: Vec<UserMessage>,
    pub request_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wrapper {
    protocol: String,
    tn_object: String,
    #[serde(rename = "use")]
    use_context: UseContext,
    destination: String,
    messages: Vec<Message>,
    stream: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    role: String,
    content: String,
}

pub fn parse_governed_object_request(
    raw: &[u8],
    limits: &RequestLimits,
    config: &GovernedInputConfig,
) -> Result<AcceptedGovernedRequest, TnLlamaError> {
    if raw.len() > limits.max_request_bytes {
        return Err(refused("tn_request_too_large"));
    }
    let value = parse_duplicate_safe_json(raw).map_err(|_| refused("tn_request_shape"))?;
    let wrapper: Wrapper =
        serde_json::from_value(value).map_err(|_| refused("tn_request_shape"))?;
    if wrapper.protocol != GOVERNED_REQUEST_PROTOCOL
        || wrapper.stream
        || wrapper.messages.len() != 1
        || wrapper.messages[0].role != "user"
        || wrapper.messages[0].content.trim().is_empty()
        || wrapper.messages[0].content.len() > limits.max_message_bytes
    {
        return Err(refused("tn_request_shape"));
    }
    if wrapper.use_context != config.use_context
        || !config.destinations.contains(&wrapper.destination)
    {
        return Err(refused("tn_governed_use_denied"));
    }
    let object = GovernedObject::parse(&wrapper.tn_object)
        .map_err(|_| refused("tn_governed_object_invalid"))?;
    if object.object_type() != limits.expected_event_type
        || !config.trusted_writers.contains(object.writer())
        || object
            .group_names()
            .iter()
            .any(|name| *name != "tn.agents" && !limits.allowed_input_groups.contains(*name))
    {
        return Err(refused("tn_governed_source_denied"));
    }
    let message = wrapper.messages.into_iter().next().expect("one message");
    let digest = tn_core::canonical::canonical_bytes(&json!({
        "object_id":object.id(), "use":wrapper.use_context, "destination":wrapper.destination,
        "messages":[{"role":"user","content":message.content}]
    }))
    .map_err(|_| refused("tn_request_shape"))?;
    Ok(AcceptedGovernedRequest {
        object,
        use_context: wrapper.use_context,
        destination: wrapper.destination,
        messages: vec![UserMessage {
            role: "user".into(),
            content: message.content,
        }],
        request_digest: digest_bytes(b"tn.llama.request.v2\0", &digest),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataStore {
    policy_revisions: Vec<String>,
    dataset_editions: Vec<String>,
    publications: Vec<String>,
    #[serde(default)]
    claim_records: Vec<String>,
    #[serde(default)]
    action_records: Vec<String>,
}

pub(crate) struct GovernedInputRuntime {
    pub config: GovernedInputConfig,
    pub(crate) reader: GovernedReader,
    pub report_policy: Option<tn_core::governed::Governance>,
    pub(crate) dag: PolicyDag,
    pub(crate) catalog: DatasetCatalog,
    pub(crate) source_selection: Option<tn_core::governed::DatasetSelection>,
    pub(crate) retained: BTreeMap<String, GovernanceView>,
    pub(crate) lineage: LineageVerifier,
    pub(crate) claim_records: Vec<String>,
    pub(crate) action_records: Vec<String>,
    /// Opened and verified evidence manifests of retained objects, by object and use.
    pub(crate) manifests: Mutex<OpenedManifests>,
}

pub(crate) type OpenedManifests =
    BTreeMap<(String, tn_core::governed::UseContext), Option<Arc<Map<String, Value>>>>;

impl GovernedInputRuntime {
    pub fn load(config: GovernedInputConfig) -> Result<Self, TnLlamaError> {
        let lineage = config
            .lineage_verifier()
            .map_err(|_| refused("tn_governed_config_invalid"))?;
        if !config.native_reader_config_path.is_absolute()
            || !config.metadata_store_path.is_absolute()
            || config.trusted_writers.is_empty()
            || config.authority_writers.is_empty()
            || config.destinations.is_empty()
            || config.destinations.iter().any(|s| s.trim().is_empty())
            || config.contracts.is_empty()
        {
            return Err(refused("tn_governed_config_invalid"));
        }
        let reader = tn_core::runtime::Objects::open(&config.native_reader_config_path)
            .and_then(|objects| objects.reader())
            .map_err(|_| refused("tn_governed_reader_invalid"))?;
        let raw = std::fs::read(&config.metadata_store_path)
            .map_err(|_| refused("tn_governed_store_invalid"))?;
        let metadata: MetadataStore = serde_json::from_value(
            parse_duplicate_safe_json(&raw).map_err(|_| refused("tn_governed_store_invalid"))?,
        )
        .map_err(|_| refused("tn_governed_store_invalid"))?;
        let mut dag = PolicyDag::new();
        let mut catalog = DatasetCatalog::new();
        let open_metadata = |wire: &str, group: &str| -> Result<_, TnLlamaError> {
            let object =
                GovernedObject::parse(wire).map_err(|_| refused("tn_governed_metadata_invalid"))?;
            if !config.authority_writers.contains(object.writer()) {
                return Err(refused("tn_governed_authority_denied"));
            }
            let view = reader
                .governance(&object)
                .map_err(|_| refused("tn_governed_metadata_invalid"))?;
            let admitted = view
                .accept(
                    UseContext::new("tn-llama.catalog", "administration", "inspect")
                        .expect("constant use"),
                    [group],
                    |ctx| {
                        Ok(ctx
                            .policies()?
                            .iter()
                            .all(|policy| config.authority_writers.contains(policy.governed_by())))
                    },
                )
                .map_err(|_| refused("tn_governed_authority_denied"))?;
            reader
                .open(&admitted, [group])
                .map_err(|_| refused("tn_governed_metadata_invalid"))
        };
        for wire in &metadata.policy_revisions {
            let revision = PolicyRevision::from_opened(&open_metadata(wire, "policy_revision")?)
                .map_err(|_| refused("tn_governed_metadata_invalid"))?;
            dag.admit(revision, |revision, _| {
                Ok(config.authority_writers.contains(revision.writer())
                    && config
                        .authority_writers
                        .contains(revision.governance().governed_by()))
            })
            .map_err(|_| refused("tn_governed_authority_denied"))?;
        }
        let mut permitted = BTreeSet::new();
        for permission in &config.contracts {
            if !permitted.insert(permission.revision_id.clone())
                || permission.allowed_uses.is_empty()
                || dag
                    .select(&permission.revision_id, &permission.scope, |_| Ok(true))
                    .is_err()
            {
                return Err(refused("tn_governed_config_invalid"));
            }
        }
        for wire in &metadata.dataset_editions {
            let edition = DatasetEdition::from_opened(&open_metadata(wire, "dataset_edition")?)
                .map_err(|_| refused("tn_governed_metadata_invalid"))?;
            catalog
                .admit(edition, &dag, |item| {
                    Ok(config.authority_writers.contains(item.writer()))
                })
                .map_err(|_| refused("tn_governed_authority_denied"))?;
        }
        let source_selection = config
            .source_edition_id
            .as_ref()
            .map(|id| {
                let record = catalog
                    .get(id)
                    .filter(|_| config.carried_policy)
                    .ok_or_else(|| refused("tn_governed_source_denied"))?;
                catalog
                    .select(record.dataset(), record.edition(), id, &config.use_context)
                    .map_err(|_| refused("tn_governed_source_denied"))
            })
            .transpose()?;
        let mut retained = BTreeMap::new();
        for wire in &metadata.publications {
            let object =
                GovernedObject::parse(wire).map_err(|_| refused("tn_governed_metadata_invalid"))?;
            if !config.trusted_writers.contains(object.writer()) {
                return Err(refused("tn_governed_source_denied"));
            }
            let view = reader
                .governance(&object)
                .map_err(|_| refused("tn_governed_metadata_invalid"))?;
            if retained.insert(object.id().to_owned(), view).is_some() {
                return Err(refused("tn_governed_store_invalid"));
            }
        }
        let report_policy = config
            .report_contract
            .as_ref()
            .map(|binding| {
                if !config.contracts.iter().any(|permission| {
                    permission.revision_id == binding.revision_id()
                        && permission.scope == binding.scope()
                        && permission.allowed_uses.contains(&config.use_context)
                }) {
                    return Err(refused("tn_governed_config_invalid"));
                }
                dag.select(binding.revision_id(), binding.scope(), |_| Ok(true))
                    .map_err(|_| refused("tn_governed_config_invalid"))
            })
            .transpose()?;
        Ok(Self {
            config,
            reader,
            report_policy,
            dag,
            catalog,
            source_selection,
            retained,
            lineage,
            claim_records: metadata.claim_records,
            action_records: metadata.action_records,
            manifests: Mutex::new(BTreeMap::new()),
        })
    }

    pub(crate) fn accepts(
        &self,
        context: &AdmissionContext<'_>,
        view: &GovernanceView,
    ) -> tn_core::Result<bool> {
        if context.use_context() != Some(&self.config.use_context)
            || !self
                .config
                .trusted_writers
                .contains(context.object().writer())
        {
            return Ok(false);
        }
        if !self.accepts_contracts(context)? {
            return Ok(false);
        }
        if self.config.carried_policy {
            return Ok(true);
        }
        self.lineage.verify(view, &self.catalog, &self.dag, |id| {
            self.retained
                .get(id)
                .cloned()
                .ok_or_else(|| tn_core::Error::InvalidConfig("missing retained ancestor".into()))
        })?;
        Ok(true)
    }

    pub(crate) fn accepts_contracts(
        &self,
        context: &AdmissionContext<'_>,
    ) -> tn_core::Result<bool> {
        if context.use_context() != Some(&self.config.use_context) {
            return Ok(false);
        }
        for policy in context.policies()? {
            let Some(permission) = self
                .config
                .contracts
                .iter()
                .find(|p| Some(p.revision_id.as_str()) == policy.revision_id())
            else {
                return Ok(false);
            };
            if !permission.allowed_uses.contains(&self.config.use_context) {
                return Ok(false);
            }
            self.dag.resolve(&policy, &permission.scope)?;
        }
        if let Some(selection) = &self.source_selection {
            if context.object().id() == selection.source_object_id() {
                selection.verify_context(context)?;
                if context.governance().dataset_bindings()?.is_empty() {
                    return Ok(true);
                }
            }
        }
        if !self.catalog.accepts(context, &self.dag)? {
            return Ok(false);
        }
        Ok(true)
    }

    pub fn accepts_output(
        &self,
        context: &AdmissionContext<'_>,
        view: &GovernanceView,
        parents: &[&GovernanceView],
    ) -> tn_core::Result<bool> {
        if !self.accepts_contracts(context)? {
            return Ok(false);
        }
        let sources = context.sources()?;
        if sources.len() != parents.len()
            || !parents.iter().all(|parent| {
                sources.iter().any(|reference| {
                    reference.references_with_policy(parent.object(), parent.governance())
                })
            })
        {
            return Ok(false);
        }
        if self.config.carried_policy {
            return Ok(true);
        }
        self.lineage.verify(view, &self.catalog, &self.dag, |id| {
            if let Some(parent) = parents.iter().find(|parent| id == parent.object().id()) {
                return Ok((*parent).clone());
            }
            self.retained
                .get(id)
                .cloned()
                .ok_or_else(|| tn_core::Error::InvalidConfig("missing retained ancestor".into()))
        })?;
        Ok(true)
    }

    /// Verify the request's governance and admit its route: the request object and,
    /// for each offered group it carries, every object on the path to the holder.
    pub fn governance(
        &self,
        request: &AcceptedGovernedRequest,
        groups: &BTreeSet<String>,
    ) -> Result<(GovernanceView, VerifiedGovernance, AdmittedRoute), TnLlamaError> {
        let view = self
            .reader
            .governance(&request.object)
            .map_err(|_| refused("tn_governed_governance_invalid"))?;
        // The reader recomputed the governance field hashes when it opened them.
        let checked = VerifiedGovernance {
            plaintext: view.governance().fields().clone().into_iter().collect(),
            commitments: field_hashes(&request.object, GOVERNANCE_GROUP)?,
        };
        // Strict group-bound acceptance before any contract content reaches inference.
        let route = self
            .reader
            .admit_route(
                &request.object,
                &request.use_context,
                groups,
                self.source_selection.iter(),
                |ctx| self.accepts_on_route(ctx, &view),
            )
            .map_err(|_| refused("tn_governed_use_denied"))?;
        Ok((view, checked, route))
    }

    /// Admission of one object on the request's route, its lineage checked on its own view.
    fn accepts_on_route(
        &self,
        context: &AdmissionContext<'_>,
        request_view: &GovernanceView,
    ) -> tn_core::Result<bool> {
        let id = context.object().id();
        if id == request_view.object().id() {
            return self.accepts(context, request_view);
        }
        let view = match self.retained.get(id) {
            Some(view) => view.clone(),
            None => self.reader.governance(context.object())?,
        };
        self.accepts(context, &view)
    }

    /// The per-object governance hash key the model is shown and passes back to decrypt.
    pub fn governance_hash_key(&self, view: &GovernanceView) -> Result<String, TnLlamaError> {
        self.reader
            .governance_hash_key(view)
            .map_err(|_| refused("tn_governed_governance_invalid"))
    }

    /// The governance hash key of the object that supplies a routed group.
    pub fn supplier_hash_key(&self, supplier: &AdmittedObject) -> Result<String, TnLlamaError> {
        self.governance_hash_key(supplier.view())
    }

    /// Open the selected groups, all supplied by one object on the route, under the
    /// governance hash key the model passed, and assemble them under the request object.
    pub fn open(
        &self,
        route: &AdmittedRoute,
        groups: &BTreeSet<String>,
        governance_hash: &str,
    ) -> Result<DataObject, TnLlamaError> {
        let supplier = groups
            .iter()
            .next()
            .and_then(|group| route.supplier(group))
            .filter(|supplier| {
                groups.iter().all(|group| {
                    route
                        .supplier(group)
                        .is_some_and(|other| other.object().id() == supplier.object().id())
                })
            })
            .ok_or_else(|| refused("tn_governed_group_open_failed"))?;
        // The reader checks each group's field hashes against the object that holds it.
        let opened = self
            .reader
            .open_with_hash_key(supplier, groups, governance_hash)
            .map_err(|_| refused("tn_governed_group_open_failed"))?;
        self.reader
            .assemble(route, vec![opened])
            .map_err(|_| refused("tn_governed_group_open_failed"))
    }
}

pub(crate) fn refused(code: &'static str) -> TnLlamaError {
    session_error(
        code,
        "governed object request does not satisfy the receiver's configured profile",
    )
}
