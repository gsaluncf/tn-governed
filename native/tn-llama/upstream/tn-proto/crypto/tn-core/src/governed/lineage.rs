//! Bounded verification of exact signed computation parents and selected origins.

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use super::contracts::base_contract;
use super::{
    invalid, DatasetBinding, DatasetCatalog, Governance, GovernanceView, PolicyDag, SourceReference,
};
use crate::Result;

/// The exact object identities reached by a successful lineage verification.
#[derive(Clone, Debug)]
pub struct VerifiedLineage {
    object_ids: Vec<String>,
    source_object_ids: Vec<String>,
}

impl VerifiedLineage {
    /// All verified publication identities, sorted for reproducible inspection.
    pub fn object_ids(&self) -> &[String] {
        &self.object_ids
    }

    /// Selected source publication identities reached by the signed graph.
    pub fn source_object_ids(&self) -> &[String] {
        &self.source_object_ids
    }
}

/// Follows retained publications without opening ancestor business groups.
///
/// The resolver supplies governance views accepted under the application's
/// writer trust rules. This verifier checks their exact identities, contract
/// continuity and selected origins; it does not grant a new permitted use.
#[derive(Clone, Debug)]
pub struct LineageVerifier {
    max_objects: usize,
    max_depth: usize,
}

impl Default for LineageVerifier {
    fn default() -> Self {
        Self {
            max_objects: 1024,
            max_depth: 64,
        }
    }
}

impl LineageVerifier {
    /// Bound resolver work and traversal depth independently of application input.
    pub fn new(max_objects: usize, max_depth: usize) -> Result<Self> {
        if max_objects == 0 || max_objects > 65536 || max_depth == 0 || max_depth > 256 {
            return Err(invalid(
                "lineage limits require 1..65536 objects and 1..256 depth",
            ));
        }
        Ok(Self {
            max_objects,
            max_depth,
        })
    }

    /// Verify exact parent identities, contract preservation, and selected origins.
    /// The resolver supplies only ancestor governance, never business plaintext.
    pub fn verify<F>(
        &self,
        view: &GovernanceView,
        catalog: &DatasetCatalog,
        dag: &PolicyDag,
        mut resolve: F,
    ) -> Result<VerifiedLineage>
    where
        F: FnMut(&str) -> Result<GovernanceView>,
    {
        let bindings = view.governance().dataset_bindings()?;
        let mut origins: BTreeMap<&str, Vec<&DatasetBinding>> = BTreeMap::new();
        for binding in &bindings {
            origins
                .entry(binding.source_object_id())
                .or_default()
                .push(binding);
        }
        let mut walk = Walk {
            limits: self,
            catalog,
            dag,
            origins,
            resolve: &mut resolve,
            visiting: BTreeSet::new(),
            visited: BTreeMap::new(),
            heights: BTreeMap::new(),
            views: BTreeMap::new(),
            verified: BTreeMap::new(),
        };
        walk.verify_bindings(&bindings)?;
        walk.views
            .insert(view.object().id().to_owned(), Rc::new(view.clone()));
        let roots = walk.visit(view, 0)?;
        let expected: BTreeSet<_> = bindings
            .iter()
            .map(|b| b.source_object_id().to_owned())
            .collect();
        if roots != expected {
            return Err(invalid(
                "declared dataset origins must be reached through signed parents",
            ));
        }
        Ok(VerifiedLineage {
            object_ids: walk.visited.into_keys().collect(),
            source_object_ids: roots.into_iter().collect(),
        })
    }
}

struct Walk<'a, F> {
    limits: &'a LineageVerifier,
    catalog: &'a DatasetCatalog,
    dag: &'a PolicyDag,
    origins: BTreeMap<&'a str, Vec<&'a DatasetBinding>>,
    resolve: &'a mut F,
    visiting: BTreeSet<String>,
    visited: BTreeMap<String, BTreeSet<String>>,
    heights: BTreeMap<String, usize>,
    views: BTreeMap<String, Rc<GovernanceView>>,
    verified: BTreeMap<String, DatasetBinding>,
}

impl<F: FnMut(&str) -> Result<GovernanceView>> Walk<'_, F> {
    /// The catalog and history are fixed for one walk, so each binding is checked once.
    fn verify_bindings(&mut self, bindings: &[DatasetBinding]) -> Result<()> {
        for binding in bindings {
            if self.verified.get(binding.edition_record_id()) != Some(binding) {
                self.catalog.verify_binding(binding, self.dag)?;
                self.verified
                    .insert(binding.edition_record_id().to_owned(), binding.clone());
            }
        }
        Ok(())
    }

    fn visit(&mut self, view: &GovernanceView, depth: usize) -> Result<BTreeSet<String>> {
        if depth > self.limits.max_depth {
            return Err(invalid("lineage depth limit exceeded"));
        }
        let id = view.object().id();
        if let Some(roots) = self.cached_roots(id, depth)? {
            return Ok(roots);
        }
        if self.views.len() > self.limits.max_objects {
            return Err(invalid("lineage object limit exceeded"));
        }
        self.visiting.insert(id.to_owned());
        let contracts: Vec<Governance> = view
            .governance()
            .policies()?
            .iter()
            .map(base_contract)
            .collect();
        let bindings = view.governance().dataset_bindings()?;
        self.verify_bindings(&bindings)?;
        let mut roots = self.verify_origins(view, &contracts)?;
        let mut height = 0;
        if roots.is_empty() {
            (roots, height) = self.visit_parents(view, &contracts, &bindings, depth)?;
        }
        self.visiting.remove(id);
        self.heights.insert(id.to_owned(), height);
        self.visited.insert(id.to_owned(), roots.clone());
        Ok(roots)
    }

    /// A cycle is refused; a verified subtree is reused while the path stays in depth.
    fn cached_roots(&self, id: &str, depth: usize) -> Result<Option<BTreeSet<String>>> {
        if self.visiting.contains(id) {
            return Err(invalid("source lineage contains a cycle"));
        }
        let Some(roots) = self.visited.get(id) else {
            return Ok(None);
        };
        if depth + self.heights[id] > self.limits.max_depth {
            return Err(invalid("lineage depth limit exceeded"));
        }
        Ok(Some(roots.clone()))
    }

    /// A catalog selection is the explicit traversal boundary. It authenticates
    /// the origin's complete contract without requiring its creation history.
    fn verify_origins(&self, view: &GovernanceView, contracts: &[Governance]) -> Result<BTreeSet<String>> {
        let id = view.object().id();
        let mut roots = BTreeSet::new();
        for binding in self.origins.get(id).into_iter().flatten() {
            let edition = self
                .catalog
                .get(binding.edition_record_id())
                .ok_or_else(|| invalid("lineage origin requires its accepted edition record"))?;
            if view.object().writer() != edition.source_writer()
                || view.object().object_type() != edition.source_type()
                || !edition
                    .source_groups()
                    .iter()
                    .all(|group| view.object().group_names().contains(&group.as_str()))
                || contracts.len() != edition.contracts().len()
            {
                return Err(invalid(
                    "selected origin must match its edition's source and contracts",
                ));
            }
            for binding in edition.contracts() {
                let expected = self
                    .dag
                    .select(binding.revision_id(), binding.scope(), |_| Ok(true))?;
                if !contracts.contains(&base_contract(&expected)) {
                    return Err(invalid(
                        "selected origin contract differs from its accepted revision",
                    ));
                }
            }
            roots.insert(id.to_owned());
        }
        Ok(roots)
    }

    /// Follow each signed parent, which the child must retain intact, and return the
    /// origins reached and the subtree height. The child's bindings must describe them.
    fn visit_parents(
        &mut self,
        view: &GovernanceView,
        contracts: &[Governance],
        bindings: &[DatasetBinding],
        depth: usize,
    ) -> Result<(BTreeSet<String>, usize)> {
        let carried: BTreeMap<&str, &DatasetBinding> = bindings
            .iter()
            .map(|binding| (binding.edition_record_id(), binding))
            .collect();
        let mut roots = BTreeSet::new();
        let mut height = 0;
        for reference in view.governance().source_references()? {
            let parent_id = reference.object_id();
            let parent = self.resolve_parent(parent_id)?;
            verify_parent_reference(&reference, &parent, contracts, &carried)?;
            roots.extend(self.visit(&parent, depth + 1)?);
            height = height.max(self.heights[parent_id] + 1);
        }
        let declared: BTreeSet<_> = bindings
            .iter()
            .map(|b| b.source_object_id().to_owned())
            .collect();
        if roots != declared {
            return Err(invalid(
                "dataset bindings must describe the reached origins",
            ));
        }
        Ok((roots, height))
    }

    /// The exact parent publication, resolved once per walk.
    fn resolve_parent(&mut self, parent_id: &str) -> Result<Rc<GovernanceView>> {
        if let Some(parent) = self.views.get(parent_id) {
            return Ok(Rc::clone(parent));
        }
        if self.views.len() >= self.limits.max_objects {
            return Err(invalid("lineage object limit exceeded"));
        }
        let parent = Rc::new((self.resolve)(parent_id)?);
        if parent.object().id() != parent_id {
            return Err(invalid(
                "lineage resolver returned a different publication",
            ));
        }
        self.views.insert(parent_id.to_owned(), Rc::clone(&parent));
        Ok(parent)
    }
}

/// The signed reference names this exact parent and groups it holds, and the child
/// retains every parent contract and dataset binding.
fn verify_parent_reference(
    reference: &SourceReference,
    parent: &GovernanceView,
    contracts: &[Governance],
    carried: &BTreeMap<&str, &DatasetBinding>,
) -> Result<()> {
    if !reference.references_with_policy(parent.object(), parent.governance())
        || !reference
            .groups()
            .iter()
            .all(|group| parent.object().group_names().contains(&group.as_str()))
    {
        return Err(invalid(
            "source reference must match the exact signed parent",
        ));
    }
    for inherited in parent.governance().policies()? {
        if !contracts.contains(&base_contract(&inherited)) {
            return Err(invalid("child must retain every parent contract"));
        }
    }
    for inherited in parent.governance().dataset_bindings()? {
        if carried.get(inherited.edition_record_id()) != Some(&&inherited) {
            return Err(invalid("child must retain every parent dataset binding"));
        }
    }
    Ok(())
}
