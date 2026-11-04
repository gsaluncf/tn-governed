//! The governed output publisher: native report and tool publications, independently read back.

use serde_json::{json, Value};

use crate::config::{output_state_is_separate, RuntimeConfig};
use crate::error::{AdmissionStage, TnLlamaError};
use crate::governance::{GovernanceKeyProvenance, GovernanceReader};

const DEFAULT_GROUP: &str = "default";
const GOVERNANCE_GROUP: &str = "tn.agents";

/// Signed report and receipt output, published as native TN objects and read back independently.
pub(crate) struct GovernedOutputPublisher {
    objects: tn_core::runtime::Objects<'static>,
    reader: tn_core::governed::GovernedReader,
    release_register_enabled: bool,
}

pub(crate) struct GovernedPublication {
    pub object: tn_core::governed::GovernedObject,
    pub view: tn_core::governed::GovernanceView,
    pub data: tn_core::governed::DataObject,
    pub register_error: Option<String>,
    pub register_enabled: bool,
}

impl GovernedOutputPublisher {
    pub fn from_config(config: &RuntimeConfig) -> Result<Self, TnLlamaError> {
        if !output_state_is_separate(config) {
            return Err(output_error(
                "tn_output_state_alias",
                "source and output material must be separate",
            ));
        }
        let objects =
            tn_core::runtime::Objects::open(&config.output_tn_config_path).map_err(|_| {
                output_error(
                    "tn_output_init_failed",
                    "native output context could not be opened",
                )
            })?;
        let native_config = tn_core::config::load(&config.output_tn_config_path).map_err(|_| {
            output_error(
                "tn_output_init_failed",
                "native output configuration could not be read",
            )
        })?;
        if native_config.ceremony.id != config.output_ceremony_id
            || ["default", "tn.agents"].iter().any(|name| {
                native_config.groups.get(*name).is_none_or(|group| {
                    group.policy != "private" || group.index_epoch != config.output_index_epoch
                })
            })
        {
            return Err(output_error(
                "tn_output_config_mismatch",
                "native output provenance and private groups must match",
            ));
        }
        let mut reader = tn_core::governed::GovernedReader::new();
        for group in ["default", "tn.agents"] {
            let kit = std::fs::read(
                config
                    .output_reader_key_dir
                    .join(format!("{group}.btn.mykit")),
            )
            .map_err(|_| {
                output_error(
                    "tn_output_init_failed",
                    "independent output reader capability is absent",
                )
            })?;
            let cipher =
                tn_core::cipher::btn::BtnReaderCipher::from_kit_bytes(&kit).map_err(|_| {
                    output_error(
                        "tn_output_init_failed",
                        "independent output reader capability is invalid",
                    )
                })?;
            reader = reader
                .with_group(group, std::sync::Arc::new(cipher))
                .map_err(|_| {
                    output_error(
                        "tn_output_init_failed",
                        "independent output reader could not be built",
                    )
                })?;
        }
        let verifier = GovernanceReader::from_paths(
            &config.output_reader_key_dir,
            &config.output_index_key_path,
            GovernanceKeyProvenance::new(
                &config.output_ceremony_id,
                "tn.agents",
                config.output_index_epoch,
            ),
        )?;
        // Bound output groups open only under the governance hash key, which the
        // independent reader derives with the output governance index key. With each
        // group's index key, the reader also recomputes that group's field hashes.
        let governance_key = verifier.group_index_key(GOVERNANCE_GROUP)?;
        let default_key = verifier.group_index_key(DEFAULT_GROUP)?;
        let reader = reader
            .with_governance_index_key(&governance_key)
            .and_then(|reader| reader.with_group_index_key(DEFAULT_GROUP, &default_key))
            .map_err(|_| {
                output_error(
                    "tn_output_init_failed",
                    "independent output reader could not be built",
                )
            })?;
        Ok(Self {
            objects,
            reader,
            release_register_enabled: std::env::var_os("TN_OBJECT_RELEASE_REGISTER")
                .is_some_and(|value| !value.is_empty()),
        })
    }

    pub fn emit(
        &self,
        data: &tn_core::governed::DataObject,
        report_html: &str,
        object_type: &str,
        request: &crate::AcceptedGovernedRequest,
        source: &tn_core::governed::GovernanceView,
        input: &crate::governed_input::GovernedInputRuntime,
        tools: &[GovernedPublication],
    ) -> Result<GovernedPublication, TnLlamaError> {
        let mut candidate = data.clone();
        for tool in tools {
            candidate.include(&tool.data).map_err(|_| {
                output_error(
                    "tn_output_release_denied",
                    "authenticated tool result could not be included",
                )
            })?;
        }
        let parents = std::iter::once(source)
            .chain(tools.iter().map(|tool| &tool.view))
            .collect::<Vec<_>>();
        self.publish(
            candidate,
            json!({"report_html":report_html}),
            object_type,
            request,
            &parents,
            input,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn publish(
        &self,
        mut candidate: tn_core::governed::DataObject,
        content: Value,
        object_type: &str,
        request: &crate::AcceptedGovernedRequest,
        parents: &[&tn_core::governed::GovernanceView],
        input: &crate::governed_input::GovernedInputRuntime,
        attach_report_policy: bool,
    ) -> Result<GovernedPublication, TnLlamaError> {
        candidate
            .set_group("default", &content)
            .and_then(|()| candidate.retain_groups(["default"]))
            .map_err(|_| {
                output_error(
                    "tn_report_proposal_invalid",
                    "report content could not be projected",
                )
            })?;
        if let Some(policy) = input
            .report_policy
            .as_ref()
            .filter(|_| attach_report_policy)
        {
            self.objects
                .attach(&mut candidate, policy.clone(), |context| {
                    Ok(context.authority() == self.objects.did() && context.policy() == policy)
                })
                .map_err(|_| {
                    output_error(
                        "tn_output_release_denied",
                        "configured report contract attachment failed",
                    )
                })?;
        }
        let expected_policies = candidate.policies().map_err(|_| {
            output_error("tn_output_release_denied", "report contract set is invalid")
        })?;
        let expected_bindings = candidate.dataset_bindings().map_err(|_| {
            output_error(
                "tn_output_release_denied",
                "publication bindings are invalid",
            )
        })?;
        let output = self
            .objects
            .release_for(
                &mut candidate,
                object_type,
                &request.use_context,
                &request.destination,
                |ctx| {
                    Ok(ctx.use_context() == Some(&input.config.use_context)
                        && input.config.destinations.contains(ctx.destination())
                        && ctx.data().sources().len() == parents.len()
                        && parents.iter().all(|parent| {
                            ctx.data().sources().iter().any(|reference| {
                                reference
                                    .references_with_policy(parent.object(), parent.governance())
                            })
                        })
                        && ctx.data().dataset_bindings()? == expected_bindings
                        && ctx.data().policies()? == expected_policies)
                },
            )
            .map_err(|_| {
                output_error(
                    "tn_output_release_denied",
                    "native report release was refused",
                )
            })?;
        // Optional register I/O never invalidates or regenerates the signed wire.
        let register_error = candidate.register_error().map(str::to_owned);
        if output.writer() != self.objects.did()
            || output.object_type() != object_type
            || output.group_names() != vec!["default", "tn.agents"]
        {
            return Err(output_error(
                "tn_output_readback_failed",
                "native output identity or group projection changed",
            ));
        }
        let view = self.reader.governance(&output).map_err(|_| {
            output_error(
                "tn_output_readback_failed",
                "output governance did not open",
            )
        })?;
        let admitted = view
            .clone()
            .accept(request.use_context.clone(), ["default"], |ctx| {
                Ok(input.accepts_output(ctx, &view, parents)?
                    && ctx.policies()? == expected_policies
                    && ctx.governance().dataset_bindings()? == expected_bindings
                    && ctx.governance().fields()["release_context"]
                        == json!({
                            "application": request.use_context.application(),
                            "purpose": request.use_context.purpose(),
                            "operation": request.use_context.operation(),
                            "destination": request.destination,
                        }))
            })
            .map_err(|_| {
                output_error(
                    "tn_output_readback_failed",
                    "output inherited governance failed admission",
                )
            })?;
        let opened = self
            .reader
            .open(&admitted, ["default"])
            .map_err(|_| output_error("tn_output_readback_failed", "output report did not open"))?;
        if opened.groups()["default"] != content {
            return Err(output_error(
                "tn_output_readback_failed",
                "output report differs from accepted content",
            ));
        }
        Ok(GovernedPublication {
            object: output,
            view,
            data: tn_core::governed::DataObject::from_opened(opened).map_err(|_| {
                output_error(
                    "tn_output_readback_failed",
                    "publication could not be retained as admitted data",
                )
            })?,
            register_error,
            register_enabled: self.release_register_enabled,
        })
    }
}

fn output_error(code: &'static str, message: &'static str) -> TnLlamaError {
    TnLlamaError::new(code, AdmissionStage::Output, message)
}
