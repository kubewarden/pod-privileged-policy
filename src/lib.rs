use anyhow::{anyhow, Result};
use lazy_static::lazy_static;

use guest::prelude::*;
use kubewarden_policy_sdk::wapc_guest as guest;

use k8s_openapi::api::core::v1 as apicore;

extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{logging, protocol_version_guest, request::ValidationRequest, validate_settings};

mod settings;
use settings::Settings;

use slog::{info, o, Logger};

lazy_static! {
    static ref LOG_DRAIN: Logger = Logger::root(
        logging::KubewardenDrain::new(),
        o!("policy" => "sample-policy")
    );
}

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;
    info!(LOG_DRAIN, "starting validation");

    match validation_request.extract_pod_spec_from_object() {
        Ok(pod_spec) => {
            if let Some(pod_spec) = pod_spec {
                return match validate_pod(&pod_spec, &validation_request.settings) {
                    Ok(_) => kubewarden::accept_request(),
                    Err(err) => kubewarden::reject_request(Some(err.to_string()), None, None, None),
                };
            };
            // If there is not pod spec, just accept it. There is no data to be
            // validated.
            kubewarden::accept_request()
        }
        Err(_) => kubewarden::reject_request(
            Some("Cannot parse validation request".to_string()),
            None,
            None,
            None,
        ),
    }
}

fn validate_pod(pod: &apicore::PodSpec, settings: &Settings) -> Result<bool> {
    for container in &pod.containers {
        let container_valid = validate_container(container);
        if !container_valid {
            return Err(anyhow!("Privileged container is not allowed"));
        }
    }
    if !settings.skip_init_containers {
        if let Some(init_containers) = &pod.init_containers {
            for container in init_containers {
                let container_valid = validate_container(container);
                if !container_valid {
                    return Err(anyhow!("Privileged init container is not allowed"));
                }
            }
        }
    }
    if !settings.skip_ephemeral_containers {
        if let Some(ephemeral_containers) = &pod.ephemeral_containers {
            for container in ephemeral_containers {
                let container_valid = validate_ephemeral_container(container);
                if !container_valid {
                    return Err(anyhow!("Privileged ephemeral container is not allowed"));
                }
            }
        }
    }
    Ok(true)
}

fn validate_ephemeral_container(container: &apicore::EphemeralContainer) -> bool {
    if let Some(security_context) = &container.security_context {
        return !security_context.privileged.unwrap_or(false);
    }
    true
}

fn validate_container(container: &apicore::Container) -> bool {
    if let Some(security_context) = &container.security_context {
        return !security_context.privileged.unwrap_or(false);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn pod_factory(
        containers_privileged: Option<Vec<bool>>,
        init_container_privileged: Option<Vec<bool>>,
        ephemeral_container_privileged: Option<Vec<bool>>,
    ) -> apicore::PodSpec {
        let mut containers: Vec<apicore::Container> = Vec::new();
        let mut init_containers: Option<Vec<apicore::Container>> = None;
        let mut ephemeral_containers: Option<Vec<apicore::EphemeralContainer>> = None;

        if let Some(containers_values) = containers_privileged {
            containers = containers_values
                .into_iter()
                .map(|privileged| apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(privileged),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                })
                .collect();
        }
        if let Some(ephemeral_container_privileged_values) = ephemeral_container_privileged {
            ephemeral_containers = Some(
                ephemeral_container_privileged_values
                    .into_iter()
                    .map(|privileged| apicore::EphemeralContainer {
                        security_context: Some(apicore::SecurityContext {
                            privileged: Some(privileged),
                            ..apicore::SecurityContext::default()
                        }),
                        ..apicore::EphemeralContainer::default()
                    })
                    .collect(),
            );
        }
        if let Some(init_container_privileged_values) = init_container_privileged {
            init_containers = Some(
                init_container_privileged_values
                    .into_iter()
                    .map(|privileged| apicore::Container {
                        security_context: Some(apicore::SecurityContext {
                            privileged: Some(privileged),
                            ..apicore::SecurityContext::default()
                        }),
                        ..apicore::Container::default()
                    })
                    .collect(),
            );
        }
        apicore::PodSpec {
            containers,
            ephemeral_containers,
            init_containers,
            ..Default::default()
        }
    }

    #[rstest]
    #[case::accept_pod_when_all_ephemeral_containers_are_not_privileged_test2(pod_factory(None, None, Some(vec![false,false,false])), Settings::default(), Ok(true), "Pod with no privileged ephemeral container should be accepted by the validator")]
    #[case::reject_pod_when_all_ephemeral_container_is_privileged_test(pod_factory(None, None, Some(vec![true, true, true])), Settings::default(), Err(anyhow!("")), "Pod with all privileged ephemeral container should be rejected by the validator")]
    #[case::reject_pod_when_one_ephemeral_container_is_privileged_test(pod_factory(None, None, Some(vec![false, false, true])), Settings::default(), Err(anyhow!("")), "Pod with only a single privileged ephemeral container should be rejected by the validator")]
    #[case::accept_pod_when_init_containers_are_not_privileged_test(pod_factory(None, Some(vec![false, false, false]), None), Settings::default(), Ok(true), "Pod with no privileged init container should be accepted by the validator")]
    #[case::reject_pod_when_one_init_container_is_privileged_test(pod_factory(None, Some(vec![false, false, true]), None), Settings::default(), Err(anyhow!("")), "Pod with only a single privileged init container should be rejected by the validator")]
    #[case::accept_pod_when_containers_are_privileged_and_policy_should_ignore_test(pod_factory(Some(vec![false]), Some(vec![false, true]), Some(vec![false, true])), Settings { skip_init_containers: true, skip_ephemeral_containers: true, }, Ok(true), "Pod should be accepted if settings is configured to ignore init and ephemeral containers")]
    #[case::reject_pod_when_all_init_containers_are_privileged_test(pod_factory(None, Some(vec![true, true, true]), None), Settings::default(), Err(anyhow!("")), "Pod with all privileged init containers should be rejected by the validator")]
    #[case::accecpt_pod_when_containers_are_not_privileged_test(pod_factory(Some(vec![false, false, false]), None, None), Settings::default(), Ok(true), "Pod with no privileged container should be accepted by the validator")]
    #[case::reject_pod_when_one_container_is_privileged_test(pod_factory(Some(vec![false, false, true]), None, None), Settings::default(), Err(anyhow!("")), "Pod with only a single privileged container should be rejected by the validator")]
    #[case::reject_pod_when_all_containers_are_privileged_test(pod_factory(Some(vec![true, true, true]), None, None), Settings::default(), Err(anyhow!("")), "Pod with all privileged containers should be rejected by the validator")]
    fn validate_pod_test(
        #[case] pod_spec: apicore::PodSpec,
        #[case] settings: Settings,
        #[case] expected_result: anyhow::Result<bool>,
        #[case] error_msg: String,
    ) {
        let result = validate_pod(&pod_spec, &settings);
        match expected_result {
            Ok(_) => assert!(result.is_ok(), "{}", error_msg.to_owned()),
            Err(_) => assert!(result.is_err(), "{}", error_msg.to_owned()),
        }
    }

    fn container_factory(privileged: Option<bool>) -> apicore::Container {
        apicore::Container {
            security_context: Some(apicore::SecurityContext {
                privileged,
                ..apicore::SecurityContext::default()
            }),
            ..apicore::Container::default()
        }
    }

    #[rstest]
    #[case::accept_container_is_not_privileged_test(
        container_factory(Some(false)),
        true,
        "Non privileged container should be accepted by the validator"
    )]
    #[case::accept_container_with_no_security_context(apicore::Container { ..apicore::Container::default() }, true, "Non privileged container should be accepted by the validator")]
    #[case::reject_privileged_container_test(
        container_factory(Some(true)),
        false,
        "Privileged container should be rejected by the validator"
    )]
    #[case::accept_privileged_container_when_privileged_is_none_test(container_factory(None), true, "Privileged container should be accepted by the validator when there is no 'privileged' configuration. The default behaviour is disable privileged containers")]
    fn validate_container_test(
        #[case] container: apicore::Container,
        #[case] expected_result: bool,
        #[case] error_msg: String,
    ) {
        assert_eq!(
            validate_container(&container),
            expected_result,
            "{}",
            error_msg
        )
    }

    fn ephemeral_container_factory(privileged: Option<bool>) -> apicore::EphemeralContainer {
        apicore::EphemeralContainer {
            security_context: Some(apicore::SecurityContext {
                privileged,
                ..apicore::SecurityContext::default()
            }),
            ..apicore::EphemeralContainer::default()
        }
    }

    #[rstest]
    #[case::accept_ephemeral_container_is_not_privileged_test(
        ephemeral_container_factory(Some(false)),
        true,
        "Non privileged container should be accepted by the validator"
    )]
    #[case::accept_ephemeral_container_with_no_security_context(apicore::EphemeralContainer { ..apicore::EphemeralContainer::default() }, true, "Non privileged container should be accepted by the validator")]
    #[case::reject_privileged_ephemeral_container_test(
        ephemeral_container_factory(Some(true)),
        false,
        "Privileged container should be rejected by the validator"
    )]
    #[case::accept_privileged_ephemeral_container_when_privileged_is_none_test(ephemeral_container_factory(None), true, "Privileged container should be accepted by the validator when there is no 'privileged' configuration. The default behaviour is disable privileged containers")]
    fn validate_ephemeral_container_test(
        #[case] container: apicore::EphemeralContainer,
        #[case] expected_result: bool,
        #[case] error_msg: String,
    ) {
        assert_eq!(
            validate_ephemeral_container(&container),
            expected_result,
            "{}",
            error_msg
        );
    }
}
