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
                return match validate_pod(&pod_spec) {
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

fn validate_pod(pod: &apicore::PodSpec) -> Result<bool> {
    for container in &pod.containers {
        let container_valid = validate_container(container);
        if !container_valid {
            return Err(anyhow!("Privileged container is not allowed"));
        }
    }
    if let Some(init_containers) = &pod.init_containers {
        for container in init_containers {
            let container_valid = validate_container(container);
            if !container_valid {
                return Err(anyhow!("Privileged init container is not allowed"));
            }
        }
    }
    if let Some(ephemeral_containers) = &pod.ephemeral_containers {
        for container in ephemeral_containers {
            let container_valid = validate_ephemeral_container(container);
            if !container_valid {
                return Err(anyhow!("Privileged ephemeral container is not allowed"));
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

    #[test]
    fn accept_pod_when_all_ephemeral_containers_are_not_privileged_test() -> Result<()> {
        let result = validate_pod(&apicore::PodSpec {
            ephemeral_containers: Some(vec![
                apicore::EphemeralContainer {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(false),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::EphemeralContainer::default()
                },
                apicore::EphemeralContainer {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(false),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::EphemeralContainer::default()
                },
                apicore::EphemeralContainer {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(false),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::EphemeralContainer::default()
                },
            ]),
            ..apicore::PodSpec::default()
        });
        assert!(
            result.is_ok(),
            "Pod with no privileged ephemeral container should be accepted by the validator"
        );
        Ok(())
    }

    #[test]
    fn reject_pod_when_all_ephemeral_container_is_privileged_test() -> Result<()> {
        let result = validate_pod(&apicore::PodSpec {
            ephemeral_containers: Some(vec![
                apicore::EphemeralContainer {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(true),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::EphemeralContainer::default()
                },
                apicore::EphemeralContainer {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(true),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::EphemeralContainer::default()
                },
                apicore::EphemeralContainer {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(true),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::EphemeralContainer::default()
                },
            ]),
            ..apicore::PodSpec::default()
        });
        assert!(
            result.is_err(),
            "Pod with all privileged ephemeral container should be rejected by the validator"
        );
        Ok(())
    }

    #[test]
    fn reject_pod_when_one_ephemeral_container_is_privileged_test() -> Result<()> {
        let result = validate_pod(&apicore::PodSpec {
            ephemeral_containers: Some(vec![
                apicore::EphemeralContainer {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(false),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::EphemeralContainer::default()
                },
                apicore::EphemeralContainer {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(false),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::EphemeralContainer::default()
                },
                apicore::EphemeralContainer {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(true),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::EphemeralContainer::default()
                },
            ]),
            ..apicore::PodSpec::default()
        });
        assert!(result.is_err(),
            "Pod with only a single privileged ephemeral container should be rejected by the validator"
        );
        Ok(())
    }

    #[test]
    fn accept_pod_when_init_containers_are_not_privileged_test() -> Result<()> {
        let result = validate_pod(&apicore::PodSpec {
            init_containers: Some(vec![
                apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(false),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                },
                apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(false),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                },
                apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(false),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                },
            ]),
            ..apicore::PodSpec::default()
        });
        assert!(
            result.is_ok(),
            "Pod with no privileged init container should be accepted by the validator"
        );
        Ok(())
    }

    #[test]
    fn reject_pod_when_one_init_container_is_privileged_test() -> Result<()> {
        let result = validate_pod(&apicore::PodSpec {
            init_containers: Some(vec![
                apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(false),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                },
                apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(false),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                },
                apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(true),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                },
            ]),
            ..apicore::PodSpec::default()
        });
        assert!(
            result.is_err(),
            "Pod with only a single privileged init container should be rejected by the validator"
        );
        Ok(())
    }

    #[test]
    fn reject_pod_when_all_init_containers_are_privileged_test() -> Result<()> {
        let result = validate_pod(&apicore::PodSpec {
            init_containers: Some(vec![
                apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(true),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                },
                apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(true),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                },
                apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(true),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                },
            ]),
            ..apicore::PodSpec::default()
        });
        assert!(
            result.is_err(),
            "Pod with all privileged init containers should be rejected by the validator"
        );
        Ok(())
    }

    #[test]
    fn accecpt_pod_when_containers_are_not_privileged_test() -> Result<()> {
        let result = validate_pod(&apicore::PodSpec {
            containers: vec![
                apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(false),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                },
                apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(false),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                },
                apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(false),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                },
            ],
            ..apicore::PodSpec::default()
        });
        assert!(
            result.is_ok(),
            "Pod with no privileged container should be accepted by the validator"
        );
        Ok(())
    }

    #[test]
    fn reject_pod_when_one_container_is_privileged_test() -> Result<()> {
        let result = validate_pod(&apicore::PodSpec {
            containers: vec![
                apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(false),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                },
                apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(false),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                },
                apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(true),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                },
            ],
            ..apicore::PodSpec::default()
        });

        assert!(
            result.is_err(),
            "Pod with only a single privileged container should be rejected by the validator"
        );
        Ok(())
    }

    #[test]
    fn reject_pod_when_all_containers_are_privileged_test() -> Result<()> {
        let result = validate_pod(&apicore::PodSpec {
            containers: vec![
                apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(true),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                },
                apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(true),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                },
                apicore::Container {
                    security_context: Some(apicore::SecurityContext {
                        privileged: Some(true),
                        ..apicore::SecurityContext::default()
                    }),
                    ..apicore::Container::default()
                },
            ],
            ..apicore::PodSpec::default()
        });
        assert!(
            result.is_err(),
            "Pod with all privileged containers should be rejected by the validator"
        );
        Ok(())
    }

    #[test]
    fn accept_container_is_not_privileged_test() -> Result<()> {
        assert_eq!(
            validate_container(&apicore::Container {
                security_context: Some(apicore::SecurityContext {
                    privileged: Some(false),
                    ..apicore::SecurityContext::default()
                }),
                ..apicore::Container::default()
            }),
            true,
            "Non privileged container should be accepted by the validator"
        );
        Ok(())
    }

    #[test]
    fn accept_container_with_no_security_context() -> Result<()> {
        assert_eq!(
            validate_container(&apicore::Container {
                ..apicore::Container::default()
            }),
            true,
            "Non privileged container should be accepted by the validator"
        );
        Ok(())
    }

    #[test]
    fn reject_privileged_container_test() -> Result<()> {
        assert_eq!(
            validate_container(&apicore::Container {
                security_context: Some(apicore::SecurityContext {
                    privileged: Some(true),
                    ..apicore::SecurityContext::default()
                }),
                ..apicore::Container::default()
            }),
            false,
            "Privileged container should be rejected by the validator"
        );
        Ok(())
    }

    #[test]
    fn accept_privileged_container_when_privileged_is_none_test() -> Result<()> {
        assert_eq!(
            validate_container(&apicore::Container {
                security_context: Some(apicore::SecurityContext {
                    privileged: None,
                    ..apicore::SecurityContext::default()
                }),
                ..apicore::Container::default()
            }),
            true,
            "Privileged container should be accepted by the validator when there is no 'privileged' configuration. The default behaviour is disable privileged containers"
        );
        Ok(())
    }

    #[test]
    fn accept_ephemeral_container_is_not_privileged_test() -> Result<()> {
        assert_eq!(
            validate_ephemeral_container(&apicore::EphemeralContainer {
                security_context: Some(apicore::SecurityContext {
                    privileged: Some(false),
                    ..apicore::SecurityContext::default()
                }),
                ..apicore::EphemeralContainer::default()
            }),
            true,
            "Non privileged container should be accepted by the validator"
        );
        Ok(())
    }

    #[test]
    fn accept_ephemeral_container_with_no_security_context() -> Result<()> {
        assert_eq!(
            validate_ephemeral_container(&apicore::EphemeralContainer {
                ..apicore::EphemeralContainer::default()
            }),
            true,
            "Non privileged container should be accepted by the validator"
        );
        Ok(())
    }

    #[test]
    fn reject_privileged_ephemeral_container_test() -> Result<()> {
        assert_eq!(
            validate_ephemeral_container(&apicore::EphemeralContainer {
                security_context: Some(apicore::SecurityContext {
                    privileged: Some(true),
                    ..apicore::SecurityContext::default()
                }),
                ..apicore::EphemeralContainer::default()
            }),
            false,
            "Privileged container should be rejected by the validator"
        );
        Ok(())
    }

    #[test]
    fn accept_privileged_ephemeral_container_when_privileged_is_none_test() -> Result<()> {
        assert_eq!(
            validate_ephemeral_container(&apicore::EphemeralContainer {
                security_context: Some(apicore::SecurityContext {
                    privileged: None,
                    ..apicore::SecurityContext::default()
                }),
                ..apicore::EphemeralContainer::default()
            }),
            true,
            "Privileged container should be accepted by the validator when there is no 'privileged' configuration. The default behaviour is disable privileged containers"
        );
        Ok(())
    }
}
