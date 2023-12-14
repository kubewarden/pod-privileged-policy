use serde::{Deserialize, Serialize};

// Describe the settings your policy expects when
// loaded by the policy server.
#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(default)]
pub(crate) struct Settings {
    pub skip_init_containers: bool,
    pub skip_ephemeral_containers: bool,
}

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        // This policy does not have settings.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kubewarden_policy_sdk::settings::Validatable;

    #[test]
    fn validate_settings() -> Result<(), ()> {
        let settings = Settings {
            ..Default::default()
        };

        assert!(settings.validate().is_ok());
        Ok(())
    }
}
