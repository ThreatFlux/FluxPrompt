//! Mitigation engine for handling detected prompt injection threats.

use std::sync::Arc;
use tracing::{debug, instrument};

use super::TextSanitizer;
use crate::config::{DetectionConfig, ResponseStrategy};
use crate::detection::DetectionResult;
use crate::error::Result;

/// Engine responsible for applying mitigation strategies to detected threats.
pub struct MitigationEngine {
    sanitizer: Arc<TextSanitizer>,
    config: DetectionConfig,
}

impl MitigationEngine {
    /// Creates a new mitigation engine.
    #[instrument(skip(config))]
    pub async fn new(config: &DetectionConfig) -> Result<Self> {
        debug!("Initializing mitigation engine");

        let sanitizer = Arc::new(TextSanitizer::new(config)?);

        Ok(Self {
            sanitizer,
            config: config.clone(),
        })
    }

    /// Applies appropriate mitigation strategy based on detection results.
    #[instrument(skip(self, original_prompt, detection_result))]
    pub async fn mitigate(
        &self,
        original_prompt: &str,
        detection_result: &DetectionResult,
    ) -> Result<String> {
        debug!(
            "Applying mitigation for {} threats with risk level {:?}",
            detection_result.threats().len(),
            detection_result.risk_level()
        );

        match &self.config.response_strategy {
            ResponseStrategy::Allow => {
                debug!("Allow strategy: returning original prompt with warning");
                Ok(self.add_warning_prefix(original_prompt))
            }
            ResponseStrategy::Block => {
                debug!("Block strategy: blocking prompt entirely");
                Ok(self.generate_block_message(detection_result))
            }
            ResponseStrategy::Sanitize => {
                debug!("Sanitize strategy: cleaning prompt");
                self.sanitizer
                    .sanitize(original_prompt, detection_result)
                    .await
            }
            ResponseStrategy::Warn => {
                debug!("Warn strategy: returning warning message");
                Ok(self.generate_warning_message(detection_result))
            }
            ResponseStrategy::Custom(message) => {
                debug!("Custom strategy: returning custom message");
                Ok(message.clone())
            }
        }
    }

    /// Adds a warning prefix to the original prompt.
    fn add_warning_prefix(&self, original_prompt: &str) -> String {
        format!(
            "[WARNING: Potential prompt injection detected] {}",
            original_prompt
        )
    }

    /// Generates a block message for detected threats.
    fn generate_block_message(&self, detection_result: &DetectionResult) -> String {
        let threat_count = detection_result.threats().len();
        let risk_level = detection_result.risk_level();

        format!(
            "Request blocked due to security policy. Detected {} potential threat(s) with risk level: {:?}. Please revise your request and try again.",
            threat_count,
            risk_level
        )
    }

    /// Generates a warning message for detected threats.
    fn generate_warning_message(&self, detection_result: &DetectionResult) -> String {
        let threat_types: Vec<String> = detection_result
            .threats()
            .iter()
            .map(|t| format!("{:?}", t.threat_type))
            .collect();

        let unique_threats: std::collections::HashSet<_> = threat_types.iter().collect();

        format!(
            "Security Warning: Potential prompt injection detected. Threat types: {}. Risk level: {:?}. Please be cautious with your request.",
            unique_threats.into_iter().cloned().collect::<Vec<_>>().join(", "),
            detection_result.risk_level()
        )
    }

    /// Updates the mitigation configuration.
    pub async fn update_config(&mut self, config: &DetectionConfig) -> Result<()> {
        debug!("Updating mitigation engine configuration");

        self.sanitizer = Arc::new(TextSanitizer::new(config)?);
        self.config = config.clone();

        Ok(())
    }

    /// Returns the current response strategy.
    pub fn response_strategy(&self) -> &ResponseStrategy {
        &self.config.response_strategy
    }

    /// Tests if a given prompt would be mitigated.
    pub async fn would_mitigate(&self, detection_result: &DetectionResult) -> bool {
        matches!(
            self.config.response_strategy,
            ResponseStrategy::Block
                | ResponseStrategy::Sanitize
                | ResponseStrategy::Warn
                | ResponseStrategy::Custom(_)
        ) && detection_result.is_injection_detected()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DetectionConfig, ResponseStrategy};
    use crate::detection::DetectionResult;
    use crate::types::{RiskLevel, ThreatInfo, ThreatType};

    #[tokio::test]
    async fn test_mitigation_engine_creation() {
        let config = DetectionConfig::default();
        let engine = MitigationEngine::new(&config).await;
        assert!(engine.is_ok());
    }

    #[tokio::test]
    async fn test_allow_strategy() {
        let config = DetectionConfig {
            response_strategy: ResponseStrategy::Allow,
            ..DetectionConfig::default()
        };

        let engine = MitigationEngine::new(&config).await.unwrap();
        let detection_result = create_test_detection_result();

        let result = engine
            .mitigate("Test prompt", &detection_result)
            .await
            .unwrap();
        assert!(result.contains("WARNING"));
        assert!(result.contains("Test prompt"));
    }

    #[tokio::test]
    async fn test_block_strategy() {
        let config = DetectionConfig {
            response_strategy: ResponseStrategy::Block,
            ..DetectionConfig::default()
        };

        let engine = MitigationEngine::new(&config).await.unwrap();
        let detection_result = create_test_detection_result();

        let result = engine
            .mitigate("Test prompt", &detection_result)
            .await
            .unwrap();
        assert!(result.contains("blocked"));
        assert!(result.contains("security policy"));
    }

    #[tokio::test]
    async fn test_warn_strategy() {
        let config = DetectionConfig {
            response_strategy: ResponseStrategy::Warn,
            ..DetectionConfig::default()
        };

        let engine = MitigationEngine::new(&config).await.unwrap();
        let detection_result = create_test_detection_result();

        let result = engine
            .mitigate("Test prompt", &detection_result)
            .await
            .unwrap();
        assert!(result.contains("Security Warning"));
        assert!(result.contains("InstructionOverride"));
    }

    #[tokio::test]
    async fn test_custom_strategy() {
        let config = DetectionConfig {
            response_strategy: ResponseStrategy::Custom("Custom response message".to_string()),
            ..DetectionConfig::default()
        };

        let engine = MitigationEngine::new(&config).await.unwrap();
        let detection_result = create_test_detection_result();

        let result = engine
            .mitigate("Test prompt", &detection_result)
            .await
            .unwrap();
        assert_eq!(result, "Custom response message");
    }

    #[tokio::test]
    async fn test_would_mitigate() {
        let config = DetectionConfig {
            response_strategy: ResponseStrategy::Block,
            ..DetectionConfig::default()
        };

        let engine = MitigationEngine::new(&config).await.unwrap();
        let detection_result = create_test_detection_result();

        assert!(engine.would_mitigate(&detection_result).await);

        let safe_result = DetectionResult::safe();
        assert!(!engine.would_mitigate(&safe_result).await);
    }

    fn create_test_detection_result() -> DetectionResult {
        let threat = ThreatInfo {
            threat_type: ThreatType::InstructionOverride,
            confidence: 0.9,
            span: None,
            metadata: std::collections::HashMap::new(),
        };

        DetectionResult::new(RiskLevel::High, 0.9, vec![threat], 100)
    }
}
