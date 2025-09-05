//! Mitigation strategies for different types of prompt injection threats.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::ThreatType;

/// Available mitigation strategies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MitigationStrategy {
    /// Remove the detected threat entirely
    Remove,
    /// Replace with safe alternative
    Replace(String),
    /// Encode the threat to neutralize it
    Encode,
    /// Add warning prefix
    Prefix(String),
    /// Add warning suffix
    Suffix(String),
    /// Wrap in safe context
    Wrap {
        /// Prefix to add before content
        prefix: String,
        /// Suffix to add after content
        suffix: String,
    },
    /// Apply custom transformation
    Custom(String),
}

impl MitigationStrategy {
    /// Returns the default strategy for a given threat type.
    pub fn default_for_threat(threat_type: &ThreatType) -> Self {
        match threat_type {
            ThreatType::InstructionOverride => {
                MitigationStrategy::Replace("[INSTRUCTION_FILTERED]".to_string())
            }
            ThreatType::RolePlaying => MitigationStrategy::Replace("[ROLE_FILTERED]".to_string()),
            ThreatType::ContextConfusion => MitigationStrategy::Wrap {
                prefix: "[CONTEXT_START]".to_string(),
                suffix: "[CONTEXT_END]".to_string(),
            },
            ThreatType::EncodingBypass => MitigationStrategy::Encode,
            ThreatType::Jailbreak => {
                MitigationStrategy::Replace("[JAILBREAK_ATTEMPT_FILTERED]".to_string())
            }
            ThreatType::SocialEngineering => {
                MitigationStrategy::Prefix("[SOCIAL_ENGINEERING_WARNING] ".to_string())
            }
            ThreatType::DataExtraction => {
                MitigationStrategy::Replace("[DATA_REQUEST_FILTERED]".to_string())
            }
            ThreatType::SystemPromptLeak => {
                MitigationStrategy::Replace("[SYSTEM_QUERY_FILTERED]".to_string())
            }
            ThreatType::CodeInjection => MitigationStrategy::Replace("[CODE_FILTERED]".to_string()),
            ThreatType::Custom(_) => {
                MitigationStrategy::Replace("[CUSTOM_THREAT_FILTERED]".to_string())
            }
        }
    }

    /// Applies this strategy to the given text.
    pub fn apply(&self, text: &str, _threat_context: Option<&ThreatContext>) -> String {
        match self {
            MitigationStrategy::Remove => String::new(),
            MitigationStrategy::Replace(replacement) => replacement.clone(),
            MitigationStrategy::Encode => self.encode_text(text),
            MitigationStrategy::Prefix(prefix) => format!("{}{}", prefix, text),
            MitigationStrategy::Suffix(suffix) => format!("{}{}", text, suffix),
            MitigationStrategy::Wrap { prefix, suffix } => {
                format!("{}{}{}", prefix, text, suffix)
            }
            MitigationStrategy::Custom(template) => {
                // Simple template substitution
                template.replace("{original}", text)
            }
        }
    }

    /// Encodes text to neutralize potential threats.
    fn encode_text(&self, text: &str) -> String {
        // URL encode special characters that might be used in attacks
        text.chars()
            .map(|c| match c {
                '<' => "%3C".to_string(),
                '>' => "%3E".to_string(),
                '"' => "%22".to_string(),
                '\'' => "%27".to_string(),
                '&' => "%26".to_string(),
                '{' => "%7B".to_string(),
                '}' => "%7D".to_string(),
                '[' => "%5B".to_string(),
                ']' => "%5D".to_string(),
                '\\' => "%5C".to_string(),
                _ => c.to_string(),
            })
            .collect()
    }

    /// Returns true if this strategy preserves the original text content.
    pub fn preserves_content(&self) -> bool {
        matches!(
            self,
            MitigationStrategy::Prefix(_)
                | MitigationStrategy::Suffix(_)
                | MitigationStrategy::Wrap { .. }
                | MitigationStrategy::Encode
        )
    }

    /// Returns true if this strategy completely removes the threat.
    pub fn removes_threat(&self) -> bool {
        matches!(
            self,
            MitigationStrategy::Remove | MitigationStrategy::Replace(_)
        )
    }
}

/// Context information for threat mitigation.
#[derive(Debug, Clone)]
pub struct ThreatContext {
    /// The type of threat being mitigated
    pub threat_type: ThreatType,
    /// Confidence level of the threat detection
    pub confidence: f32,
    /// Position in the original text
    pub position: Option<(usize, usize)>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl ThreatContext {
    /// Creates a new threat context.
    pub fn new(threat_type: ThreatType, confidence: f32, position: Option<(usize, usize)>) -> Self {
        Self {
            threat_type,
            confidence,
            position,
            metadata: HashMap::new(),
        }
    }

    /// Adds metadata to the context.
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

/// Strategy selector for choosing appropriate mitigation strategies.
pub struct StrategySelector {
    threat_strategies: HashMap<ThreatType, MitigationStrategy>,
    default_strategy: MitigationStrategy,
}

impl StrategySelector {
    /// Creates a new strategy selector with default strategies.
    pub fn new() -> Self {
        let mut threat_strategies = HashMap::new();

        // Configure default strategies for each threat type
        threat_strategies.insert(
            ThreatType::InstructionOverride,
            MitigationStrategy::default_for_threat(&ThreatType::InstructionOverride),
        );
        threat_strategies.insert(
            ThreatType::RolePlaying,
            MitigationStrategy::default_for_threat(&ThreatType::RolePlaying),
        );
        threat_strategies.insert(
            ThreatType::ContextConfusion,
            MitigationStrategy::default_for_threat(&ThreatType::ContextConfusion),
        );
        threat_strategies.insert(
            ThreatType::EncodingBypass,
            MitigationStrategy::default_for_threat(&ThreatType::EncodingBypass),
        );
        threat_strategies.insert(
            ThreatType::Jailbreak,
            MitigationStrategy::default_for_threat(&ThreatType::Jailbreak),
        );
        threat_strategies.insert(
            ThreatType::SocialEngineering,
            MitigationStrategy::default_for_threat(&ThreatType::SocialEngineering),
        );
        threat_strategies.insert(
            ThreatType::DataExtraction,
            MitigationStrategy::default_for_threat(&ThreatType::DataExtraction),
        );

        Self {
            threat_strategies,
            default_strategy: MitigationStrategy::Replace("[FILTERED]".to_string()),
        }
    }

    /// Selects the appropriate strategy for a given threat context.
    pub fn select_strategy(&self, context: &ThreatContext) -> &MitigationStrategy {
        self.threat_strategies
            .get(&context.threat_type)
            .unwrap_or(&self.default_strategy)
    }

    /// Sets a custom strategy for a specific threat type.
    pub fn set_strategy(&mut self, threat_type: ThreatType, strategy: MitigationStrategy) {
        self.threat_strategies.insert(threat_type, strategy);
    }

    /// Sets the default strategy for unrecognized threats.
    pub fn set_default_strategy(&mut self, strategy: MitigationStrategy) {
        self.default_strategy = strategy;
    }

    /// Returns all configured strategies.
    pub fn strategies(&self) -> &HashMap<ThreatType, MitigationStrategy> {
        &self.threat_strategies
    }
}

impl Default for StrategySelector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mitigation_strategy_remove() {
        let strategy = MitigationStrategy::Remove;
        let result = strategy.apply("dangerous text", None);
        assert_eq!(result, "");
    }

    #[test]
    fn test_mitigation_strategy_replace() {
        let strategy = MitigationStrategy::Replace("[FILTERED]".to_string());
        let result = strategy.apply("dangerous text", None);
        assert_eq!(result, "[FILTERED]");
    }

    #[test]
    fn test_mitigation_strategy_encode() {
        let strategy = MitigationStrategy::Encode;
        let result = strategy.apply("<script>", None);
        assert_eq!(result, "%3Cscript%3E");
    }

    #[test]
    fn test_mitigation_strategy_prefix() {
        let strategy = MitigationStrategy::Prefix("[WARNING] ".to_string());
        let result = strategy.apply("suspicious text", None);
        assert_eq!(result, "[WARNING] suspicious text");
    }

    #[test]
    fn test_mitigation_strategy_suffix() {
        let strategy = MitigationStrategy::Suffix(" [FILTERED]".to_string());
        let result = strategy.apply("suspicious text", None);
        assert_eq!(result, "suspicious text [FILTERED]");
    }

    #[test]
    fn test_mitigation_strategy_wrap() {
        let strategy = MitigationStrategy::Wrap {
            prefix: "[START]".to_string(),
            suffix: "[END]".to_string(),
        };
        let result = strategy.apply("content", None);
        assert_eq!(result, "[START]content[END]");
    }

    #[test]
    fn test_mitigation_strategy_custom() {
        let strategy = MitigationStrategy::Custom("Filtered: {original}".to_string());
        let result = strategy.apply("test", None);
        assert_eq!(result, "Filtered: test");
    }

    #[test]
    fn test_strategy_preserves_content() {
        assert!(MitigationStrategy::Prefix("".to_string()).preserves_content());
        assert!(MitigationStrategy::Encode.preserves_content());
        assert!(!MitigationStrategy::Remove.preserves_content());
        assert!(!MitigationStrategy::Replace("".to_string()).preserves_content());
    }

    #[test]
    fn test_strategy_removes_threat() {
        assert!(MitigationStrategy::Remove.removes_threat());
        assert!(MitigationStrategy::Replace("".to_string()).removes_threat());
        assert!(!MitigationStrategy::Prefix("".to_string()).removes_threat());
        assert!(!MitigationStrategy::Encode.removes_threat());
    }

    #[test]
    fn test_threat_context_creation() {
        let context = ThreatContext::new(ThreatType::InstructionOverride, 0.9, Some((0, 10)));

        assert_eq!(context.threat_type, ThreatType::InstructionOverride);
        assert_eq!(context.confidence, 0.9);
        assert_eq!(context.position, Some((0, 10)));
    }

    #[test]
    fn test_strategy_selector() {
        let selector = StrategySelector::new();

        let context = ThreatContext::new(ThreatType::InstructionOverride, 0.9, None);

        let strategy = selector.select_strategy(&context);
        assert!(matches!(strategy, MitigationStrategy::Replace(_)));
    }

    #[test]
    fn test_strategy_selector_custom() {
        let mut selector = StrategySelector::new();
        selector.set_strategy(ThreatType::InstructionOverride, MitigationStrategy::Remove);

        let context = ThreatContext::new(ThreatType::InstructionOverride, 0.9, None);

        let strategy = selector.select_strategy(&context);
        assert!(matches!(strategy, MitigationStrategy::Remove));
    }

    #[test]
    fn test_default_strategies_for_threats() {
        let instruction_strategy =
            MitigationStrategy::default_for_threat(&ThreatType::InstructionOverride);
        assert!(matches!(
            instruction_strategy,
            MitigationStrategy::Replace(_)
        ));

        let jailbreak_strategy = MitigationStrategy::default_for_threat(&ThreatType::Jailbreak);
        assert!(matches!(jailbreak_strategy, MitigationStrategy::Replace(_)));

        let context_strategy =
            MitigationStrategy::default_for_threat(&ThreatType::ContextConfusion);
        assert!(matches!(context_strategy, MitigationStrategy::Wrap { .. }));
    }
}
