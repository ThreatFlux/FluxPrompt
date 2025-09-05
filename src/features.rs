//! Feature toggle system for FluxPrompt detection capabilities.
//!
//! This module provides granular control over individual detection features,
//! allowing users to enable or disable specific detection methods based on
//! their use case requirements.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Individual feature toggles for detection capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Features {
    /// Enable pattern-based detection using regex patterns
    pub pattern_matching: bool,
    /// Enable heuristic analysis for behavioral detection
    pub heuristic_analysis: bool,
    /// Enable semantic detection using embeddings/ML models
    pub semantic_detection: bool,
    /// Enable encoding/obfuscation bypass detection
    pub encoding_detection: bool,
    /// Enable social engineering pattern detection
    pub social_engineering_detection: bool,
    /// Enable context hijacking detection
    pub context_hijacking_detection: bool,
    /// Enable role-playing attack detection
    pub role_play_detection: bool,
    /// Enable data extraction attempt detection
    pub data_extraction_detection: bool,
    /// Enable multi-modal detection (images, audio, etc.)
    pub multi_modal_detection: bool,
    /// Enable custom pattern matching
    pub custom_patterns: bool,
    /// Enable jailbreak pattern detection
    pub jailbreak_detection: bool,
    /// Enable instruction override detection
    pub instruction_override_detection: bool,
    /// Enable code injection detection
    pub code_injection_detection: bool,
    /// Enable system prompt leak detection
    pub system_prompt_leak_detection: bool,
}

impl Features {
    /// Creates a new Features instance with all features enabled.
    pub fn all_enabled() -> Self {
        Self {
            pattern_matching: true,
            heuristic_analysis: true,
            semantic_detection: true,
            encoding_detection: true,
            social_engineering_detection: true,
            context_hijacking_detection: true,
            role_play_detection: true,
            data_extraction_detection: true,
            multi_modal_detection: true,
            custom_patterns: true,
            jailbreak_detection: true,
            instruction_override_detection: true,
            code_injection_detection: true,
            system_prompt_leak_detection: true,
        }
    }

    /// Creates a new Features instance with all features disabled.
    pub fn all_disabled() -> Self {
        Self {
            pattern_matching: false,
            heuristic_analysis: false,
            semantic_detection: false,
            encoding_detection: false,
            social_engineering_detection: false,
            context_hijacking_detection: false,
            role_play_detection: false,
            data_extraction_detection: false,
            multi_modal_detection: false,
            custom_patterns: false,
            jailbreak_detection: false,
            instruction_override_detection: false,
            code_injection_detection: false,
            system_prompt_leak_detection: false,
        }
    }

    /// Creates a minimal feature set with only basic detection.
    pub fn minimal() -> Self {
        Self {
            pattern_matching: true,
            heuristic_analysis: false,
            semantic_detection: false,
            encoding_detection: false,
            social_engineering_detection: false,
            context_hijacking_detection: false,
            role_play_detection: false,
            data_extraction_detection: false,
            multi_modal_detection: false,
            custom_patterns: false,
            jailbreak_detection: true,
            instruction_override_detection: true,
            code_injection_detection: false,
            system_prompt_leak_detection: false,
        }
    }

    /// Creates a balanced feature set suitable for most applications.
    pub fn balanced() -> Self {
        Self {
            pattern_matching: true,
            heuristic_analysis: true,
            semantic_detection: false, // Disabled by default to avoid model dependencies
            encoding_detection: true,
            social_engineering_detection: true,
            context_hijacking_detection: true,
            role_play_detection: true,
            data_extraction_detection: true,
            multi_modal_detection: false,
            custom_patterns: true,
            jailbreak_detection: true,
            instruction_override_detection: true,
            code_injection_detection: true,
            system_prompt_leak_detection: true,
        }
    }

    /// Creates a performance-optimized feature set with faster detection.
    pub fn performance_optimized() -> Self {
        Self {
            pattern_matching: true,
            heuristic_analysis: false, // Disable computationally expensive features
            semantic_detection: false,
            encoding_detection: true,
            social_engineering_detection: false,
            context_hijacking_detection: true,
            role_play_detection: true,
            data_extraction_detection: false,
            multi_modal_detection: false,
            custom_patterns: true,
            jailbreak_detection: true,
            instruction_override_detection: true,
            code_injection_detection: true,
            system_prompt_leak_detection: false,
        }
    }

    /// Creates a comprehensive feature set with maximum security.
    pub fn comprehensive() -> Self {
        Self::all_enabled()
    }

    /// Enables a specific feature by name.
    pub fn enable_feature(&mut self, feature_name: &str) -> Result<(), String> {
        match feature_name {
            "pattern_matching" => self.pattern_matching = true,
            "heuristic_analysis" => self.heuristic_analysis = true,
            "semantic_detection" => self.semantic_detection = true,
            "encoding_detection" => self.encoding_detection = true,
            "social_engineering_detection" => self.social_engineering_detection = true,
            "context_hijacking_detection" => self.context_hijacking_detection = true,
            "role_play_detection" => self.role_play_detection = true,
            "data_extraction_detection" => self.data_extraction_detection = true,
            "multi_modal_detection" => self.multi_modal_detection = true,
            "custom_patterns" => self.custom_patterns = true,
            "jailbreak_detection" => self.jailbreak_detection = true,
            "instruction_override_detection" => self.instruction_override_detection = true,
            "code_injection_detection" => self.code_injection_detection = true,
            "system_prompt_leak_detection" => self.system_prompt_leak_detection = true,
            _ => return Err(format!("Unknown feature: {}", feature_name)),
        }
        Ok(())
    }

    /// Disables a specific feature by name.
    pub fn disable_feature(&mut self, feature_name: &str) -> Result<(), String> {
        match feature_name {
            "pattern_matching" => self.pattern_matching = false,
            "heuristic_analysis" => self.heuristic_analysis = false,
            "semantic_detection" => self.semantic_detection = false,
            "encoding_detection" => self.encoding_detection = false,
            "social_engineering_detection" => self.social_engineering_detection = false,
            "context_hijacking_detection" => self.context_hijacking_detection = false,
            "role_play_detection" => self.role_play_detection = false,
            "data_extraction_detection" => self.data_extraction_detection = false,
            "multi_modal_detection" => self.multi_modal_detection = false,
            "custom_patterns" => self.custom_patterns = false,
            "jailbreak_detection" => self.jailbreak_detection = false,
            "instruction_override_detection" => self.instruction_override_detection = false,
            "code_injection_detection" => self.code_injection_detection = false,
            "system_prompt_leak_detection" => self.system_prompt_leak_detection = false,
            _ => return Err(format!("Unknown feature: {}", feature_name)),
        }
        Ok(())
    }

    /// Returns true if a specific feature is enabled.
    pub fn is_feature_enabled(&self, feature_name: &str) -> bool {
        match feature_name {
            "pattern_matching" => self.pattern_matching,
            "heuristic_analysis" => self.heuristic_analysis,
            "semantic_detection" => self.semantic_detection,
            "encoding_detection" => self.encoding_detection,
            "social_engineering_detection" => self.social_engineering_detection,
            "context_hijacking_detection" => self.context_hijacking_detection,
            "role_play_detection" => self.role_play_detection,
            "data_extraction_detection" => self.data_extraction_detection,
            "multi_modal_detection" => self.multi_modal_detection,
            "custom_patterns" => self.custom_patterns,
            "jailbreak_detection" => self.jailbreak_detection,
            "instruction_override_detection" => self.instruction_override_detection,
            "code_injection_detection" => self.code_injection_detection,
            "system_prompt_leak_detection" => self.system_prompt_leak_detection,
            _ => false,
        }
    }

    /// Returns a list of all enabled feature names.
    pub fn enabled_features(&self) -> Vec<String> {
        let mut enabled = Vec::new();

        if self.pattern_matching {
            enabled.push("pattern_matching".to_string());
        }
        if self.heuristic_analysis {
            enabled.push("heuristic_analysis".to_string());
        }
        if self.semantic_detection {
            enabled.push("semantic_detection".to_string());
        }
        if self.encoding_detection {
            enabled.push("encoding_detection".to_string());
        }
        if self.social_engineering_detection {
            enabled.push("social_engineering_detection".to_string());
        }
        if self.context_hijacking_detection {
            enabled.push("context_hijacking_detection".to_string());
        }
        if self.role_play_detection {
            enabled.push("role_play_detection".to_string());
        }
        if self.data_extraction_detection {
            enabled.push("data_extraction_detection".to_string());
        }
        if self.multi_modal_detection {
            enabled.push("multi_modal_detection".to_string());
        }
        if self.custom_patterns {
            enabled.push("custom_patterns".to_string());
        }
        if self.jailbreak_detection {
            enabled.push("jailbreak_detection".to_string());
        }
        if self.instruction_override_detection {
            enabled.push("instruction_override_detection".to_string());
        }
        if self.code_injection_detection {
            enabled.push("code_injection_detection".to_string());
        }
        if self.system_prompt_leak_detection {
            enabled.push("system_prompt_leak_detection".to_string());
        }

        enabled
    }

    /// Returns a list of all disabled feature names.
    pub fn disabled_features(&self) -> Vec<String> {
        let mut disabled = Vec::new();

        if !self.pattern_matching {
            disabled.push("pattern_matching".to_string());
        }
        if !self.heuristic_analysis {
            disabled.push("heuristic_analysis".to_string());
        }
        if !self.semantic_detection {
            disabled.push("semantic_detection".to_string());
        }
        if !self.encoding_detection {
            disabled.push("encoding_detection".to_string());
        }
        if !self.social_engineering_detection {
            disabled.push("social_engineering_detection".to_string());
        }
        if !self.context_hijacking_detection {
            disabled.push("context_hijacking_detection".to_string());
        }
        if !self.role_play_detection {
            disabled.push("role_play_detection".to_string());
        }
        if !self.data_extraction_detection {
            disabled.push("data_extraction_detection".to_string());
        }
        if !self.multi_modal_detection {
            disabled.push("multi_modal_detection".to_string());
        }
        if !self.custom_patterns {
            disabled.push("custom_patterns".to_string());
        }
        if !self.jailbreak_detection {
            disabled.push("jailbreak_detection".to_string());
        }
        if !self.instruction_override_detection {
            disabled.push("instruction_override_detection".to_string());
        }
        if !self.code_injection_detection {
            disabled.push("code_injection_detection".to_string());
        }
        if !self.system_prompt_leak_detection {
            disabled.push("system_prompt_leak_detection".to_string());
        }

        disabled
    }

    /// Returns the total number of enabled features.
    pub fn enabled_count(&self) -> usize {
        self.enabled_features().len()
    }

    /// Returns the total number of features available.
    pub fn total_count(&self) -> usize {
        14 // Total number of features
    }

    /// Converts the features to a HashMap for easy serialization/configuration.
    pub fn to_map(&self) -> HashMap<String, bool> {
        let mut map = HashMap::new();

        map.insert("pattern_matching".to_string(), self.pattern_matching);
        map.insert("heuristic_analysis".to_string(), self.heuristic_analysis);
        map.insert("semantic_detection".to_string(), self.semantic_detection);
        map.insert("encoding_detection".to_string(), self.encoding_detection);
        map.insert(
            "social_engineering_detection".to_string(),
            self.social_engineering_detection,
        );
        map.insert(
            "context_hijacking_detection".to_string(),
            self.context_hijacking_detection,
        );
        map.insert("role_play_detection".to_string(), self.role_play_detection);
        map.insert(
            "data_extraction_detection".to_string(),
            self.data_extraction_detection,
        );
        map.insert(
            "multi_modal_detection".to_string(),
            self.multi_modal_detection,
        );
        map.insert("custom_patterns".to_string(), self.custom_patterns);
        map.insert("jailbreak_detection".to_string(), self.jailbreak_detection);
        map.insert(
            "instruction_override_detection".to_string(),
            self.instruction_override_detection,
        );
        map.insert(
            "code_injection_detection".to_string(),
            self.code_injection_detection,
        );
        map.insert(
            "system_prompt_leak_detection".to_string(),
            self.system_prompt_leak_detection,
        );

        map
    }

    /// Creates Features from a HashMap.
    pub fn from_map(map: &HashMap<String, bool>) -> Self {
        Self {
            pattern_matching: map.get("pattern_matching").copied().unwrap_or(true),
            heuristic_analysis: map.get("heuristic_analysis").copied().unwrap_or(true),
            semantic_detection: map.get("semantic_detection").copied().unwrap_or(false),
            encoding_detection: map.get("encoding_detection").copied().unwrap_or(true),
            social_engineering_detection: map
                .get("social_engineering_detection")
                .copied()
                .unwrap_or(true),
            context_hijacking_detection: map
                .get("context_hijacking_detection")
                .copied()
                .unwrap_or(true),
            role_play_detection: map.get("role_play_detection").copied().unwrap_or(true),
            data_extraction_detection: map
                .get("data_extraction_detection")
                .copied()
                .unwrap_or(true),
            multi_modal_detection: map.get("multi_modal_detection").copied().unwrap_or(false),
            custom_patterns: map.get("custom_patterns").copied().unwrap_or(true),
            jailbreak_detection: map.get("jailbreak_detection").copied().unwrap_or(true),
            instruction_override_detection: map
                .get("instruction_override_detection")
                .copied()
                .unwrap_or(true),
            code_injection_detection: map.get("code_injection_detection").copied().unwrap_or(true),
            system_prompt_leak_detection: map
                .get("system_prompt_leak_detection")
                .copied()
                .unwrap_or(true),
        }
    }

    /// Returns a description of the features configuration.
    pub fn description(&self) -> String {
        let enabled_count = self.enabled_count();
        let total_count = self.total_count();

        if enabled_count == 0 {
            "All detection features disabled".to_string()
        } else if enabled_count == total_count {
            "All detection features enabled".to_string()
        } else {
            format!(
                "{}/{} detection features enabled",
                enabled_count, total_count
            )
        }
    }
}

impl Default for Features {
    fn default() -> Self {
        Self::balanced()
    }
}

impl std::fmt::Display for Features {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// Builder for creating Features configurations.
#[derive(Debug, Default)]
pub struct FeaturesBuilder {
    features: Features,
}

impl FeaturesBuilder {
    /// Creates a new FeaturesBuilder starting from all disabled.
    pub fn new() -> Self {
        Self {
            features: Features::all_disabled(),
        }
    }

    /// Creates a new FeaturesBuilder starting from a base configuration.
    pub fn from_base(base: Features) -> Self {
        Self { features: base }
    }

    /// Enables a specific feature.
    pub fn enable(mut self, feature_name: &str) -> Result<Self, String> {
        self.features.enable_feature(feature_name)?;
        Ok(self)
    }

    /// Disables a specific feature.
    pub fn disable(mut self, feature_name: &str) -> Result<Self, String> {
        self.features.disable_feature(feature_name)?;
        Ok(self)
    }

    /// Enables pattern matching.
    pub fn with_pattern_matching(mut self, enabled: bool) -> Self {
        self.features.pattern_matching = enabled;
        self
    }

    /// Enables heuristic analysis.
    pub fn with_heuristic_analysis(mut self, enabled: bool) -> Self {
        self.features.heuristic_analysis = enabled;
        self
    }

    /// Enables semantic detection.
    pub fn with_semantic_detection(mut self, enabled: bool) -> Self {
        self.features.semantic_detection = enabled;
        self
    }

    /// Enables encoding detection.
    pub fn with_encoding_detection(mut self, enabled: bool) -> Self {
        self.features.encoding_detection = enabled;
        self
    }

    /// Enables social engineering detection.
    pub fn with_social_engineering_detection(mut self, enabled: bool) -> Self {
        self.features.social_engineering_detection = enabled;
        self
    }

    /// Enables context hijacking detection.
    pub fn with_context_hijacking_detection(mut self, enabled: bool) -> Self {
        self.features.context_hijacking_detection = enabled;
        self
    }

    /// Enables role play detection.
    pub fn with_role_play_detection(mut self, enabled: bool) -> Self {
        self.features.role_play_detection = enabled;
        self
    }

    /// Enables data extraction detection.
    pub fn with_data_extraction_detection(mut self, enabled: bool) -> Self {
        self.features.data_extraction_detection = enabled;
        self
    }

    /// Enables multi-modal detection.
    pub fn with_multi_modal_detection(mut self, enabled: bool) -> Self {
        self.features.multi_modal_detection = enabled;
        self
    }

    /// Enables custom patterns.
    pub fn with_custom_patterns(mut self, enabled: bool) -> Self {
        self.features.custom_patterns = enabled;
        self
    }

    /// Enables jailbreak detection.
    pub fn with_jailbreak_detection(mut self, enabled: bool) -> Self {
        self.features.jailbreak_detection = enabled;
        self
    }

    /// Enables instruction override detection.
    pub fn with_instruction_override_detection(mut self, enabled: bool) -> Self {
        self.features.instruction_override_detection = enabled;
        self
    }

    /// Enables code injection detection.
    pub fn with_code_injection_detection(mut self, enabled: bool) -> Self {
        self.features.code_injection_detection = enabled;
        self
    }

    /// Enables system prompt leak detection.
    pub fn with_system_prompt_leak_detection(mut self, enabled: bool) -> Self {
        self.features.system_prompt_leak_detection = enabled;
        self
    }

    /// Builds the Features configuration.
    pub fn build(self) -> Features {
        self.features
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_features_presets() {
        let all_enabled = Features::all_enabled();
        assert_eq!(all_enabled.enabled_count(), all_enabled.total_count());

        let all_disabled = Features::all_disabled();
        assert_eq!(all_disabled.enabled_count(), 0);

        let minimal = Features::minimal();
        assert!(minimal.pattern_matching);
        assert!(minimal.jailbreak_detection);
        assert!(minimal.instruction_override_detection);
        assert!(!minimal.semantic_detection);

        let balanced = Features::balanced();
        assert!(balanced.pattern_matching);
        assert!(balanced.heuristic_analysis);
        assert!(!balanced.semantic_detection); // Disabled by default
        assert!(!balanced.multi_modal_detection);

        let performance = Features::performance_optimized();
        assert!(performance.pattern_matching);
        assert!(!performance.heuristic_analysis); // Disabled for performance
        assert!(!performance.semantic_detection);
    }

    #[test]
    fn test_feature_enable_disable() {
        let mut features = Features::all_disabled();

        assert!(!features.pattern_matching);
        features.enable_feature("pattern_matching").unwrap();
        assert!(features.pattern_matching);

        features.disable_feature("pattern_matching").unwrap();
        assert!(!features.pattern_matching);

        // Test invalid feature name
        assert!(features.enable_feature("invalid_feature").is_err());
        assert!(features.disable_feature("invalid_feature").is_err());
    }

    #[test]
    fn test_feature_queries() {
        let features = Features::balanced();

        assert!(features.is_feature_enabled("pattern_matching"));
        assert!(!features.is_feature_enabled("semantic_detection"));
        assert!(!features.is_feature_enabled("invalid_feature"));

        let enabled = features.enabled_features();
        assert!(enabled.contains(&"pattern_matching".to_string()));
        assert!(!enabled.contains(&"semantic_detection".to_string()));

        let disabled = features.disabled_features();
        assert!(disabled.contains(&"semantic_detection".to_string()));
        assert!(!disabled.contains(&"pattern_matching".to_string()));
    }

    #[test]
    fn test_features_map_conversion() {
        let features = Features::balanced();
        let map = features.to_map();

        assert_eq!(map.get("pattern_matching"), Some(&true));
        assert_eq!(map.get("semantic_detection"), Some(&false));

        let reconstructed = Features::from_map(&map);
        assert_eq!(features, reconstructed);
    }

    #[test]
    fn test_features_builder() {
        let features = FeaturesBuilder::new()
            .with_pattern_matching(true)
            .with_semantic_detection(true)
            .with_heuristic_analysis(false)
            .build();

        assert!(features.pattern_matching);
        assert!(features.semantic_detection);
        assert!(!features.heuristic_analysis);
    }

    #[test]
    fn test_features_builder_with_enable_disable() {
        let features = FeaturesBuilder::new()
            .enable("pattern_matching")
            .unwrap()
            .enable("semantic_detection")
            .unwrap()
            .disable("heuristic_analysis")
            .unwrap()
            .build();

        assert!(features.pattern_matching);
        assert!(features.semantic_detection);
        assert!(!features.heuristic_analysis);

        // Test invalid feature name
        let result = FeaturesBuilder::new().enable("invalid_feature");
        assert!(result.is_err());
    }

    #[test]
    fn test_features_builder_from_base() {
        let base = Features::minimal();
        let features = FeaturesBuilder::from_base(base.clone())
            .with_semantic_detection(true)
            .build();

        assert!(features.pattern_matching); // From base
        assert!(features.semantic_detection); // Added
        assert!(!features.heuristic_analysis); // From base
    }

    #[test]
    fn test_features_description() {
        let all_enabled = Features::all_enabled();
        assert!(all_enabled
            .description()
            .contains("All detection features enabled"));

        let all_disabled = Features::all_disabled();
        assert!(all_disabled
            .description()
            .contains("All detection features disabled"));

        let balanced = Features::balanced();
        let desc = balanced.description();
        assert!(desc.contains("/"));
        assert!(desc.contains("detection features enabled"));
    }

    #[test]
    fn test_features_serialization() {
        let features = Features::balanced();

        // Test JSON serialization
        let json = serde_json::to_string(&features).unwrap();
        let deserialized: Features = serde_json::from_str(&json).unwrap();

        assert_eq!(features, deserialized);
    }

    #[test]
    fn test_all_feature_names() {
        let features = Features::all_enabled();
        let enabled = features.enabled_features();

        // Verify all expected features are present
        assert!(enabled.contains(&"pattern_matching".to_string()));
        assert!(enabled.contains(&"heuristic_analysis".to_string()));
        assert!(enabled.contains(&"semantic_detection".to_string()));
        assert!(enabled.contains(&"encoding_detection".to_string()));
        assert!(enabled.contains(&"social_engineering_detection".to_string()));
        assert!(enabled.contains(&"context_hijacking_detection".to_string()));
        assert!(enabled.contains(&"role_play_detection".to_string()));
        assert!(enabled.contains(&"data_extraction_detection".to_string()));
        assert!(enabled.contains(&"multi_modal_detection".to_string()));
        assert!(enabled.contains(&"custom_patterns".to_string()));
        assert!(enabled.contains(&"jailbreak_detection".to_string()));
        assert!(enabled.contains(&"instruction_override_detection".to_string()));
        assert!(enabled.contains(&"code_injection_detection".to_string()));
        assert!(enabled.contains(&"system_prompt_leak_detection".to_string()));

        assert_eq!(enabled.len(), features.total_count());
    }
}
