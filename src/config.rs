//! Configuration types and builders for FluxPrompt.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

use crate::types::{PreprocessingConfig, RiskLevel};

/// Granular security levels for detection thresholds (0-10 scale).
/// Level 0: Minimal filtering, Level 5: Balanced, Level 10: Maximum paranoia
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityLevel(u8);

impl SecurityLevel {
    /// Creates a new security level (0-10).
    pub fn new(level: u8) -> Result<Self, String> {
        if level <= 10 {
            Ok(SecurityLevel(level))
        } else {
            Err("Security level must be between 0 and 10".to_string())
        }
    }

    /// Returns the raw level value (0-10).
    pub fn level(&self) -> u8 {
        self.0
    }

    /// Returns the base threshold using smooth scaling: 0.95 - (level * 0.08)
    pub fn base_threshold(&self) -> f32 {
        (0.95 - (self.0 as f32 * 0.08)).clamp(0.15, 0.95)
    }

    /// Returns the pattern weight using scaling: 1.0 + (level * 0.15)
    pub fn pattern_weight(&self) -> f32 {
        1.0 + (self.0 as f32 * 0.15)
    }

    /// Returns the heuristic sensitivity: 0.1 + (level * 0.09)
    pub fn heuristic_sensitivity(&self) -> f32 {
        0.1 + (self.0 as f32 * 0.09)
    }

    /// Returns the combination multiplier: 1.0 + (level * 0.2)
    pub fn combination_multiplier(&self) -> f32 {
        1.0 + (self.0 as f32 * 0.2)
    }

    /// Returns the confidence threshold for this security level.
    pub fn confidence_threshold(&self) -> f32 {
        self.base_threshold()
    }

    /// Returns the risk threshold for this security level.
    pub fn risk_threshold(&self) -> RiskLevel {
        match self.0 {
            0..=2 => RiskLevel::High,   // Only flag high-risk content
            3..=4 => RiskLevel::Medium, // Flag medium and above
            5 => RiskLevel::Medium,     // Medium severity level (backward compat)
            6 => RiskLevel::Low,        // Flag low and above
            7..=8 => RiskLevel::Low,    // High severity level
            9..=10 => RiskLevel::None,  // Paranoid - flag everything
            _ => RiskLevel::Medium,     // Fallback
        }
    }

    /// Returns a description of the security level's behavior.
    pub fn description(&self) -> &str {
        match self.0 {
            0 => "Minimal filtering - allows almost everything",
            1 => "Very permissive - only obvious attacks blocked",
            2 => "Permissive - basic attack patterns only",
            3 => "Light filtering - adds social engineering detection",
            4 => "Moderate filtering - balanced security and usability",
            5 => "Balanced - good security with reasonable false positives",
            6 => "Enhanced filtering - includes encoding/obfuscation checks",
            7 => "Strict filtering - aggressive pattern matching",
            8 => "Very strict - low tolerance for suspicious content",
            9 => "Near-paranoid - blocks most suspicious patterns",
            10 => "Zero-tolerance - blocks almost everything suspicious",
            _ => "Unknown level",
        }
    }

    /// Returns which threat categories are enabled at this level.
    pub fn enabled_threat_categories(&self) -> Vec<&str> {
        let mut categories = Vec::new();

        // Level 0-2: Basic threats only
        if self.0 >= 1 {
            categories.extend_from_slice(&["instruction_override", "jailbreak"]);
        }

        // Level 3-4: Add social engineering
        if self.0 >= 3 {
            categories.extend_from_slice(&[
                "social_engineering",
                "social_engineering_comprehensive",
                "authority_manipulation_advanced",
            ]);
        }

        // Level 5-6: Add encoding and context confusion
        if self.0 >= 5 {
            categories.extend_from_slice(&[
                "encoding_bypass",
                "encoding_bypass_comprehensive",
                "context_confusion",
                "context_hijacking_advanced",
                "role_playing",
                "role_playing_comprehensive",
            ]);
        }

        // Level 7-8: Add all advanced patterns
        if self.0 >= 7 {
            categories.extend_from_slice(&[
                "advanced_instruction_override",
                "urgency_manipulation_advanced",
                "trust_manipulation_advanced",
                "fake_system_messages_advanced",
                "dan_variations_comprehensive",
                "gradual_escalation_patterns",
                "hypothetical_scenarios_advanced",
            ]);
        }

        // Level 9-10: Add all comprehensive patterns
        if self.0 >= 9 {
            categories.extend_from_slice(&[
                "data_extraction",
                "memory_data_extraction_advanced",
                "evasion_techniques_advanced",
                "context_breaking_advanced",
                "compliance_testing_disguised",
            ]);
        }

        categories
    }
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel(5) // Balanced level
    }
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Level {} - {}", self.0, self.description())
    }
}

/// Legacy severity levels for backward compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeverityLevel {
    /// Very permissive - only catch obvious attacks
    Low,
    /// Balanced approach - catch most attacks with few false positives
    Medium,
    /// Strict - catch all potential attacks, may have false positives
    High,
    /// Very strict - maximum security, high false positive rate
    Paranoid,
}

impl SeverityLevel {
    /// Converts legacy severity level to new security level.
    pub fn to_security_level(&self) -> SecurityLevel {
        match self {
            SeverityLevel::Low => SecurityLevel(2),
            SeverityLevel::Medium => SecurityLevel(5),
            SeverityLevel::High => SecurityLevel(7),
            SeverityLevel::Paranoid => SecurityLevel(10),
        }
    }

    /// Returns the risk threshold for this severity level.
    pub fn risk_threshold(&self) -> RiskLevel {
        self.to_security_level().risk_threshold()
    }

    /// Returns the confidence threshold for this severity level.
    pub fn confidence_threshold(&self) -> f32 {
        self.to_security_level().confidence_threshold()
    }
}

/// Response strategies when injection is detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ResponseStrategy {
    /// Allow the prompt but mark it as suspicious
    Allow,
    /// Block the prompt entirely
    #[default]
    Block,
    /// Sanitize the prompt and continue
    Sanitize,
    /// Return a warning message
    Warn,
    /// Custom response with specified message
    Custom(String),
}

/// Configuration for pattern-based detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternConfig {
    /// Built-in pattern categories to enable (auto-populated based on security level if None)
    pub enabled_categories: Option<Vec<String>>,
    /// Custom regex patterns to include
    pub custom_patterns: Vec<String>,
    /// Whether to use case-sensitive matching
    pub case_sensitive: bool,
    /// Maximum number of patterns to compile
    pub max_patterns: usize,
}

impl PatternConfig {
    /// Gets the enabled categories for a given security level.
    pub fn get_enabled_categories(&self, security_level: &SecurityLevel) -> Vec<String> {
        if let Some(ref categories) = self.enabled_categories {
            categories.clone()
        } else {
            security_level
                .enabled_threat_categories()
                .into_iter()
                .map(|s| s.to_string())
                .collect()
        }
    }
}

impl Default for PatternConfig {
    fn default() -> Self {
        Self {
            enabled_categories: None, // Will be auto-populated based on security level
            custom_patterns: Vec::new(),
            case_sensitive: false,
            max_patterns: 3000, // Increased for Phase 1 new patterns (200+ additional patterns)
        }
    }
}

/// Configuration for semantic analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticConfig {
    /// Whether to enable semantic analysis
    pub enabled: bool,
    /// Embedding model to use (if any)
    pub model_name: Option<String>,
    /// Similarity threshold for semantic matching
    pub similarity_threshold: f32,
    /// Maximum context length for analysis
    pub max_context_length: usize,
}

impl Default for SemanticConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default to avoid model dependencies
            model_name: None,
            similarity_threshold: 0.8,
            max_context_length: 512,
        }
    }
}

/// Configuration for rate limiting and resource management.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceConfig {
    /// Maximum number of concurrent analyses
    pub max_concurrent_analyses: usize,
    /// Analysis timeout duration
    pub analysis_timeout: Duration,
    /// Maximum memory usage in MB
    pub max_memory_mb: usize,
    /// Cache size for compiled patterns
    pub pattern_cache_size: usize,
}

impl Default for ResourceConfig {
    fn default() -> Self {
        Self {
            max_concurrent_analyses: 100,
            analysis_timeout: Duration::from_secs(10),
            max_memory_mb: 512,
            pattern_cache_size: 1000,
        }
    }
}

/// Main configuration for FluxPrompt detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Granular security level (0-10 scale)
    pub security_level: SecurityLevel,
    /// Legacy severity level (for backward compatibility)
    pub severity_level: Option<SeverityLevel>,
    /// Response strategy for detected injections
    pub response_strategy: ResponseStrategy,
    /// Pattern-based detection configuration
    pub pattern_config: PatternConfig,
    /// Semantic analysis configuration
    pub semantic_config: SemanticConfig,
    /// Text preprocessing configuration
    pub preprocessing_config: PreprocessingConfig,
    /// Resource management configuration
    pub resource_config: ResourceConfig,
    /// Whether to enable metrics collection
    pub enable_metrics: bool,
    /// Custom configuration values
    pub custom_config: HashMap<String, String>,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            security_level: SecurityLevel::default(),
            severity_level: None,
            response_strategy: ResponseStrategy::default(),
            pattern_config: PatternConfig::default(),
            semantic_config: SemanticConfig::default(),
            preprocessing_config: PreprocessingConfig::default(),
            resource_config: ResourceConfig::default(),
            enable_metrics: true,
            custom_config: HashMap::new(),
        }
    }
}

impl DetectionConfig {
    /// Creates a new configuration builder.
    pub fn builder() -> DetectionConfigBuilder {
        DetectionConfigBuilder::default()
    }

    /// Returns the effective security level (preferring new over legacy).
    pub fn effective_security_level(&self) -> SecurityLevel {
        self.severity_level
            .map_or(self.security_level, |legacy| legacy.to_security_level())
    }

    /// Validates the configuration and returns any errors.
    pub fn validate(&self) -> crate::Result<()> {
        // Validate pattern config
        if self.pattern_config.max_patterns == 0 {
            return Err(crate::error::FluxPromptError::config(
                "max_patterns must be greater than 0",
            ));
        }

        // Validate resource config
        if self.resource_config.max_concurrent_analyses == 0 {
            return Err(crate::error::FluxPromptError::config(
                "max_concurrent_analyses must be greater than 0",
            ));
        }

        if self.resource_config.analysis_timeout.is_zero() {
            return Err(crate::error::FluxPromptError::config(
                "analysis_timeout must be greater than 0",
            ));
        }

        // Validate semantic config
        if self.semantic_config.enabled && self.semantic_config.similarity_threshold <= 0.0 {
            return Err(crate::error::FluxPromptError::config(
                "similarity_threshold must be greater than 0",
            ));
        }

        Ok(())
    }
}

/// Builder for DetectionConfig.
#[derive(Debug, Default)]
pub struct DetectionConfigBuilder {
    security_level: Option<SecurityLevel>,
    severity_level: Option<SeverityLevel>,
    response_strategy: Option<ResponseStrategy>,
    pattern_config: Option<PatternConfig>,
    semantic_config: Option<SemanticConfig>,
    preprocessing_config: Option<PreprocessingConfig>,
    resource_config: Option<ResourceConfig>,
    enable_metrics: Option<bool>,
    custom_config: HashMap<String, String>,
}

impl DetectionConfigBuilder {
    /// Sets the granular security level (0-10).
    pub fn with_security_level(mut self, level: u8) -> Result<Self, String> {
        self.security_level = Some(SecurityLevel::new(level)?);
        Ok(self)
    }

    /// Sets the security level using SecurityLevel struct.
    pub fn with_security_level_struct(mut self, level: SecurityLevel) -> Self {
        self.security_level = Some(level);
        self
    }

    /// Sets the legacy severity level (for backward compatibility).
    pub fn with_severity_level(mut self, level: SeverityLevel) -> Self {
        self.severity_level = Some(level);
        self
    }

    /// Sets the response strategy.
    pub fn with_response_strategy(mut self, strategy: ResponseStrategy) -> Self {
        self.response_strategy = Some(strategy);
        self
    }

    /// Sets custom patterns to include.
    pub fn with_custom_patterns(mut self, patterns: Vec<String>) -> Self {
        let mut config = self.pattern_config.unwrap_or_default();
        config.custom_patterns = patterns;
        self.pattern_config = Some(config);
        self
    }

    /// Enables or disables semantic analysis.
    pub fn enable_semantic_analysis(mut self, enabled: bool) -> Self {
        let mut config = self.semantic_config.unwrap_or_default();
        config.enabled = enabled;
        self.semantic_config = Some(config);
        self
    }

    /// Sets the analysis timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        let mut config = self.resource_config.unwrap_or_default();
        config.analysis_timeout = timeout;
        self.resource_config = Some(config);
        self
    }

    /// Enables or disables metrics collection.
    pub fn enable_metrics(mut self, enabled: bool) -> Self {
        self.enable_metrics = Some(enabled);
        self
    }

    /// Adds a custom configuration value.
    pub fn with_custom_config<K: Into<String>, V: Into<String>>(
        mut self,
        key: K,
        value: V,
    ) -> Self {
        self.custom_config.insert(key.into(), value.into());
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> DetectionConfig {
        // If severity_level is set but security_level is not, convert it
        let security_level = if let Some(severity) = self.severity_level {
            if self.security_level.is_none() {
                severity.to_security_level()
            } else {
                self.security_level.unwrap_or_default()
            }
        } else {
            self.security_level.unwrap_or_default()
        };

        DetectionConfig {
            security_level,
            severity_level: self.severity_level,
            response_strategy: self.response_strategy.unwrap_or_default(),
            pattern_config: self.pattern_config.unwrap_or_default(),
            semantic_config: self.semantic_config.unwrap_or_default(),
            preprocessing_config: self.preprocessing_config.unwrap_or_default(),
            resource_config: self.resource_config.unwrap_or_default(),
            enable_metrics: self.enable_metrics.unwrap_or(true),
            custom_config: self.custom_config,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_security_level_creation() {
        for level in 0..=10 {
            let security_level = SecurityLevel::new(level);
            assert!(security_level.is_ok());
            assert_eq!(security_level.unwrap().level(), level);
        }

        // Test invalid level
        assert!(SecurityLevel::new(11).is_err());
    }

    #[test]
    fn test_security_level_thresholds() {
        let level_0 = SecurityLevel::new(0).unwrap();
        let level_5 = SecurityLevel::new(5).unwrap();
        let level_10 = SecurityLevel::new(10).unwrap();

        // Base thresholds should decrease with higher security levels
        assert!(level_0.base_threshold() > level_5.base_threshold());
        assert!(level_5.base_threshold() > level_10.base_threshold());

        // Pattern weights should increase with higher security levels
        assert!(level_10.pattern_weight() > level_5.pattern_weight());
        assert!(level_5.pattern_weight() > level_0.pattern_weight());
    }

    #[test]
    fn test_severity_level_thresholds() {
        assert_eq!(SeverityLevel::Low.risk_threshold(), RiskLevel::High);
        assert_eq!(SeverityLevel::Medium.risk_threshold(), RiskLevel::Low);
        assert_eq!(SeverityLevel::High.risk_threshold(), RiskLevel::Low);
    }

    #[test]
    fn test_config_builder() {
        let config = DetectionConfig::builder()
            .with_security_level(7)
            .unwrap()
            .with_response_strategy(ResponseStrategy::Block)
            .enable_metrics(false)
            .build();

        assert_eq!(config.security_level.level(), 7);
        assert_eq!(config.response_strategy, ResponseStrategy::Block);
        assert!(!config.enable_metrics);
    }

    #[test]
    fn test_config_builder_legacy() {
        let config = DetectionConfig::builder()
            .with_severity_level(SeverityLevel::High)
            .with_response_strategy(ResponseStrategy::Block)
            .enable_metrics(false)
            .build();

        assert_eq!(config.severity_level, Some(SeverityLevel::High));
        assert_eq!(config.response_strategy, ResponseStrategy::Block);
        assert!(!config.enable_metrics);
    }

    #[test]
    fn test_config_validation() {
        let mut config = DetectionConfig::default();
        assert!(config.validate().is_ok());

        config.pattern_config.max_patterns = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_custom_response_strategy() {
        let strategy = ResponseStrategy::Custom("Custom warning message".to_string());
        match strategy {
            ResponseStrategy::Custom(msg) => assert_eq!(msg, "Custom warning message"),
            _ => panic!("Expected custom response strategy"),
        }
    }

    // COMPREHENSIVE CONFIGURATION TESTS

    #[test]
    fn test_security_level_enabled_categories() {
        let level_0 = SecurityLevel::new(0).unwrap();
        let level_5 = SecurityLevel::new(5).unwrap();
        let level_10 = SecurityLevel::new(10).unwrap();

        // Higher levels should have more categories enabled
        assert!(
            level_10.enabled_threat_categories().len() > level_5.enabled_threat_categories().len()
        );
        assert!(
            level_5.enabled_threat_categories().len() >= level_0.enabled_threat_categories().len()
        );
    }

    #[test]
    fn test_severity_level_confidence_thresholds() {
        // Test the legacy system still works through conversion
        let low_sec = SeverityLevel::Low.to_security_level();
        let med_sec = SeverityLevel::Medium.to_security_level();
        let high_sec = SeverityLevel::High.to_security_level();
        let paranoid_sec = SeverityLevel::Paranoid.to_security_level();

        // Test ordering - higher severity should have lower confidence threshold
        assert!(paranoid_sec.confidence_threshold() < high_sec.confidence_threshold());
        assert!(high_sec.confidence_threshold() < med_sec.confidence_threshold());
        assert!(med_sec.confidence_threshold() < low_sec.confidence_threshold());
    }

    #[test]
    fn test_severity_level_risk_thresholds() {
        assert_eq!(SeverityLevel::Low.risk_threshold(), RiskLevel::High);
        assert_eq!(SeverityLevel::Medium.risk_threshold(), RiskLevel::Medium);
        assert_eq!(SeverityLevel::High.risk_threshold(), RiskLevel::Low);
        assert_eq!(SeverityLevel::Paranoid.risk_threshold(), RiskLevel::None);

        // Test ordering - higher severity should have lower risk threshold
        assert!(SeverityLevel::Paranoid.risk_threshold() < SeverityLevel::High.risk_threshold());
        assert!(SeverityLevel::High.risk_threshold() < SeverityLevel::Medium.risk_threshold());
        assert!(SeverityLevel::Medium.risk_threshold() < SeverityLevel::Low.risk_threshold());
    }

    #[test]
    fn test_response_strategy_variants() {
        // Test all response strategy variants
        let strategies = vec![
            ResponseStrategy::Allow,
            ResponseStrategy::Block,
            ResponseStrategy::Sanitize,
            ResponseStrategy::Warn,
            ResponseStrategy::Custom("Test message".to_string()),
        ];

        for strategy in strategies {
            // Should serialize/deserialize correctly
            let json = serde_json::to_string(&strategy).unwrap();
            let deserialized: ResponseStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(strategy, deserialized);
        }
    }

    #[test]
    fn test_pattern_config_defaults() {
        let config = PatternConfig::default();
        let security_level = SecurityLevel::default(); // Level 5

        // Should use auto-populated categories based on security level
        assert!(config.enabled_categories.is_none());

        // Test that get_enabled_categories works correctly
        let categories = config.get_enabled_categories(&security_level);
        assert!(!categories.is_empty());
        assert!(categories.contains(&"instruction_override".to_string()));
        assert!(categories.contains(&"jailbreak".to_string()));
        assert!(categories.contains(&"social_engineering".to_string()));

        assert!(config.custom_patterns.is_empty());
        assert!(!config.case_sensitive);
        assert_eq!(config.max_patterns, 3000);
    }

    #[test]
    fn test_pattern_config_custom() {
        let config = PatternConfig {
            custom_patterns: vec![
                "custom_pattern_1".to_string(),
                "custom_pattern_2".to_string(),
            ],
            case_sensitive: true,
            max_patterns: 500,
            ..Default::default()
        };

        assert_eq!(config.custom_patterns.len(), 2);
        assert!(config.case_sensitive);
        assert_eq!(config.max_patterns, 500);
    }

    #[test]
    fn test_semantic_config_defaults() {
        let config = SemanticConfig::default();

        assert!(!config.enabled); // Disabled by default
        assert!(config.model_name.is_none());
        assert_eq!(config.similarity_threshold, 0.8);
        assert_eq!(config.max_context_length, 512);
    }

    #[test]
    fn test_semantic_config_custom() {
        let config = SemanticConfig {
            enabled: true,
            model_name: Some("test-model".to_string()),
            similarity_threshold: 0.6,
            max_context_length: 1024,
        };

        assert!(config.enabled);
        assert_eq!(config.model_name.as_ref().unwrap(), "test-model");
        assert_eq!(config.similarity_threshold, 0.6);
        assert_eq!(config.max_context_length, 1024);
    }

    #[test]
    fn test_resource_config_defaults() {
        let config = ResourceConfig::default();

        assert_eq!(config.max_concurrent_analyses, 100);
        assert_eq!(config.analysis_timeout, Duration::from_secs(10));
        assert_eq!(config.max_memory_mb, 512);
        assert_eq!(config.pattern_cache_size, 1000);
    }

    #[test]
    fn test_resource_config_custom() {
        let config = ResourceConfig {
            max_concurrent_analyses: 50,
            analysis_timeout: Duration::from_secs(5),
            max_memory_mb: 256,
            pattern_cache_size: 500,
        };

        assert_eq!(config.max_concurrent_analyses, 50);
        assert_eq!(config.analysis_timeout, Duration::from_secs(5));
        assert_eq!(config.max_memory_mb, 256);
        assert_eq!(config.pattern_cache_size, 500);
    }

    #[test]
    fn test_detection_config_defaults() {
        let config = DetectionConfig::default();

        assert_eq!(config.security_level.level(), 5); // Default balanced level
        assert_eq!(config.severity_level, None);
        assert_eq!(config.response_strategy, ResponseStrategy::Block);
        assert!(config.enable_metrics);
        assert!(config.custom_config.is_empty());

        // Check nested configs have reasonable defaults
        // Pattern config default should have None for enabled_categories
        assert!(config.pattern_config.enabled_categories.is_none());
        assert!(!config.semantic_config.enabled);
        assert!(config.preprocessing_config.normalize_unicode);
        assert_eq!(config.resource_config.max_concurrent_analyses, 100);
    }

    #[test]
    fn test_detection_config_builder_comprehensive() {
        let config = DetectionConfig::builder()
            .with_security_level(9)
            .unwrap()
            .with_response_strategy(ResponseStrategy::Sanitize)
            .with_custom_patterns(vec!["pattern1".to_string(), "pattern2".to_string()])
            .enable_semantic_analysis(true)
            .with_timeout(Duration::from_secs(30))
            .enable_metrics(false)
            .with_custom_config("key1", "value1")
            .with_custom_config("key2", "value2")
            .build();

        assert_eq!(config.security_level.level(), 9);
        assert_eq!(config.response_strategy, ResponseStrategy::Sanitize);
        assert!(!config.enable_metrics);

        assert_eq!(config.pattern_config.custom_patterns.len(), 2);
        assert!(config.semantic_config.enabled);
        assert_eq!(
            config.resource_config.analysis_timeout,
            Duration::from_secs(30)
        );

        assert_eq!(config.custom_config.len(), 2);
        assert_eq!(config.custom_config.get("key1").unwrap(), "value1");
        assert_eq!(config.custom_config.get("key2").unwrap(), "value2");
    }

    #[test]
    fn test_detection_config_validation_comprehensive() {
        // Test valid config
        let valid_config = DetectionConfig::default();
        assert!(valid_config.validate().is_ok());

        // Test invalid pattern config
        let mut invalid_pattern_config = DetectionConfig::default();
        invalid_pattern_config.pattern_config.max_patterns = 0;
        let result = invalid_pattern_config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("max_patterns"));

        // Test invalid resource config - zero concurrent analyses
        let mut invalid_resource_config = DetectionConfig::default();
        invalid_resource_config
            .resource_config
            .max_concurrent_analyses = 0;
        let result = invalid_resource_config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("max_concurrent_analyses"));

        // Test invalid resource config - zero timeout
        let mut invalid_timeout_config = DetectionConfig::default();
        invalid_timeout_config.resource_config.analysis_timeout = Duration::from_secs(0);
        let result = invalid_timeout_config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("analysis_timeout"));

        // Test invalid semantic config - enabled with invalid threshold
        let mut invalid_semantic_config = DetectionConfig::default();
        invalid_semantic_config.semantic_config.enabled = true;
        invalid_semantic_config.semantic_config.similarity_threshold = 0.0;
        let result = invalid_semantic_config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("similarity_threshold"));

        // Test invalid semantic config - enabled with negative threshold
        invalid_semantic_config.semantic_config.similarity_threshold = -0.1;
        let result = invalid_semantic_config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_detection_config_builder_partial() {
        // Test builder with only some fields set
        let config1 = DetectionConfig::builder()
            .with_severity_level(SeverityLevel::High)
            .build();

        assert_eq!(config1.security_level.level(), 7); // High maps to level 7
        assert_eq!(config1.response_strategy, ResponseStrategy::Block); // Default
        assert!(config1.enable_metrics); // Default

        // Test builder with different subset
        let config2 = DetectionConfig::builder()
            .with_response_strategy(ResponseStrategy::Allow)
            .enable_metrics(false)
            .build();

        assert_eq!(config2.security_level.level(), 5); // Default balanced level
        assert_eq!(config2.response_strategy, ResponseStrategy::Allow);
        assert!(!config2.enable_metrics);
    }

    #[test]
    fn test_detection_config_builder_timeout_variations() {
        let timeouts = vec![
            Duration::from_millis(100),
            Duration::from_secs(1),
            Duration::from_secs(60),
            Duration::from_secs(300),
        ];

        for timeout in timeouts {
            let config = DetectionConfig::builder().with_timeout(timeout).build();

            assert_eq!(config.resource_config.analysis_timeout, timeout);
        }
    }

    #[test]
    fn test_detection_config_builder_semantic_variations() {
        // Test enabling semantic analysis
        let enabled_config = DetectionConfig::builder()
            .enable_semantic_analysis(true)
            .build();
        assert!(enabled_config.semantic_config.enabled);

        // Test disabling semantic analysis
        let disabled_config = DetectionConfig::builder()
            .enable_semantic_analysis(false)
            .build();
        assert!(!disabled_config.semantic_config.enabled);
    }

    #[test]
    fn test_detection_config_builder_custom_patterns() {
        let patterns = vec![
            "test_pattern_1".to_string(),
            "test_pattern_2".to_string(),
            "test_pattern_3".to_string(),
        ];

        let config = DetectionConfig::builder()
            .with_custom_patterns(patterns.clone())
            .build();

        assert_eq!(config.pattern_config.custom_patterns, patterns);
    }

    #[test]
    fn test_detection_config_builder_custom_config_multiple() {
        let config = DetectionConfig::builder()
            .with_custom_config("database_url", "postgresql://localhost")
            .with_custom_config("redis_url", "redis://localhost")
            .with_custom_config("log_level", "debug")
            .build();

        assert_eq!(config.custom_config.len(), 3);
        assert_eq!(
            config.custom_config.get("database_url").unwrap(),
            "postgresql://localhost"
        );
        assert_eq!(
            config.custom_config.get("redis_url").unwrap(),
            "redis://localhost"
        );
        assert_eq!(config.custom_config.get("log_level").unwrap(), "debug");
    }

    #[test]
    fn test_config_serialization() {
        let config = DetectionConfig::builder()
            .with_severity_level(SeverityLevel::High)
            .with_response_strategy(ResponseStrategy::Sanitize)
            .enable_semantic_analysis(true)
            .build();

        // Test JSON serialization
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: DetectionConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config.severity_level, deserialized.severity_level);
        assert_eq!(config.response_strategy, deserialized.response_strategy);
        assert_eq!(
            config.semantic_config.enabled,
            deserialized.semantic_config.enabled
        );
    }

    #[test]
    fn test_config_edge_cases() {
        // Test with extreme values
        let extreme_config = DetectionConfig::builder()
            .with_timeout(Duration::from_nanos(1)) // Very short timeout
            .build();

        // Should not panic, even with extreme values
        assert_eq!(
            extreme_config.resource_config.analysis_timeout,
            Duration::from_nanos(1)
        );

        // Test with very long timeout
        let long_timeout_config = DetectionConfig::builder()
            .with_timeout(Duration::from_secs(86400)) // 24 hours
            .build();

        assert_eq!(
            long_timeout_config.resource_config.analysis_timeout,
            Duration::from_secs(86400)
        );
    }

    #[test]
    fn test_pattern_config_validation_edge_cases() {
        let mut config = DetectionConfig::default();

        // Test with empty enabled categories
        // Test that None enabled_categories is valid
        assert!(config.pattern_config.enabled_categories.is_none());
        assert!(config.validate().is_ok()); // Should be valid, just no patterns enabled

        // Test with very large max_patterns
        config.pattern_config.max_patterns = usize::MAX;
        assert!(config.validate().is_ok()); // Should be valid

        // Test with custom patterns
        config.pattern_config.custom_patterns =
            vec!["valid_pattern_1".to_string(), "valid_pattern_2".to_string()];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_resource_config_validation_edge_cases() {
        let mut config = DetectionConfig::default();

        // Test with very large concurrent analyses
        config.resource_config.max_concurrent_analyses = usize::MAX;
        assert!(config.validate().is_ok());

        // Test with very large memory limit
        config.resource_config.max_memory_mb = usize::MAX;
        assert!(config.validate().is_ok());

        // Test with very large cache size
        config.resource_config.pattern_cache_size = usize::MAX;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_semantic_config_validation_edge_cases() {
        let mut config = DetectionConfig::default();

        // Test disabled semantic config with invalid threshold - should be OK
        config.semantic_config.enabled = false;
        config.semantic_config.similarity_threshold = -1.0;
        assert!(config.validate().is_ok()); // Invalid threshold ignored when disabled

        // Test enabled with valid edge case thresholds
        config.semantic_config.enabled = true;
        config.semantic_config.similarity_threshold = 0.001; // Very low but valid
        assert!(config.validate().is_ok());

        config.semantic_config.similarity_threshold = 1.0; // Maximum valid
        assert!(config.validate().is_ok());

        // Test with very large context length
        config.semantic_config.max_context_length = usize::MAX;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_severity_level_serialization() {
        let levels = vec![
            SeverityLevel::Low,
            SeverityLevel::Medium,
            SeverityLevel::High,
            SeverityLevel::Paranoid,
        ];

        for level in levels {
            let json = serde_json::to_string(&level).unwrap();
            let deserialized: SeverityLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, deserialized);
        }
    }

    #[test]
    fn test_response_strategy_serialization() {
        let strategies = vec![
            ResponseStrategy::Allow,
            ResponseStrategy::Block,
            ResponseStrategy::Sanitize,
            ResponseStrategy::Warn,
            ResponseStrategy::Custom("test message".to_string()),
        ];

        for strategy in strategies {
            let json = serde_json::to_string(&strategy).unwrap();
            let deserialized: ResponseStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(strategy, deserialized);
        }
    }
}
