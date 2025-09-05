//! Advanced configuration builder API for FluxPrompt custom configurations.
//!
//! This module provides a fluent builder API that allows users to create fully
//! customized configurations with granular control over all aspects of prompt
//! injection detection and mitigation.

use std::time::Duration;

use crate::config::{ResponseStrategy, SecurityLevel};
#[cfg(test)]
use crate::custom_config::RateLimitStrategy;
use crate::custom_config::{
    ContextAwarenessConfig, CustomConfig, LanguageSettings, LocaleSettings, RateLimitConfig,
    RoleConfig, TimeBasedRules,
};
use crate::features::{Features, FeaturesBuilder};
use crate::presets::Preset;
use crate::types::PreprocessingConfig;

/// Builder for creating comprehensive custom configurations.
#[derive(Debug)]
pub struct CustomConfigBuilder {
    config: CustomConfig,
}

impl CustomConfigBuilder {
    /// Creates a new builder with default settings.
    pub fn new() -> Self {
        Self {
            config: CustomConfig::new(
                "Custom Configuration".to_string(),
                "User-defined configuration".to_string(),
            ),
        }
    }

    /// Creates a builder starting from a preset configuration.
    pub fn from_preset(preset: Preset) -> Self {
        Self {
            config: CustomConfig::from_preset(
                preset.clone(),
                format!("{} Configuration", preset),
                format!("Configuration based on {} preset", preset),
            ),
        }
    }

    /// Creates a builder from an existing custom configuration.
    pub fn from_config(config: CustomConfig) -> Self {
        Self { config }
    }

    // Basic Configuration Methods

    /// Sets the configuration name.
    pub fn with_name<S: Into<String>>(mut self, name: S) -> Self {
        self.config.name = name.into();
        self.config.touch();
        self
    }

    /// Sets the configuration description.
    pub fn with_description<S: Into<String>>(mut self, description: S) -> Self {
        self.config.description = description.into();
        self.config.touch();
        self
    }

    /// Sets the configuration version.
    pub fn with_version<S: Into<String>>(mut self, version: S) -> Self {
        self.config.version = version.into();
        self.config.touch();
        self
    }

    /// Adds a tag to the configuration.
    pub fn with_tag<S: Into<String>>(mut self, tag: S) -> Self {
        self.config.tags.push(tag.into());
        self.config.touch();
        self
    }

    /// Adds multiple tags to the configuration.
    pub fn with_tags<I, S>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for tag in tags {
            self.config.tags.push(tag.into());
        }
        self.config.touch();
        self
    }

    /// Adds metadata to the configuration.
    pub fn with_metadata<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.config.metadata.insert(key.into(), value.into());
        self.config.touch();
        self
    }

    /// Sets whether the configuration is enabled.
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self.config.touch();
        self
    }

    // Security Configuration Methods

    /// Sets the security level (0-10 scale).
    pub fn with_security_level(mut self, level: u8) -> Result<Self, String> {
        self.config.detection_config.security_level = SecurityLevel::new(level)?;
        self.config.touch();
        Ok(self)
    }

    /// Sets the response strategy.
    pub fn with_response_strategy(mut self, strategy: ResponseStrategy) -> Self {
        self.config.detection_config.response_strategy = strategy;
        self.config.touch();
        self
    }

    /// Sets a custom response template for a specific scenario.
    pub fn with_response_template<K: Into<String>, V: Into<String>>(
        mut self,
        scenario: K,
        template: V,
    ) -> Self {
        self.config
            .advanced_options
            .response_templates
            .insert(scenario.into(), template.into());
        self.config.touch();
        self
    }

    // Feature Configuration Methods

    /// Sets the features configuration.
    pub fn with_features(mut self, features: Features) -> Self {
        self.config.features = features;
        self.config.touch();
        self
    }

    /// Configures features using a builder pattern.
    pub fn configure_features<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(FeaturesBuilder) -> FeaturesBuilder,
    {
        let builder = FeaturesBuilder::from_base(self.config.features.clone());
        self.config.features = configure(builder).build();
        self.config.touch();
        self
    }

    /// Enables a specific feature.
    pub fn enable_feature(mut self, feature_name: &str) -> Result<Self, String> {
        self.config.features.enable_feature(feature_name)?;
        self.config.touch();
        Ok(self)
    }

    /// Disables a specific feature.
    pub fn disable_feature(mut self, feature_name: &str) -> Result<Self, String> {
        self.config.features.disable_feature(feature_name)?;
        self.config.touch();
        Ok(self)
    }

    // Threshold Configuration Methods

    /// Sets a custom threshold for a detection category.
    pub fn override_threshold<S: Into<String>>(
        mut self,
        category: S,
        threshold: f32,
    ) -> Result<Self, String> {
        if !(0.0..=1.0).contains(&threshold) {
            return Err(format!(
                "Threshold must be between 0.0 and 1.0, got: {}",
                threshold
            ));
        }
        self.config
            .advanced_options
            .category_thresholds
            .insert(category.into(), threshold);
        self.config.touch();
        Ok(self)
    }

    /// Sets a custom weight for a threat type.
    pub fn override_threat_weight<S: Into<String>>(
        mut self,
        threat_type: S,
        weight: f32,
    ) -> Result<Self, String> {
        if weight < 0.0 {
            return Err(format!("Weight must be non-negative, got: {}", weight));
        }
        self.config
            .advanced_options
            .threat_weights
            .insert(threat_type.into(), weight);
        self.config.touch();
        Ok(self)
    }

    /// Sets category-specific sensitivity level (0-10).
    pub fn set_category_sensitivity<S: Into<String>>(
        mut self,
        category: S,
        sensitivity: u8,
    ) -> Result<Self, String> {
        if sensitivity > 10 {
            return Err(format!(
                "Sensitivity must be between 0 and 10, got: {}",
                sensitivity
            ));
        }

        // Convert sensitivity to threshold (higher sensitivity = lower threshold)
        let threshold = (10.0 - sensitivity as f32) / 10.0 * 0.8 + 0.1; // Maps 0-10 to 0.9-0.1
        self.config
            .advanced_options
            .category_thresholds
            .insert(category.into(), threshold);
        self.config.touch();
        Ok(self)
    }

    // Pattern Configuration Methods

    /// Adds a custom pattern to the configuration.
    pub fn add_custom_pattern<S: Into<String>>(mut self, pattern: S) -> Self {
        self.config
            .detection_config
            .pattern_config
            .custom_patterns
            .push(pattern.into());
        self.config.touch();
        self
    }

    /// Adds multiple custom patterns.
    pub fn add_custom_patterns<I, S>(mut self, patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for pattern in patterns {
            self.config
                .detection_config
                .pattern_config
                .custom_patterns
                .push(pattern.into());
        }
        self.config.touch();
        self
    }

    /// Adds a pattern to the allowlist (patterns that should never be flagged).
    pub fn add_pattern_allowlist<S: Into<String>>(mut self, pattern: S) -> Self {
        self.config
            .advanced_options
            .pattern_allowlists
            .push(pattern.into());
        self.config.touch();
        self
    }

    /// Adds a pattern to the denylist (patterns that should always be flagged).
    pub fn add_pattern_denylist<S: Into<String>>(mut self, pattern: S) -> Self {
        self.config
            .advanced_options
            .pattern_denylists
            .push(pattern.into());
        self.config.touch();
        self
    }

    /// Sets whether pattern matching should be case-sensitive.
    pub fn case_sensitive_patterns(mut self, case_sensitive: bool) -> Self {
        self.config.detection_config.pattern_config.case_sensitive = case_sensitive;
        self.config.touch();
        self
    }

    /// Sets the maximum number of patterns to compile.
    pub fn max_patterns(mut self, max_patterns: usize) -> Self {
        self.config.detection_config.pattern_config.max_patterns = max_patterns;
        self.config.touch();
        self
    }

    // Semantic Analysis Configuration

    /// Enables semantic analysis with optional model name.
    pub fn enable_semantic_analysis(mut self, model_name: Option<String>) -> Self {
        self.config.detection_config.semantic_config.enabled = true;
        self.config.detection_config.semantic_config.model_name = model_name;
        self.config.touch();
        self
    }

    /// Sets the semantic similarity threshold.
    pub fn semantic_threshold(mut self, threshold: f32) -> Result<Self, String> {
        if threshold <= 0.0 || threshold > 1.0 {
            return Err(format!(
                "Semantic threshold must be between 0.0 and 1.0, got: {}",
                threshold
            ));
        }
        self.config
            .detection_config
            .semantic_config
            .similarity_threshold = threshold;
        self.config.touch();
        Ok(self)
    }

    /// Sets the maximum context length for semantic analysis.
    pub fn semantic_context_length(mut self, length: usize) -> Self {
        self.config
            .detection_config
            .semantic_config
            .max_context_length = length;
        self.config.touch();
        self
    }

    // Resource Configuration

    /// Sets the analysis timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.config
            .detection_config
            .resource_config
            .analysis_timeout = timeout;
        self.config.touch();
        self
    }

    /// Sets the maximum number of concurrent analyses.
    pub fn max_concurrent_analyses(mut self, max: usize) -> Self {
        self.config
            .detection_config
            .resource_config
            .max_concurrent_analyses = max;
        self.config.touch();
        self
    }

    /// Sets the maximum memory usage in MB.
    pub fn max_memory_mb(mut self, max_memory: usize) -> Self {
        self.config.detection_config.resource_config.max_memory_mb = max_memory;
        self.config.touch();
        self
    }

    /// Sets the pattern cache size.
    pub fn pattern_cache_size(mut self, cache_size: usize) -> Self {
        self.config
            .detection_config
            .resource_config
            .pattern_cache_size = cache_size;
        self.config.touch();
        self
    }

    // Advanced Configuration Methods

    /// Configures rate limiting.
    pub fn configure_rate_limiting<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(&mut RateLimitConfig),
    {
        configure(&mut self.config.advanced_options.rate_limiting);
        self.config.touch();
        self
    }

    /// Sets rate limiting parameters.
    pub fn with_rate_limits(mut self, per_minute: u32, per_hour: u32, per_day: u32) -> Self {
        self.config
            .advanced_options
            .rate_limiting
            .requests_per_minute = per_minute;
        self.config.advanced_options.rate_limiting.requests_per_hour = per_hour;
        self.config.advanced_options.rate_limiting.requests_per_day = per_day;
        self.config.touch();
        self
    }

    /// Configures context awareness.
    pub fn configure_context_awareness<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(&mut ContextAwarenessConfig),
    {
        configure(&mut self.config.advanced_options.context_awareness);
        self.config.touch();
        self
    }

    /// Enables context awareness with conversation history.
    pub fn with_context_history(mut self, history_length: usize) -> Self {
        self.config
            .advanced_options
            .context_awareness
            .consider_history = true;
        self.config
            .advanced_options
            .context_awareness
            .history_length = history_length;
        self.config.touch();
        self
    }

    /// Adds a language-specific configuration.
    pub fn add_language_config<S: Into<String>>(
        mut self,
        language: S,
        config: LanguageSettings,
    ) -> Self {
        self.config
            .advanced_options
            .language_settings
            .insert(language.into(), config);
        self.config.touch();
        self
    }

    /// Adds a role-based configuration override.
    pub fn add_role_config<S: Into<String>>(mut self, role: S, config: RoleConfig) -> Self {
        self.config
            .advanced_options
            .role_configurations
            .insert(role.into(), config);
        self.config.touch();
        self
    }

    /// Adds a locale-specific configuration.
    pub fn add_locale_config<S: Into<String>>(mut self, locale: S, config: LocaleSettings) -> Self {
        self.config
            .advanced_options
            .locale_settings
            .insert(locale.into(), config);
        self.config.touch();
        self
    }

    /// Configures time-based rules.
    pub fn with_time_based_rules(mut self, rules: TimeBasedRules) -> Self {
        self.config.advanced_options.time_based_rules = Some(rules);
        self.config.touch();
        self
    }

    // Preprocessing Configuration

    /// Configures text preprocessing options.
    pub fn configure_preprocessing<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(&mut PreprocessingConfig),
    {
        configure(&mut self.config.detection_config.preprocessing_config);
        self.config.touch();
        self
    }

    /// Sets the maximum text length to analyze.
    pub fn max_text_length(mut self, max_length: usize) -> Self {
        self.config.detection_config.preprocessing_config.max_length = max_length;
        self.config.touch();
        self
    }

    /// Sets whether to preserve formatting during preprocessing.
    pub fn preserve_formatting(mut self, preserve: bool) -> Self {
        self.config
            .detection_config
            .preprocessing_config
            .preserve_formatting = preserve;
        self.config.touch();
        self
    }

    /// Sets whether to normalize Unicode characters.
    pub fn normalize_unicode(mut self, normalize: bool) -> Self {
        self.config
            .detection_config
            .preprocessing_config
            .normalize_unicode = normalize;
        self.config.touch();
        self
    }

    /// Sets whether to decode common encodings.
    pub fn decode_encodings(mut self, decode: bool) -> Self {
        self.config
            .detection_config
            .preprocessing_config
            .decode_encodings = decode;
        self.config.touch();
        self
    }

    // Metrics Configuration

    /// Enables or disables metrics collection.
    pub fn enable_metrics(mut self, enabled: bool) -> Self {
        self.config.detection_config.enable_metrics = enabled;
        self.config.touch();
        self
    }

    // Validation and Building

    /// Validates the configuration before building.
    pub fn validate(mut self) -> Result<Self, String> {
        self.config.validate().map_err(|e| e.to_string())?;
        Ok(self)
    }

    /// Builds the configuration without validation.
    pub fn build(self) -> CustomConfig {
        self.config
    }

    /// Builds and validates the configuration.
    pub fn build_validated(mut self) -> Result<CustomConfig, String> {
        self.config.validate().map_err(|e| e.to_string())?;
        Ok(self.config)
    }

    /// Creates a preset-specific builder with common configurations for that use case.
    pub fn for_use_case(use_case: &str) -> Self {
        let preset = match use_case.to_lowercase().as_str() {
            "chatbot" | "chat" | "conversation" => Preset::ChatBot,
            "code" | "programming" | "development" => Preset::CodeAssistant,
            "customer" | "support" | "service" => Preset::CustomerService,
            "education" | "learning" | "school" => Preset::Educational,
            "financial" | "banking" | "payment" => Preset::Financial,
            "healthcare" | "medical" | "hipaa" => Preset::Healthcare,
            "dev" | "debug" | "testing" => Preset::Development,
            _ => Preset::ChatBot, // Default
        };

        Self::from_preset(preset)
    }

    /// Creates a builder optimized for high performance.
    pub fn high_performance() -> Self {
        Self::from_preset(Preset::Development)
            .with_name("High Performance Configuration".to_string())
            .with_description("Optimized for speed and low resource usage".to_string())
            .configure_features(|f| {
                f.with_semantic_detection(false)
                    .with_heuristic_analysis(false)
            })
            .max_concurrent_analyses(500)
            .with_timeout(Duration::from_secs(1))
            .max_memory_mb(128)
    }

    /// Creates a builder optimized for maximum security.
    pub fn maximum_security() -> Self {
        Self::from_preset(Preset::Financial)
            .with_name("Maximum Security Configuration".to_string())
            .with_description(
                "Comprehensive security with all detection methods enabled".to_string(),
            )
            .configure_features(|_f| FeaturesBuilder::from_base(Features::all_enabled()))
            .enable_semantic_analysis(Some("sentence-transformers/all-MiniLM-L6-v2".to_string()))
            .with_timeout(Duration::from_secs(30))
            .max_memory_mb(2048)
    }

    /// Creates a builder balanced for production use.
    pub fn production_ready() -> Self {
        Self::from_preset(Preset::ChatBot)
            .with_name("Production Configuration".to_string())
            .with_description(
                "Balanced configuration suitable for production environments".to_string(),
            )
            .max_concurrent_analyses(200)
            .with_timeout(Duration::from_secs(5))
            .with_rate_limits(120, 2000, 20000) // Generous but controlled
            .enable_metrics(true)
    }
}

impl Default for CustomConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_builder() {
        let config = CustomConfigBuilder::new()
            .with_name("Test Config")
            .with_description("A test configuration")
            .with_security_level(7)
            .unwrap()
            .with_response_strategy(ResponseStrategy::Block)
            .enable_metrics(true)
            .build();

        assert_eq!(config.name, "Test Config");
        assert_eq!(config.description, "A test configuration");
        assert_eq!(config.detection_config.security_level.level(), 7);
        assert_eq!(
            config.detection_config.response_strategy,
            ResponseStrategy::Block
        );
        assert!(config.detection_config.enable_metrics);
    }

    #[test]
    fn test_preset_builder() {
        let config = CustomConfigBuilder::from_preset(Preset::Healthcare)
            .with_name("Custom Healthcare Config")
            .override_threshold("phi_detection", 0.6)
            .unwrap()
            .add_custom_pattern(r"(?i)patient\s+id")
            .build();

        assert_eq!(config.name, "Custom Healthcare Config");
        assert_eq!(config.base_preset, Some(Preset::Healthcare));
        assert_eq!(config.detection_config.security_level.level(), 8); // Healthcare preset level
        assert!(config
            .advanced_options
            .category_thresholds
            .contains_key("phi_detection"));
        assert!(config
            .detection_config
            .pattern_config
            .custom_patterns
            .contains(&"(?i)patient\\s+id".to_string()));
    }

    #[test]
    fn test_features_configuration() {
        let config = CustomConfigBuilder::new()
            .configure_features(|f| {
                f.with_pattern_matching(true)
                    .with_semantic_detection(true)
                    .with_heuristic_analysis(false)
            })
            .build();

        assert!(config.features.pattern_matching);
        assert!(config.features.semantic_detection);
        assert!(!config.features.heuristic_analysis);
    }

    #[test]
    fn test_threshold_overrides() {
        let config = CustomConfigBuilder::new()
            .override_threshold("test_category", 0.8)
            .unwrap()
            .override_threat_weight("TestThreat", 1.5)
            .unwrap()
            .set_category_sensitivity("sensitive_category", 8)
            .unwrap()
            .build();

        assert_eq!(
            config
                .advanced_options
                .category_thresholds
                .get("test_category"),
            Some(&0.8)
        );
        assert_eq!(
            config.advanced_options.threat_weights.get("TestThreat"),
            Some(&1.5)
        );
        assert!(config
            .advanced_options
            .category_thresholds
            .contains_key("sensitive_category"));
    }

    #[test]
    fn test_threshold_validation() {
        // Invalid threshold (> 1.0)
        let result = CustomConfigBuilder::new().override_threshold("test", 1.5);
        assert!(result.is_err());

        // Invalid threshold (< 0.0)
        let result = CustomConfigBuilder::new().override_threshold("test", -0.1);
        assert!(result.is_err());

        // Invalid weight (< 0.0)
        let result = CustomConfigBuilder::new().override_threat_weight("test", -1.0);
        assert!(result.is_err());

        // Invalid sensitivity (> 10)
        let result = CustomConfigBuilder::new().set_category_sensitivity("test", 11);
        assert!(result.is_err());
    }

    #[test]
    fn test_pattern_configuration() {
        let config = CustomConfigBuilder::new()
            .add_custom_pattern("pattern1")
            .add_custom_patterns(vec!["pattern2", "pattern3"])
            .add_pattern_allowlist("allowed_pattern")
            .add_pattern_denylist("denied_pattern")
            .case_sensitive_patterns(true)
            .max_patterns(5000)
            .build();

        assert_eq!(
            config.detection_config.pattern_config.custom_patterns.len(),
            3
        );
        assert!(config
            .detection_config
            .pattern_config
            .custom_patterns
            .contains(&"pattern1".to_string()));
        assert!(config
            .advanced_options
            .pattern_allowlists
            .contains(&"allowed_pattern".to_string()));
        assert!(config
            .advanced_options
            .pattern_denylists
            .contains(&"denied_pattern".to_string()));
        assert!(config.detection_config.pattern_config.case_sensitive);
        assert_eq!(config.detection_config.pattern_config.max_patterns, 5000);
    }

    #[test]
    fn test_semantic_configuration() {
        let config = CustomConfigBuilder::new()
            .enable_semantic_analysis(Some("test-model".to_string()))
            .semantic_threshold(0.7)
            .unwrap()
            .semantic_context_length(1024)
            .build();

        assert!(config.detection_config.semantic_config.enabled);
        assert_eq!(
            config
                .detection_config
                .semantic_config
                .model_name
                .as_ref()
                .unwrap(),
            "test-model"
        );
        assert_eq!(
            config.detection_config.semantic_config.similarity_threshold,
            0.7
        );
        assert_eq!(
            config.detection_config.semantic_config.max_context_length,
            1024
        );
    }

    #[test]
    fn test_resource_configuration() {
        let config = CustomConfigBuilder::new()
            .with_timeout(Duration::from_secs(15))
            .max_concurrent_analyses(50)
            .max_memory_mb(1024)
            .pattern_cache_size(2000)
            .build();

        assert_eq!(
            config.detection_config.resource_config.analysis_timeout,
            Duration::from_secs(15)
        );
        assert_eq!(
            config
                .detection_config
                .resource_config
                .max_concurrent_analyses,
            50
        );
        assert_eq!(config.detection_config.resource_config.max_memory_mb, 1024);
        assert_eq!(
            config.detection_config.resource_config.pattern_cache_size,
            2000
        );
    }

    #[test]
    fn test_rate_limiting_configuration() {
        let config = CustomConfigBuilder::new()
            .with_rate_limits(60, 1000, 10000)
            .configure_rate_limiting(|rate_config| {
                rate_config.burst_allowance = 20;
                rate_config.enforcement_strategy = RateLimitStrategy::Drop;
            })
            .build();

        assert_eq!(
            config.advanced_options.rate_limiting.requests_per_minute,
            60
        );
        assert_eq!(
            config.advanced_options.rate_limiting.requests_per_hour,
            1000
        );
        assert_eq!(
            config.advanced_options.rate_limiting.requests_per_day,
            10000
        );
        assert_eq!(config.advanced_options.rate_limiting.burst_allowance, 20);
        assert!(matches!(
            config.advanced_options.rate_limiting.enforcement_strategy,
            RateLimitStrategy::Drop
        ));
    }

    #[test]
    fn test_context_awareness_configuration() {
        let config = CustomConfigBuilder::new()
            .with_context_history(20)
            .configure_context_awareness(|context_config| {
                context_config.track_user_patterns = true;
                context_config.trust_score_adjustment = 0.1;
            })
            .build();

        assert!(config.advanced_options.context_awareness.consider_history);
        assert_eq!(config.advanced_options.context_awareness.history_length, 20);
        assert!(
            config
                .advanced_options
                .context_awareness
                .track_user_patterns
        );
        assert_eq!(
            config
                .advanced_options
                .context_awareness
                .trust_score_adjustment,
            0.1
        );
    }

    #[test]
    fn test_preprocessing_configuration() {
        let config = CustomConfigBuilder::new()
            .max_text_length(50000)
            .preserve_formatting(true)
            .normalize_unicode(false)
            .decode_encodings(false)
            .build();

        assert_eq!(
            config.detection_config.preprocessing_config.max_length,
            50000
        );
        assert!(
            config
                .detection_config
                .preprocessing_config
                .preserve_formatting
        );
        assert!(
            !config
                .detection_config
                .preprocessing_config
                .normalize_unicode
        );
        assert!(
            !config
                .detection_config
                .preprocessing_config
                .decode_encodings
        );
    }

    #[test]
    fn test_use_case_builders() {
        let chatbot_config = CustomConfigBuilder::for_use_case("chatbot").build();
        assert_eq!(chatbot_config.base_preset, Some(Preset::ChatBot));

        let financial_config = CustomConfigBuilder::for_use_case("financial").build();
        assert_eq!(financial_config.base_preset, Some(Preset::Financial));

        let code_config = CustomConfigBuilder::for_use_case("code").build();
        assert_eq!(code_config.base_preset, Some(Preset::CodeAssistant));
    }

    #[test]
    fn test_specialized_builders() {
        let high_perf = CustomConfigBuilder::high_performance().build();
        assert!(high_perf.name.contains("High Performance"));
        assert!(!high_perf.features.semantic_detection);
        assert_eq!(
            high_perf.detection_config.resource_config.analysis_timeout,
            Duration::from_secs(1)
        );

        let max_security = CustomConfigBuilder::maximum_security().build();
        assert!(max_security.name.contains("Maximum Security"));
        assert!(max_security.detection_config.semantic_config.enabled);
        assert_eq!(
            max_security.detection_config.resource_config.max_memory_mb,
            2048
        );

        let production = CustomConfigBuilder::production_ready().build();
        assert!(production.name.contains("Production"));
        assert_eq!(
            production
                .advanced_options
                .rate_limiting
                .requests_per_minute,
            120
        );
        assert!(production.detection_config.enable_metrics);
    }

    #[test]
    fn test_metadata_and_tags() {
        let config = CustomConfigBuilder::new()
            .with_metadata("environment", "production")
            .with_metadata("version", "2.0")
            .with_tag("security")
            .with_tags(vec!["production", "validated"])
            .build();

        assert_eq!(config.metadata.get("environment").unwrap(), "production");
        assert_eq!(config.metadata.get("version").unwrap(), "2.0");
        assert!(config.tags.contains(&"security".to_string()));
        assert!(config.tags.contains(&"production".to_string()));
        assert!(config.tags.contains(&"validated".to_string()));
    }

    #[test]
    fn test_validation() {
        let valid_config = CustomConfigBuilder::new()
            .with_security_level(5)
            .unwrap()
            .override_threshold("test", 0.8)
            .unwrap()
            .validate()
            .unwrap()
            .build();

        assert!(valid_config.validation_status.is_valid);

        // Test validation failure (this should be tested with invalid config)
        // Note: The validate() method would catch invalid configurations
    }

    #[test]
    fn test_feature_enable_disable() {
        let config = CustomConfigBuilder::new()
            .enable_feature("pattern_matching")
            .unwrap()
            .disable_feature("semantic_detection")
            .unwrap()
            .build();

        assert!(config.features.pattern_matching);
        assert!(!config.features.semantic_detection);

        // Test invalid feature name
        let result = CustomConfigBuilder::new().enable_feature("invalid_feature");
        assert!(result.is_err());
    }

    #[test]
    fn test_response_templates() {
        let config = CustomConfigBuilder::new()
            .with_response_template("block", "Access denied: {reason}")
            .with_response_template("warn", "Warning: {message}")
            .build();

        assert_eq!(
            config
                .advanced_options
                .response_templates
                .get("block")
                .unwrap(),
            "Access denied: {reason}"
        );
        assert_eq!(
            config
                .advanced_options
                .response_templates
                .get("warn")
                .unwrap(),
            "Warning: {message}"
        );
    }
}
