//! Serializable configuration wrappers and advanced policy metadata.
//!
//! [`crate::FluxPrompt::from_custom_config`] currently consumes only
//! [`CustomConfig::detection_config`]. Feature descriptors and advanced options
//! can be stored and validated here, but FluxPrompt does not independently
//! enforce them.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
#[cfg(test)]
use std::time::Duration;
use std::time::SystemTime;
use uuid::Uuid;

use crate::config::{DetectionConfig, ResponseStrategy, SecurityLevel};
use crate::features::Features;
use crate::presets::Preset;

/// Advanced policy-shaped metadata.
///
/// The current detector does not consume these values. A host application may
/// interpret and enforce them separately.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdvancedOptions {
    /// Per-category confidence thresholds (category_name -> threshold)
    pub category_thresholds: HashMap<String, f32>,
    /// Per-threat-type severity weights (threat_type -> weight)
    pub threat_weights: HashMap<String, f32>,
    /// Language-specific configuration overrides
    pub language_settings: HashMap<String, LanguageSettings>,
    /// Time-based rules for different periods
    pub time_based_rules: Option<TimeBasedRules>,
    /// User role-based configuration overrides
    pub role_configurations: HashMap<String, RoleConfig>,
    /// Geographic/locale-specific settings
    pub locale_settings: HashMap<String, LocaleSettings>,
    /// Rate limiting configuration per endpoint/user
    pub rate_limiting: RateLimitConfig,
    /// Custom response templates for different scenarios
    pub response_templates: HashMap<String, String>,
    /// Pattern allowlist metadata for a host application
    pub pattern_allowlists: Vec<String>,
    /// Pattern denylist metadata for a host application
    pub pattern_denylists: Vec<String>,
    /// Context-aware settings that consider conversation history
    pub context_awareness: ContextAwarenessConfig,
}

/// Language-specific metadata for a host application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageSettings {
    /// Language-specific pattern overrides
    pub custom_patterns: Vec<String>,
    /// Confidence threshold adjustment for this language
    pub threshold_adjustment: f32,
    /// Whether to enable unicode normalization for this language
    pub normalize_unicode: bool,
    /// Character set considerations
    pub character_set: Option<String>,
}

/// Time-based policy metadata for a host application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBasedRules {
    /// Business hours configuration (stricter rules)
    pub business_hours: TimeConfig,
    /// After hours configuration (more permissive)
    pub after_hours: TimeConfig,
    /// Weekend configuration
    pub weekend: TimeConfig,
    /// Holiday configuration
    pub holiday: TimeConfig,
    /// Timezone for time-based rules
    pub timezone: String,
}

/// Configuration for a specific time period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeConfig {
    /// Security level override for this time period
    pub security_level_override: Option<SecurityLevel>,
    /// Response strategy override for this time period
    pub response_strategy_override: Option<ResponseStrategy>,
    /// Feature toggles override for this time period
    pub features_override: Option<Features>,
    /// Custom threshold adjustments
    pub threshold_adjustments: HashMap<String, f32>,
}

/// Role-based policy metadata for a host application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleConfig {
    /// Role name/identifier
    pub role_name: String,
    /// Security level for this role
    pub security_level: Option<SecurityLevel>,
    /// Features enabled for this role
    pub features: Option<Features>,
    /// Custom patterns specific to this role
    pub custom_patterns: Vec<String>,
    /// Response strategy for this role
    pub response_strategy: Option<ResponseStrategy>,
    /// Additional permissions or restrictions
    pub permissions: HashMap<String, bool>,
}

/// Geographic/locale policy metadata for a host application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocaleSettings {
    /// Locale identifier (e.g., "en-US", "fr-FR")
    pub locale: String,
    /// Compliance labels supplied by the host application
    pub compliance_requirements: Vec<String>,
    /// Locale-specific patterns
    pub custom_patterns: Vec<String>,
    /// Privacy-regulation labels supplied by the host application
    pub privacy_regulations: Vec<String>,
    /// Cultural sensitivity adjustments
    pub cultural_adjustments: HashMap<String, f32>,
}

/// Rate-limit metadata for a host application.
///
/// FluxPrompt does not enforce these limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per minute per user/IP
    pub requests_per_minute: u32,
    /// Maximum requests per hour per user/IP
    pub requests_per_hour: u32,
    /// Maximum requests per day per user/IP
    pub requests_per_day: u32,
    /// Burst allowance for sudden traffic spikes
    pub burst_allowance: u32,
    /// Rate limit enforcement strategy
    pub enforcement_strategy: RateLimitStrategy,
    /// Custom rate limits per endpoint/operation
    pub custom_limits: HashMap<String, CustomRateLimit>,
}

/// Rate limiting enforcement strategies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RateLimitStrategy {
    /// Drop requests that exceed the limit
    Drop,
    /// Queue requests and process them later
    Queue,
    /// Apply stricter security measures for rate-limited requests
    StricterSecurity,
    /// Send warning but allow the request
    WarnAndAllow,
}

/// Custom rate limit for specific operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRateLimit {
    /// Operation/endpoint identifier
    pub operation: String,
    /// Requests per minute for this operation
    pub requests_per_minute: u32,
    /// Additional restrictions
    pub restrictions: HashMap<String, String>,
}

/// Conversation-context metadata for a host application.
///
/// FluxPrompt analyzes one string at a time and does not consume this history
/// configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextAwarenessConfig {
    /// Whether to consider conversation history
    pub consider_history: bool,
    /// Maximum number of previous messages to consider
    pub history_length: usize,
    /// Whether to track user behavior patterns
    pub track_user_patterns: bool,
    /// Confidence adjustment based on user trust score
    pub trust_score_adjustment: f32,
    /// Context window for pattern detection
    pub context_window_size: usize,
}

/// Serializable custom configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomConfig {
    /// Unique identifier for this configuration
    pub id: Uuid,
    /// Human-readable name for this configuration
    pub name: String,
    /// Description of this configuration's purpose
    pub description: String,
    /// Version of this configuration
    pub version: String,
    /// Creation timestamp
    pub created_at: SystemTime,
    /// Last modified timestamp
    pub modified_at: SystemTime,
    /// Base preset this configuration is derived from
    pub base_preset: Option<Preset>,
    /// Core detection configuration
    pub detection_config: DetectionConfig,
    /// Feature descriptors; not applied by the current runtime
    pub features: Features,
    /// Advanced policy metadata; not enforced by the current runtime
    pub advanced_options: AdvancedOptions,
    /// Configuration metadata
    pub metadata: HashMap<String, String>,
    /// Configuration tags for organization
    pub tags: Vec<String>,
    /// Whether this configuration is active/enabled
    pub enabled: bool,
    /// Configuration validation status
    pub validation_status: ValidationStatus,
}

/// Validation status of a configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationStatus {
    /// Whether the configuration is valid
    pub is_valid: bool,
    /// Validation timestamp
    pub validated_at: SystemTime,
    /// Validation errors if any
    pub errors: Vec<String>,
    /// Validation warnings
    pub warnings: Vec<String>,
    /// Non-cryptographic marker for detecting configuration changes.
    ///
    /// The field name is retained for wire compatibility. This value is not a
    /// security checksum and must not be used to establish integrity,
    /// authenticity, or trust. Its format may change between crate releases.
    pub checksum: String,
}

#[derive(Serialize)]
struct ChangeMarkerMaterial<'a> {
    id: &'a Uuid,
    name: &'a str,
    description: &'a str,
    version: &'a str,
    created_at: &'a SystemTime,
    modified_at: &'a SystemTime,
    base_preset: &'a Option<Preset>,
    detection_config: &'a DetectionConfig,
    features: &'a Features,
    advanced_options: &'a AdvancedOptions,
    metadata: &'a HashMap<String, String>,
    tags: &'a [String],
    enabled: bool,
}

impl CustomConfig {
    /// Creates a new custom configuration.
    pub fn new(name: String, description: String) -> Self {
        let now = SystemTime::now();
        Self {
            id: Uuid::new_v4(),
            name,
            description,
            version: "1.0.0".to_string(),
            created_at: now,
            modified_at: now,
            base_preset: None,
            detection_config: DetectionConfig::default(),
            features: Features::default(),
            advanced_options: AdvancedOptions::default(),
            metadata: HashMap::new(),
            tags: Vec::new(),
            enabled: true,
            validation_status: ValidationStatus::new(),
        }
    }

    /// Creates a custom configuration from a preset.
    pub fn from_preset(preset: Preset, name: String, description: String) -> Self {
        let now = SystemTime::now();
        Self {
            id: Uuid::new_v4(),
            name,
            description,
            version: "1.0.0".to_string(),
            created_at: now,
            modified_at: now,
            base_preset: Some(preset.clone()),
            detection_config: preset.to_detection_config(),
            features: preset.features(),
            advanced_options: AdvancedOptions::default(),
            metadata: preset.custom_config(),
            tags: vec!["preset".to_string(), preset.to_string().to_lowercase()],
            enabled: true,
            validation_status: ValidationStatus::new(),
        }
    }

    /// Validates the configuration and updates validation status.
    pub fn validate(&mut self) -> crate::Result<()> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Validate core detection config
        if let Err(e) = self.detection_config.validate() {
            errors.push(format!("Detection config error: {}", e));
        }

        // Validate feature consistency
        self.validate_feature_consistency(&mut warnings);

        // Validate advanced options
        self.validate_advanced_options(&mut errors, &mut warnings);

        // Validate thresholds
        self.validate_thresholds(&mut errors);

        let change_marker = match self.calculate_change_marker() {
            Ok(marker) => marker,
            Err(error) => {
                errors.push(format!(
                    "Configuration change marker could not be calculated: {error}"
                ));
                String::new()
            }
        };

        // Update validation status
        self.validation_status = ValidationStatus {
            is_valid: errors.is_empty(),
            validated_at: SystemTime::now(),
            errors,
            warnings,
            checksum: change_marker,
        };

        if !self.validation_status.is_valid {
            Err(crate::error::FluxPromptError::config(
                "Configuration validation failed",
            ))
        } else {
            Ok(())
        }
    }

    /// Validates feature consistency between detection config and features.
    fn validate_feature_consistency(&self, warnings: &mut Vec<String>) {
        // Check if semantic detection is enabled in features but not configured properly
        if self.features.semantic_detection && !self.detection_config.semantic_config.enabled {
            warnings.push(
                "Semantic detection enabled in features but disabled in detection config"
                    .to_string(),
            );
        }

        // Check if pattern matching is disabled but custom patterns are provided
        if !self.features.pattern_matching
            && !self
                .detection_config
                .pattern_config
                .custom_patterns
                .is_empty()
        {
            warnings.push("Pattern matching disabled but custom patterns provided".to_string());
        }
    }

    /// Validates advanced options.
    fn validate_advanced_options(&self, errors: &mut Vec<String>, warnings: &mut Vec<String>) {
        // Validate category thresholds
        for (category, threshold) in &self.advanced_options.category_thresholds {
            if !threshold.is_finite() || *threshold < 0.0 || *threshold > 1.0 {
                errors.push(format!(
                    "Invalid threshold for category {}: {}",
                    category, threshold
                ));
            }
        }

        // Validate threat weights
        for (threat_type, weight) in &self.advanced_options.threat_weights {
            if !weight.is_finite() || *weight < 0.0 {
                errors.push(format!(
                    "Invalid weight for threat type {}: {}",
                    threat_type, weight
                ));
            }
        }

        // Validate rate limiting
        if self.advanced_options.rate_limiting.requests_per_minute == 0 {
            warnings.push("Rate limiting disabled (0 requests per minute)".to_string());
        }

        // Validate context awareness settings
        if self.advanced_options.context_awareness.consider_history
            && self.advanced_options.context_awareness.history_length == 0
        {
            warnings.push("Context history enabled but history length is 0".to_string());
        }
    }

    /// Validates threshold values.
    fn validate_thresholds(&self, errors: &mut Vec<String>) {
        let security_level = self.detection_config.effective_security_level();
        let base_threshold = security_level.base_threshold();

        // Validate that category thresholds are reasonable relative to base threshold
        for (category, threshold) in &self.advanced_options.category_thresholds {
            if (*threshold - base_threshold).abs() > 0.5 {
                errors.push(format!(
                    "Category threshold for {} ({}) differs significantly from base threshold ({})",
                    category, threshold, base_threshold
                ));
            }
        }
    }

    /// Calculates a deterministic, non-cryptographic configuration change marker.
    fn calculate_change_marker(&self) -> serde_json::Result<String> {
        let material = ChangeMarkerMaterial {
            id: &self.id,
            name: &self.name,
            description: &self.description,
            version: &self.version,
            created_at: &self.created_at,
            modified_at: &self.modified_at,
            base_preset: &self.base_preset,
            detection_config: &self.detection_config,
            features: &self.features,
            advanced_options: &self.advanced_options,
            metadata: &self.metadata,
            tags: &self.tags,
            enabled: self.enabled,
        };
        let value = serde_json::to_value(material)?;
        let mut canonical = Vec::new();
        write_canonical_json(&value, &mut canonical)?;

        // FNV-1a is deliberately used as a small deterministic change detector,
        // not as a cryptographic integrity or authenticity mechanism.
        let mut marker = 0xcbf2_9ce4_8422_2325_u64;
        for byte in canonical {
            marker ^= u64::from(byte);
            marker = marker.wrapping_mul(0x0000_0100_0000_01b3);
        }

        Ok(format!("fnv1a64:{marker:016x}"))
    }

    /// Merges this configuration with another, with the other taking priority.
    pub fn merge_with(&mut self, other: &CustomConfig) {
        // Update metadata
        self.modified_at = SystemTime::now();
        self.version = other.version.clone();

        // Merge detection config (selective merge)
        if other.detection_config.security_level.level() != SecurityLevel::default().level() {
            self.detection_config.security_level = other.detection_config.security_level;
        }

        if other.detection_config.response_strategy != ResponseStrategy::default() {
            self.detection_config.response_strategy =
                other.detection_config.response_strategy.clone();
        }

        // Merge features (other takes priority for enabled features)
        if other.features != Features::default() {
            self.features = other.features.clone();
        }

        // Merge advanced options
        self.advanced_options
            .category_thresholds
            .extend(other.advanced_options.category_thresholds.clone());
        self.advanced_options
            .threat_weights
            .extend(other.advanced_options.threat_weights.clone());

        // Merge metadata
        self.metadata.extend(other.metadata.clone());

        // Merge tags (deduplicate)
        for tag in &other.tags {
            if !self.tags.contains(tag) {
                self.tags.push(tag.clone());
            }
        }

        // Reset validation status since config changed
        self.validation_status = ValidationStatus::new();
    }

    /// Exports the configuration to JSON format.
    pub fn to_json(&self) -> crate::Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| {
            crate::error::FluxPromptError::config(format!("JSON serialization error: {}", e))
        })
    }

    /// Imports a configuration from JSON format.
    pub fn from_json(json: &str) -> crate::Result<Self> {
        serde_json::from_str(json).map_err(|e| {
            crate::error::FluxPromptError::config(format!("JSON deserialization error: {}", e))
        })
    }

    /// Exports the configuration to YAML format.
    pub fn to_yaml(&self) -> crate::Result<String> {
        serde_yaml::to_string(self).map_err(|e| {
            crate::error::FluxPromptError::config(format!("YAML serialization error: {}", e))
        })
    }

    /// Imports a configuration from YAML format.
    pub fn from_yaml(yaml: &str) -> crate::Result<Self> {
        serde_yaml::from_str(yaml).map_err(|e| {
            crate::error::FluxPromptError::config(format!("YAML deserialization error: {}", e))
        })
    }

    /// Saves the configuration to a file.
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> crate::Result<()> {
        let path = path.as_ref();
        let content = match path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => self.to_json()?,
            Some("yaml") | Some("yml") => self.to_yaml()?,
            _ => {
                return Err(crate::error::FluxPromptError::config(
                    "Unsupported file format. Use .json, .yaml, or .yml",
                ));
            }
        };

        std::fs::write(path, content)
            .map_err(|e| crate::error::FluxPromptError::config(format!("File write error: {}", e)))
    }

    /// Loads a configuration from a file.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path).map_err(|e| {
            crate::error::FluxPromptError::config(format!("File read error: {}", e))
        })?;

        match path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => Self::from_json(&content),
            Some("yaml") | Some("yml") => Self::from_yaml(&content),
            _ => Err(crate::error::FluxPromptError::config(
                "Unsupported file format. Use .json, .yaml, or .yml",
            )),
        }
    }

    /// Creates a summary of the configuration for display.
    pub fn summary(&self) -> ConfigurationSummary {
        ConfigurationSummary {
            name: self.name.clone(),
            description: self.description.clone(),
            base_preset: self.base_preset.clone(),
            security_level: self.detection_config.effective_security_level(),
            response_strategy: self.detection_config.response_strategy.clone(),
            enabled_features_count: self.features.enabled_count(),
            total_features_count: self.features.total_count(),
            has_advanced_options: !self.advanced_options.category_thresholds.is_empty()
                || !self.advanced_options.threat_weights.is_empty()
                || self.advanced_options.time_based_rules.is_some(),
            validation_status: self.validation_status.is_valid,
            created_at: self.created_at,
            modified_at: self.modified_at,
            tags: self.tags.clone(),
        }
    }

    /// Updates the modification timestamp.
    pub fn touch(&mut self) {
        self.modified_at = SystemTime::now();
        self.validation_status = ValidationStatus::new(); // Reset validation
    }

    /// Clones the configuration with a new name and ID.
    pub fn clone_with_name(&self, name: String, description: Option<String>) -> Self {
        let mut cloned = self.clone();
        cloned.id = Uuid::new_v4();
        cloned.name = name;
        if let Some(desc) = description {
            cloned.description = desc;
        }
        cloned.created_at = SystemTime::now();
        cloned.modified_at = SystemTime::now();
        cloned.validation_status = ValidationStatus::new();
        cloned
    }
}

fn write_canonical_json(value: &serde_json::Value, output: &mut Vec<u8>) -> serde_json::Result<()> {
    match value {
        serde_json::Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        serde_json::Value::Object(values) => {
            output.push(b'{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|(key, _)| *key);
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                output.extend(serde_json::to_vec(key)?);
                output.push(b':');
                write_canonical_json(value, output)?;
            }
            output.push(b'}');
        }
        _ => output.extend(serde_json::to_vec(value)?),
    }

    Ok(())
}

/// Summary information about a configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurationSummary {
    /// Configuration name
    pub name: String,
    /// Configuration description
    pub description: String,
    /// Base preset if any
    pub base_preset: Option<Preset>,
    /// Current security level
    pub security_level: SecurityLevel,
    /// Current response strategy
    pub response_strategy: ResponseStrategy,
    /// Number of enabled features
    pub enabled_features_count: usize,
    /// Total number of available features
    pub total_features_count: usize,
    /// Whether advanced options are configured
    pub has_advanced_options: bool,
    /// Validation status
    pub validation_status: bool,
    /// Creation timestamp
    pub created_at: SystemTime,
    /// Last modification timestamp
    pub modified_at: SystemTime,
    /// Configuration tags
    pub tags: Vec<String>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            requests_per_hour: 1000,
            requests_per_day: 10000,
            burst_allowance: 10,
            enforcement_strategy: RateLimitStrategy::WarnAndAllow,
            custom_limits: HashMap::new(),
        }
    }
}

impl Default for ContextAwarenessConfig {
    fn default() -> Self {
        Self {
            consider_history: false,
            history_length: 10,
            track_user_patterns: false,
            trust_score_adjustment: 0.0,
            context_window_size: 3,
        }
    }
}

impl ValidationStatus {
    fn new() -> Self {
        Self {
            is_valid: false, // Default to invalid until validated
            validated_at: SystemTime::now(),
            errors: Vec::new(),
            warnings: Vec::new(),
            checksum: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_config_creation() {
        let config = CustomConfig::new(
            "Test Config".to_string(),
            "A test configuration".to_string(),
        );

        assert_eq!(config.name, "Test Config");
        assert_eq!(config.description, "A test configuration");
        assert_eq!(config.version, "1.0.0");
        assert!(config.enabled);
        assert!(!config.validation_status.is_valid); // Default to invalid until validated
    }

    #[test]
    fn test_custom_config_from_preset() {
        let config = CustomConfig::from_preset(
            Preset::ChatBot,
            "ChatBot Config".to_string(),
            "Configuration based on ChatBot preset".to_string(),
        );

        assert_eq!(config.base_preset, Some(Preset::ChatBot));
        assert_eq!(config.detection_config.security_level.level(), 5);
        assert_eq!(
            config.detection_config.response_strategy,
            ResponseStrategy::Sanitize
        );
        assert!(config.tags.contains(&"preset".to_string()));
        assert!(config.tags.contains(&"chatbot".to_string()));
    }

    #[test]
    fn test_config_validation() {
        let mut config = CustomConfig::new(
            "Valid Config".to_string(),
            "A valid configuration".to_string(),
        );

        // Should be valid by default
        assert!(config.validate().is_ok());
        assert!(config.validation_status.is_valid);
        assert!(config.validation_status.checksum.starts_with("fnv1a64:"));

        // Add invalid threshold
        config.advanced_options.category_thresholds.insert(
            "test_category".to_string(),
            1.5, // Invalid: > 1.0
        );

        assert!(config.validate().is_err());
        assert!(!config.validation_status.is_valid);
        assert!(!config.validation_status.errors.is_empty());
    }

    #[test]
    fn test_config_validation_rejects_non_finite_advanced_values() {
        for invalid_threshold in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let mut config = CustomConfig::new("Invalid".to_string(), "Test".to_string());
            config
                .advanced_options
                .category_thresholds
                .insert("category".to_string(), invalid_threshold);

            assert!(config.validate().is_err());
            assert!(!config.validation_status.is_valid);
        }

        for invalid_weight in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let mut config = CustomConfig::new("Invalid".to_string(), "Test".to_string());
            config
                .advanced_options
                .threat_weights
                .insert("threat".to_string(), invalid_weight);

            assert!(config.validate().is_err());
            assert!(!config.validation_status.is_valid);
        }
    }

    #[test]
    fn test_config_merge() {
        let mut config1 = CustomConfig::from_preset(
            Preset::Development,
            "Config1".to_string(),
            "First config".to_string(),
        );

        let mut config2 = CustomConfig::from_preset(
            Preset::Financial,
            "Config2".to_string(),
            "Second config".to_string(),
        );

        config2
            .advanced_options
            .category_thresholds
            .insert("test".to_string(), 0.8);

        let original_security_level = config1.detection_config.security_level.level();
        config1.merge_with(&config2);

        // Security level should have changed
        assert_ne!(
            config1.detection_config.security_level.level(),
            original_security_level
        );
        assert_eq!(config1.detection_config.security_level.level(), 9); // Financial preset level

        // Advanced options should be merged
        assert!(
            config1
                .advanced_options
                .category_thresholds
                .contains_key("test")
        );
    }

    #[test]
    fn test_config_serialization() {
        let config = CustomConfig::from_preset(
            Preset::Healthcare,
            "Healthcare Config".to_string(),
            "Healthcare-labeled starting configuration".to_string(),
        );

        // Test JSON serialization
        let json = config.to_json().unwrap();
        let deserialized = CustomConfig::from_json(&json).unwrap();
        assert_eq!(config.name, deserialized.name);
        assert_eq!(config.base_preset, deserialized.base_preset);

        // Test YAML serialization
        let yaml = config.to_yaml().unwrap();
        let deserialized = CustomConfig::from_yaml(&yaml).unwrap();
        assert_eq!(config.name, deserialized.name);
        assert_eq!(config.base_preset, deserialized.base_preset);
    }

    #[test]
    fn test_config_summary() {
        let config = CustomConfig::from_preset(
            Preset::Financial,
            "Financial Config".to_string(),
            "Financial-labeled starting configuration".to_string(),
        );

        let summary = config.summary();
        assert_eq!(summary.name, "Financial Config");
        assert_eq!(summary.base_preset, Some(Preset::Financial));
        assert_eq!(summary.security_level.level(), 9);
        assert_eq!(summary.response_strategy, ResponseStrategy::Block);
        assert!(summary.enabled_features_count > 0);
    }

    #[test]
    fn test_config_clone_with_name() {
        let original = CustomConfig::from_preset(
            Preset::Educational,
            "Original Config".to_string(),
            "Original description".to_string(),
        );

        let cloned = original.clone_with_name(
            "Cloned Config".to_string(),
            Some("Cloned description".to_string()),
        );

        assert_eq!(cloned.name, "Cloned Config");
        assert_eq!(cloned.description, "Cloned description");
        assert_ne!(cloned.id, original.id);
        assert_eq!(cloned.base_preset, original.base_preset);
    }

    #[test]
    fn test_advanced_options_defaults() {
        let options = AdvancedOptions::default();
        assert!(options.category_thresholds.is_empty());
        assert!(options.threat_weights.is_empty());
        assert!(options.language_settings.is_empty());
        assert!(options.time_based_rules.is_none());
        assert!(options.role_configurations.is_empty());
        assert!(options.locale_settings.is_empty());
        assert_eq!(options.rate_limiting.requests_per_minute, 60);
        assert!(!options.context_awareness.consider_history);
    }

    #[test]
    fn test_rate_limit_config() {
        let rate_limit = RateLimitConfig::default();
        assert_eq!(rate_limit.requests_per_minute, 60);
        assert_eq!(rate_limit.requests_per_hour, 1000);
        assert_eq!(rate_limit.requests_per_day, 10000);
        assert_eq!(rate_limit.burst_allowance, 10);
        assert!(matches!(
            rate_limit.enforcement_strategy,
            RateLimitStrategy::WarnAndAllow
        ));
    }

    #[test]
    fn test_context_awareness_config() {
        let context_config = ContextAwarenessConfig::default();
        assert!(!context_config.consider_history);
        assert_eq!(context_config.history_length, 10);
        assert!(!context_config.track_user_patterns);
        assert_eq!(context_config.trust_score_adjustment, 0.0);
        assert_eq!(context_config.context_window_size, 3);
    }

    #[test]
    fn test_validation_status() {
        let status = ValidationStatus::new();
        assert!(!status.is_valid); // Default to invalid
        assert!(status.errors.is_empty());
        assert!(status.warnings.is_empty());
        assert!(status.checksum.is_empty());
    }

    #[test]
    fn test_config_change_marker() {
        let config1 = CustomConfig::new("Test1".to_string(), "Description1".to_string());
        let config2 = CustomConfig::new("Test2".to_string(), "Description2".to_string());

        let marker1 = config1.calculate_change_marker().unwrap();
        let marker2 = config2.calculate_change_marker().unwrap();

        assert!(marker1.starts_with("fnv1a64:"));
        assert_ne!(marker1, marker2);

        let marker1_again = config1.calculate_change_marker().unwrap();
        assert_eq!(marker1, marker1_again);
    }

    #[test]
    fn test_config_change_marker_covers_runtime_configuration() {
        let config = CustomConfig::new("Test".to_string(), "Description".to_string());
        let marker = config.calculate_change_marker().unwrap();
        let mut changed = config.clone();
        changed.detection_config.response_strategy = ResponseStrategy::Warn;

        assert_ne!(marker, changed.calculate_change_marker().unwrap());
    }

    #[test]
    fn test_config_change_marker_canonicalizes_map_order() {
        let mut first = CustomConfig::new("Test".to_string(), "Description".to_string());
        let mut second = first.clone();
        first.metadata.insert("alpha".to_string(), "1".to_string());
        first.metadata.insert("beta".to_string(), "2".to_string());
        second.metadata.insert("beta".to_string(), "2".to_string());
        second.metadata.insert("alpha".to_string(), "1".to_string());

        assert_eq!(
            first.calculate_change_marker().unwrap(),
            second.calculate_change_marker().unwrap()
        );
    }

    #[test]
    fn test_config_touch() {
        let mut config = CustomConfig::new("Test".to_string(), "Description".to_string());
        let original_modified = config.modified_at;

        // Sleep briefly to ensure timestamp difference
        std::thread::sleep(Duration::from_millis(10));
        config.touch();

        assert!(config.modified_at > original_modified);
        assert!(!config.validation_status.is_valid); // Should reset validation
    }
}
