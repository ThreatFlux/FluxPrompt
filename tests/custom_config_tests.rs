//! Comprehensive tests for the custom configuration system.

use fluxprompt::{
    config::ResponseStrategy,
    custom_config::{AdvancedOptions, ContextAwarenessConfig, RateLimitConfig, RateLimitStrategy},
    CustomConfig, CustomConfigBuilder, Features, Preset,
};
use std::collections::HashMap;
use std::time::Duration;
use tempfile::NamedTempFile;

#[tokio::test]
async fn test_custom_config_creation() {
    let config = CustomConfig::new(
        "Test Configuration".to_string(),
        "A test configuration for unit testing".to_string(),
    );

    assert_eq!(config.name, "Test Configuration");
    assert_eq!(config.description, "A test configuration for unit testing");
    assert_eq!(config.version, "1.0.0");
    assert!(config.enabled);
    assert_eq!(config.base_preset, None);
    assert!(config.tags.is_empty());
    assert!(!config.validation_status.is_valid); // Should be invalid until validated
}

#[tokio::test]
async fn test_custom_config_from_preset() {
    let config = CustomConfig::from_preset(
        Preset::Financial,
        "Financial Config".to_string(),
        "Test financial configuration".to_string(),
    );

    assert_eq!(config.base_preset, Some(Preset::Financial));
    assert_eq!(config.detection_config.security_level.level(), 9); // Financial preset level
    assert_eq!(
        config.detection_config.response_strategy,
        ResponseStrategy::Block
    );
    assert!(config.tags.contains(&"preset".to_string()));
    assert!(config.tags.contains(&"financial".to_string()));
}

#[tokio::test]
async fn test_custom_config_validation() {
    let mut config = CustomConfig::new(
        "Valid Config".to_string(),
        "A valid configuration".to_string(),
    );

    // Should be valid by default structure
    assert!(config.validate().is_ok());
    assert!(config.validation_status.is_valid);

    // Add invalid threshold
    config.advanced_options.category_thresholds.insert(
        "invalid_category".to_string(),
        1.5, // Invalid: > 1.0
    );

    assert!(config.validate().is_err());
    assert!(!config.validation_status.is_valid);
    assert!(!config.validation_status.errors.is_empty());
}

#[tokio::test]
async fn test_custom_config_merging() {
    let mut base_config = CustomConfig::from_preset(
        Preset::ChatBot,
        "Base Config".to_string(),
        "Base configuration".to_string(),
    );

    let overlay_config = CustomConfig::from_preset(
        Preset::Financial,
        "Overlay Config".to_string(),
        "Overlay configuration".to_string(),
    );

    let original_level = base_config.detection_config.security_level.level();
    base_config.merge_with(&overlay_config);

    // Security level should have changed to Financial preset level
    assert_ne!(
        base_config.detection_config.security_level.level(),
        original_level
    );
    assert_eq!(base_config.detection_config.security_level.level(), 9);
}

#[tokio::test]
async fn test_custom_config_serialization() -> Result<(), Box<dyn std::error::Error>> {
    let config = CustomConfig::from_preset(
        Preset::Healthcare,
        "Healthcare Config".to_string(),
        "HIPAA compliant configuration".to_string(),
    );

    // Test JSON serialization
    let json_str = config.to_json()?;
    let deserialized_json = CustomConfig::from_json(&json_str)?;
    assert_eq!(config.name, deserialized_json.name);
    assert_eq!(config.base_preset, deserialized_json.base_preset);

    // Test YAML serialization
    let yaml_str = config.to_yaml()?;
    let deserialized_yaml = CustomConfig::from_yaml(&yaml_str)?;
    assert_eq!(config.name, deserialized_yaml.name);
    assert_eq!(config.base_preset, deserialized_yaml.base_preset);

    Ok(())
}

#[tokio::test]
async fn test_custom_config_file_operations() -> Result<(), Box<dyn std::error::Error>> {
    let config = CustomConfig::from_preset(
        Preset::Educational,
        "File Test Config".to_string(),
        "Configuration for file operations testing".to_string(),
    );

    // Test JSON file operations
    let json_file = NamedTempFile::new()?.into_temp_path();
    config.save_to_file(&json_file)?;
    let loaded_json = CustomConfig::load_from_file(&json_file)?;
    assert_eq!(config.name, loaded_json.name);

    // Test YAML file operations
    let yaml_file = NamedTempFile::new()?
        .into_temp_path()
        .with_extension("yaml");
    config.save_to_file(&yaml_file)?;
    let loaded_yaml = CustomConfig::load_from_file(&yaml_file)?;
    assert_eq!(config.name, loaded_yaml.name);

    Ok(())
}

#[tokio::test]
async fn test_custom_config_summary() {
    let config = CustomConfig::from_preset(
        Preset::Development,
        "Dev Config".to_string(),
        "Development configuration".to_string(),
    );

    let summary = config.summary();
    assert_eq!(summary.name, "Dev Config");
    assert_eq!(summary.base_preset, Some(Preset::Development));
    assert_eq!(summary.security_level.level(), 2); // Development preset level
    assert!(summary.enabled_features_count > 0);
}

#[tokio::test]
async fn test_custom_config_clone_with_name() {
    let original = CustomConfig::from_preset(
        Preset::ChatBot,
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

#[tokio::test]
async fn test_features_creation_and_manipulation() {
    let mut features = Features::default(); // Should be balanced
    assert!(features.pattern_matching);
    assert!(features.heuristic_analysis);
    assert!(!features.semantic_detection); // Disabled by default

    // Test feature enable/disable
    assert!(features.enable_feature("semantic_detection").is_ok());
    assert!(features.is_feature_enabled("semantic_detection"));

    assert!(features.disable_feature("heuristic_analysis").is_ok());
    assert!(!features.is_feature_enabled("heuristic_analysis"));

    // Test invalid feature name
    assert!(features.enable_feature("invalid_feature").is_err());
}

#[tokio::test]
async fn test_features_presets() {
    let minimal = Features::minimal();
    assert!(minimal.pattern_matching);
    assert!(!minimal.semantic_detection);
    assert!(minimal.enabled_count() < Features::all_enabled().enabled_count());

    let comprehensive = Features::comprehensive();
    assert_eq!(comprehensive.enabled_count(), comprehensive.total_count());

    let performance = Features::performance_optimized();
    assert!(performance.pattern_matching);
    assert!(!performance.heuristic_analysis); // Disabled for performance
}

#[tokio::test]
async fn test_features_map_conversion() {
    let features = Features::balanced();
    let map = features.to_map();

    assert!(map.contains_key("pattern_matching"));
    assert!(map.contains_key("semantic_detection"));

    let reconstructed = Features::from_map(&map);
    assert_eq!(features, reconstructed);
}

#[tokio::test]
async fn test_preset_configurations() {
    let presets = [
        Preset::ChatBot,
        Preset::CodeAssistant,
        Preset::CustomerService,
        Preset::Educational,
        Preset::Financial,
        Preset::Healthcare,
        Preset::Development,
    ];

    for preset in presets {
        let config = preset.to_detection_config();
        assert!(
            config.validate().is_ok(),
            "Preset {:?} should produce valid config",
            preset
        );

        // Check that security levels are reasonable
        let level = config.security_level.level();
        assert!(
            level <= 10,
            "Security level should not exceed 10 for preset {:?}",
            preset
        );

        // Check that features are consistent
        let features = preset.features();
        assert!(
            features.enabled_count() > 0,
            "Preset {:?} should have at least some features enabled",
            preset
        );
    }
}

#[tokio::test]
async fn test_preset_recommendations() {
    let chat_recs = Preset::recommend_for_use_case("chatbot", "medium", "high");
    assert!(chat_recs.contains(&Preset::ChatBot));

    let financial_recs = Preset::recommend_for_use_case("banking", "high", "low");
    assert!(financial_recs.contains(&Preset::Financial));

    let dev_recs = Preset::recommend_for_use_case("development", "low", "high");
    assert!(dev_recs.contains(&Preset::Development));

    // Test fallback
    let generic_recs = Preset::recommend_for_use_case("unknown", "medium", "medium");
    assert!(!generic_recs.is_empty());
}

#[tokio::test]
async fn test_custom_config_builder_basic() -> Result<(), Box<dyn std::error::Error>> {
    let config = CustomConfigBuilder::new()
        .with_name("Builder Test Config")
        .with_description("Configuration created with builder")
        .with_security_level(7)?
        .with_response_strategy(ResponseStrategy::Sanitize)
        .enable_feature("semantic_detection")?
        .add_custom_pattern("test_pattern")?
        .build_validated()?;

    assert_eq!(config.name, "Builder Test Config");
    assert_eq!(config.detection_config.security_level.level(), 7);
    assert_eq!(
        config.detection_config.response_strategy,
        ResponseStrategy::Sanitize
    );
    assert!(config.features.semantic_detection);
    assert!(config
        .detection_config
        .pattern_config
        .custom_patterns
        .contains(&"test_pattern".to_string()));

    Ok(())
}

#[tokio::test]
async fn test_custom_config_builder_from_preset() -> Result<(), Box<dyn std::error::Error>> {
    let config = CustomConfigBuilder::from_preset(Preset::Healthcare)
        .with_name("Custom Healthcare Config")
        .override_threshold("data_extraction", 0.3)?
        .add_custom_pattern("phi_pattern")?
        .build_validated()?;

    assert_eq!(config.name, "Custom Healthcare Config");
    assert_eq!(config.base_preset, Some(Preset::Healthcare));
    assert!(config
        .advanced_options
        .category_thresholds
        .contains_key("data_extraction"));
    assert!(config
        .detection_config
        .pattern_config
        .custom_patterns
        .iter()
        .any(|p| p.contains("phi_pattern")));

    Ok(())
}

#[tokio::test]
async fn test_custom_config_builder_features() -> Result<(), Box<dyn std::error::Error>> {
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

    Ok(())
}

#[tokio::test]
async fn test_custom_config_builder_thresholds() -> Result<(), Box<dyn std::error::Error>> {
    let config = CustomConfigBuilder::new()
        .override_threshold("pattern_matching", 0.8)?
        .override_threat_weight("Jailbreak", 2.0)?
        .set_category_sensitivity("social_engineering", 7)?
        .build();

    assert_eq!(
        config
            .advanced_options
            .category_thresholds
            .get("pattern_matching"),
        Some(&0.8)
    );
    assert_eq!(
        config.advanced_options.threat_weights.get("Jailbreak"),
        Some(&2.0)
    );
    assert!(config
        .advanced_options
        .category_thresholds
        .contains_key("social_engineering"));

    Ok(())
}

#[tokio::test]
async fn test_custom_config_builder_validation() {
    // Valid configuration
    let valid_result = CustomConfigBuilder::new()
        .with_security_level(5)
        .unwrap()
        .override_threshold("test", 0.7)
        .unwrap()
        .build_validated();
    assert!(valid_result.is_ok());

    // Invalid threshold
    let invalid_result = CustomConfigBuilder::new().override_threshold("test", 1.5);
    assert!(invalid_result.is_err());

    // Invalid security level
    let invalid_level = CustomConfigBuilder::new().with_security_level(15);
    assert!(invalid_level.is_err());
}

#[tokio::test]
async fn test_custom_config_builder_patterns() {
    let config = CustomConfigBuilder::new()
        .add_custom_pattern("pattern1")
        .add_custom_patterns(vec!["pattern2", "pattern3"])
        .add_pattern_allowlist("allowed_pattern")
        .add_pattern_denylist("denied_pattern")
        .case_sensitive_patterns(true)
        .build();

    assert_eq!(
        config.detection_config.pattern_config.custom_patterns.len(),
        3
    );
    assert!(config
        .advanced_options
        .pattern_allowlists
        .contains(&"allowed_pattern".to_string()));
    assert!(config
        .advanced_options
        .pattern_denylists
        .contains(&"denied_pattern".to_string()));
    assert!(config.detection_config.pattern_config.case_sensitive);
}

#[tokio::test]
async fn test_custom_config_builder_resource_settings() {
    let config = CustomConfigBuilder::new()
        .with_timeout(Duration::from_secs(30))
        .max_concurrent_analyses(100)
        .max_memory_mb(512)
        .pattern_cache_size(1000)
        .build();

    assert_eq!(
        config.detection_config.resource_config.analysis_timeout,
        Duration::from_secs(30)
    );
    assert_eq!(
        config
            .detection_config
            .resource_config
            .max_concurrent_analyses,
        100
    );
    assert_eq!(config.detection_config.resource_config.max_memory_mb, 512);
    assert_eq!(
        config.detection_config.resource_config.pattern_cache_size,
        1000
    );
}

#[tokio::test]
async fn test_custom_config_builder_rate_limiting() {
    let config = CustomConfigBuilder::new()
        .with_rate_limits(60, 1000, 10000)
        .configure_rate_limiting(|rate_config| {
            rate_config.enforcement_strategy = RateLimitStrategy::Drop;
            rate_config.burst_allowance = 20;
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
    assert!(matches!(
        config.advanced_options.rate_limiting.enforcement_strategy,
        RateLimitStrategy::Drop
    ));
    assert_eq!(config.advanced_options.rate_limiting.burst_allowance, 20);
}

#[tokio::test]
async fn test_custom_config_builder_context_awareness() {
    let config = CustomConfigBuilder::new()
        .with_context_history(15)
        .configure_context_awareness(|ctx| {
            ctx.track_user_patterns = true;
            ctx.trust_score_adjustment = 0.2;
        })
        .build();

    assert!(config.advanced_options.context_awareness.consider_history);
    assert_eq!(config.advanced_options.context_awareness.history_length, 15);
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
        0.2
    );
}

#[tokio::test]
async fn test_custom_config_builder_semantic_analysis() -> Result<(), Box<dyn std::error::Error>> {
    let config = CustomConfigBuilder::new()
        .enable_semantic_analysis(Some("test-model".to_string()))
        .semantic_threshold(0.75)?
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
        0.75
    );
    assert_eq!(
        config.detection_config.semantic_config.max_context_length,
        1024
    );

    Ok(())
}

#[tokio::test]
async fn test_custom_config_builder_preprocessing() {
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

#[tokio::test]
async fn test_custom_config_builder_use_case_builders() {
    let chatbot_config = CustomConfigBuilder::for_use_case("chatbot").build();
    assert_eq!(chatbot_config.base_preset, Some(Preset::ChatBot));

    let financial_config = CustomConfigBuilder::for_use_case("financial").build();
    assert_eq!(financial_config.base_preset, Some(Preset::Financial));

    let dev_config = CustomConfigBuilder::for_use_case("development").build();
    assert_eq!(dev_config.base_preset, Some(Preset::Development));
}

#[tokio::test]
async fn test_custom_config_builder_specialized_builders() {
    let high_perf = CustomConfigBuilder::high_performance().build();
    assert!(high_perf.name.contains("Performance"));
    assert!(!high_perf.features.semantic_detection);
    assert_eq!(
        high_perf.detection_config.resource_config.analysis_timeout,
        Duration::from_secs(1)
    );

    let max_security = CustomConfigBuilder::maximum_security().build();
    assert!(max_security.name.contains("Security"));
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

#[tokio::test]
async fn test_custom_config_builder_metadata_and_tags() {
    let config = CustomConfigBuilder::new()
        .with_metadata("environment", "test")
        .with_metadata("version", "1.0")
        .with_tag("testing")
        .with_tags(vec!["unit-test", "automated"])
        .build();

    assert_eq!(config.metadata.get("environment").unwrap(), "test");
    assert_eq!(config.metadata.get("version").unwrap(), "1.0");
    assert!(config.tags.contains(&"testing".to_string()));
    assert!(config.tags.contains(&"unit-test".to_string()));
    assert!(config.tags.contains(&"automated".to_string()));
}

#[tokio::test]
async fn test_custom_config_builder_response_templates() {
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

#[tokio::test]
async fn test_advanced_options_defaults() {
    let options = AdvancedOptions::default();
    assert!(options.category_thresholds.is_empty());
    assert!(options.threat_weights.is_empty());
    assert!(options.time_based_rules.is_none());
    assert_eq!(options.rate_limiting.requests_per_minute, 60);
    assert!(!options.context_awareness.consider_history);
}

#[tokio::test]
async fn test_rate_limit_config() {
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

#[tokio::test]
async fn test_context_awareness_config() {
    let context_config = ContextAwarenessConfig::default();
    assert!(!context_config.consider_history);
    assert_eq!(context_config.history_length, 10);
    assert!(!context_config.track_user_patterns);
    assert_eq!(context_config.trust_score_adjustment, 0.0);
    assert_eq!(context_config.context_window_size, 3);
}

#[tokio::test]
async fn test_configuration_checksum() {
    let config1 = CustomConfig::new("Test1".to_string(), "Description1".to_string());
    let config2 = CustomConfig::new("Test2".to_string(), "Description2".to_string());

    let checksum1 = config1.calculate_checksum();
    let checksum2 = config2.calculate_checksum();

    // Different configs should have different checksums (with high probability)
    assert_ne!(checksum1, checksum2);

    // Same config should have same checksum
    let checksum1_again = config1.calculate_checksum();
    assert_eq!(checksum1, checksum1_again);
}

#[tokio::test]
async fn test_configuration_touch() {
    let mut config = CustomConfig::new("Test".to_string(), "Description".to_string());
    let original_modified = config.modified_at;

    // Sleep briefly to ensure timestamp difference
    tokio::time::sleep(Duration::from_millis(10)).await;
    config.touch();

    assert!(config.modified_at > original_modified);
    assert!(!config.validation_status.is_valid); // Should reset validation
}

#[tokio::test]
async fn test_invalid_configurations() {
    // Test invalid thresholds
    let result = CustomConfigBuilder::new().override_threshold("test", 1.5);
    assert!(result.is_err());

    let result = CustomConfigBuilder::new().override_threshold("test", -0.1);
    assert!(result.is_err());

    // Test invalid weights
    let result = CustomConfigBuilder::new().override_threat_weight("test", -1.0);
    assert!(result.is_err());

    // Test invalid sensitivity
    let result = CustomConfigBuilder::new().set_category_sensitivity("test", 15);
    assert!(result.is_err());

    // Test invalid semantic threshold
    let result = CustomConfigBuilder::new().semantic_threshold(0.0);
    assert!(result.is_err());

    let result = CustomConfigBuilder::new().semantic_threshold(1.5);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_features_edge_cases() {
    let mut features = Features::all_disabled();
    assert_eq!(features.enabled_count(), 0);

    let all_enabled = Features::all_enabled();
    assert_eq!(all_enabled.enabled_count(), all_enabled.total_count());

    // Test feature list consistency
    let enabled_list = all_enabled.enabled_features();
    let disabled_list = all_enabled.disabled_features();
    assert_eq!(enabled_list.len(), all_enabled.total_count());
    assert_eq!(disabled_list.len(), 0);

    // Test description
    let desc = all_enabled.description();
    assert!(desc.contains("All detection features enabled"));
}

// Integration tests with the main FluxPrompt API would go here
// but require the actual detection/mitigation engines to be implemented
