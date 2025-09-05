//! Basic custom configuration example.
//!
//! This example demonstrates how to create a basic custom configuration
//! using the FluxPrompt custom configuration system.

use fluxprompt::config_builder::CustomConfigBuilder;
use fluxprompt::presets::Preset;
use fluxprompt::config::ResponseStrategy;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Basic Custom Configuration Example");
    println!("=================================");

    // Example 1: Building from scratch
    let basic_config = CustomConfigBuilder::new()
        .with_name("Basic Custom Configuration")
        .with_description("A simple custom configuration for demonstration")
        .with_security_level(6)?  // Enhanced security
        .with_response_strategy(ResponseStrategy::Sanitize)
        .enable_feature("pattern_matching")?
        .enable_feature("encoding_detection")?
        .disable_feature("semantic_detection")?  // Disable to avoid model dependencies
        .add_custom_pattern(r"(?i)bypass\s+security")?
        .add_custom_pattern(r"(?i)admin\s+mode")?
        .override_threshold("pattern_matching", 0.7)?
        .with_timeout(Duration::from_secs(8))
        .max_concurrent_analyses(150)
        .enable_metrics(true)
        .with_tag("basic")
        .with_tag("example")
        .with_metadata("created_by", "example")
        .with_metadata("purpose", "demonstration")
        .build_validated()?;

    println!("✓ Created basic configuration: {}", basic_config.name);
    println!("  - Security Level: {}", basic_config.detection_config.security_level.level());
    println!("  - Response Strategy: {:?}", basic_config.detection_config.response_strategy);
    println!("  - Enabled Features: {}/{}", 
        basic_config.features.enabled_count(), 
        basic_config.features.total_count()
    );
    println!("  - Custom Patterns: {}", basic_config.detection_config.pattern_config.custom_patterns.len());
    println!("  - Tags: {:?}", basic_config.tags);

    // Example 2: Building from a preset and customizing
    let preset_based_config = CustomConfigBuilder::from_preset(Preset::ChatBot)
        .with_name("Customized ChatBot Configuration")
        .with_description("ChatBot preset with custom modifications")
        .with_security_level(7)?  // Increase from default level 5
        .add_custom_pattern(r"(?i)tell\s+me\s+about\s+your\s+system")?
        .add_custom_pattern(r"(?i)what\s+are\s+your\s+instructions")?
        .override_threshold("social_engineering_detection", 0.6)?
        .set_category_sensitivity("role_playing", 8)?  // High sensitivity for role-playing
        .case_sensitive_patterns(false)
        .max_text_length(8000)
        .preserve_formatting(true)
        .with_rate_limits(100, 1500, 15000)  // Moderate rate limiting
        .build_validated()?;

    println!("\n✓ Created preset-based configuration: {}", preset_based_config.name);
    println!("  - Base Preset: {:?}", preset_based_config.base_preset);
    println!("  - Security Level: {} (upgraded from preset default)", 
        preset_based_config.detection_config.security_level.level()
    );
    println!("  - Rate Limiting: {}/min, {}/hour, {}/day",
        preset_based_config.advanced_options.rate_limiting.requests_per_minute,
        preset_based_config.advanced_options.rate_limiting.requests_per_hour,
        preset_based_config.advanced_options.rate_limiting.requests_per_day
    );

    // Example 3: Use case-specific configuration
    let use_case_config = CustomConfigBuilder::for_use_case("customer")
        .with_name("Customer Support Configuration")
        .add_custom_pattern(r"(?i)escalate\s+to\s+human")?
        .add_custom_pattern(r"(?i)speak\s+to\s+manager")?
        .add_pattern_allowlist("thank you for contacting support")
        .add_pattern_allowlist("how can I help you today")
        .with_response_template("block", "I apologize, but I cannot process this request. Please rephrase your question.")
        .with_response_template("warn", "Please note: {reason}. How else can I assist you?")
        .with_context_history(5)  // Remember last 5 interactions
        .build_validated()?;

    println!("\n✓ Created use case-specific configuration: {}", use_case_config.name);
    println!("  - Based on: {:?} preset", use_case_config.base_preset);
    println!("  - Context History: {} messages", 
        use_case_config.advanced_options.context_awareness.history_length
    );
    println!("  - Pattern Allowlist: {} patterns", 
        use_case_config.advanced_options.pattern_allowlists.len()
    );
    println!("  - Response Templates: {} defined", 
        use_case_config.advanced_options.response_templates.len()
    );

    // Example 4: Export configurations to files
    println!("\n📄 Exporting configurations to files...");
    
    basic_config.save_to_file("/tmp/basic_config.json")?;
    println!("  ✓ Saved basic_config.json");
    
    preset_based_config.save_to_file("/tmp/preset_based_config.yaml")?;
    println!("  ✓ Saved preset_based_config.yaml");
    
    use_case_config.save_to_file("/tmp/use_case_config.json")?;
    println!("  ✓ Saved use_case_config.json");

    // Example 5: Display configuration summaries
    println!("\n📋 Configuration Summaries:");
    println!("===========================");
    
    let configs = vec![&basic_config, &preset_based_config, &use_case_config];
    
    for config in configs {
        let summary = config.summary();
        println!("\n{}", summary.name);
        println!("  Description: {}", summary.description);
        println!("  Security Level: {}", summary.security_level.level());
        println!("  Response Strategy: {:?}", summary.response_strategy);
        println!("  Features: {}/{} enabled", summary.enabled_features_count, summary.total_features_count);
        println!("  Advanced Options: {}", if summary.has_advanced_options { "Yes" } else { "No" });
        println!("  Valid: {}", if summary.validation_status { "✓" } else { "✗" });
        println!("  Tags: {}", summary.tags.join(", "));
    }

    // Example 6: Demonstrate configuration merging
    println!("\n🔄 Configuration Merging Example:");
    println!("==================================");
    
    let mut base_config = basic_config.clone();
    let overlay_config = CustomConfigBuilder::new()
        .with_security_level(8)?
        .override_threshold("encoding_detection", 0.5)?
        .add_custom_pattern(r"(?i)override\s+settings")?
        .with_metadata("merge_source", "overlay")
        .build();

    println!("  Base config security level: {}", base_config.detection_config.security_level.level());
    
    base_config.merge_with(&overlay_config);
    
    println!("  After merge security level: {}", base_config.detection_config.security_level.level());
    println!("  New threshold count: {}", base_config.advanced_options.category_thresholds.len());
    println!("  New pattern count: {}", base_config.detection_config.pattern_config.custom_patterns.len());

    println!("\n✅ Basic custom configuration examples completed successfully!");
    println!("\nNext steps:");
    println!("  - Check the exported configuration files in /tmp/");
    println!("  - Try loading configurations from files");
    println!("  - Experiment with different presets and customizations");
    println!("  - Explore advanced configuration options in other examples");

    Ok(())
}