//! Advanced multi-layer configuration example.
//!
//! This example demonstrates how to create complex configurations with
//! multiple layers, role-based access, time-based rules, and context awareness.

use fluxprompt::config_builder::CustomConfigBuilder;
use fluxprompt::custom_config::{
    LanguageSettings, LocaleSettings, RoleConfig, TimeBasedRules, TimeConfig,
};
use fluxprompt::config::{ResponseStrategy, SecurityLevel};
use fluxprompt::features::Features;
use fluxprompt::presets::Preset;
use std::collections::HashMap;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Advanced Multi-Layer Configuration Example");
    println!("==========================================");

    // Example 1: Enterprise-grade configuration with role-based access
    println!("\n🏢 Enterprise Configuration with Role-Based Access");
    println!("==================================================");

    let mut enterprise_config = CustomConfigBuilder::from_preset(Preset::Financial)
        .with_name("Enterprise Multi-Role Configuration")
        .with_description("Comprehensive enterprise configuration with role-based security")
        .with_version("2.1.0")
        .with_tags(vec!["enterprise", "production", "multi-role", "financial"])
        .with_metadata("compliance", "SOX,PCI-DSS,GDPR")
        .with_metadata("environment", "production")
        .with_metadata("department", "security")
        .build_validated()?;

    // Configure role-based access
    let admin_role = RoleConfig {
        role_name: "administrator".to_string(),
        security_level: Some(SecurityLevel::new(10)?), // Maximum security for admins
        features: Some(Features::all_enabled()),
        custom_patterns: vec![
            r"(?i)admin\s+override\s+security".to_string(),
            r"(?i)escalate\s+privileges".to_string(),
        ],
        response_strategy: Some(ResponseStrategy::Block),
        permissions: {
            let mut perms = HashMap::new();
            perms.insert("bypass_rate_limits".to_string(), false);
            perms.insert("view_audit_logs".to_string(), true);
            perms.insert("modify_security_settings".to_string(), false);
            perms
        },
    };

    let user_role = RoleConfig {
        role_name: "standard_user".to_string(),
        security_level: Some(SecurityLevel::new(6)?), // Moderate security for users
        features: Some({
            let mut features = Features::balanced();
            features.semantic_detection = false; // Disable expensive features for users
            features.multi_modal_detection = false;
            features
        }),
        custom_patterns: vec![
            r"(?i)share\s+account\s+details".to_string(),
            r"(?i)password\s+reset\s+bypass".to_string(),
        ],
        response_strategy: Some(ResponseStrategy::Warn),
        permissions: {
            let mut perms = HashMap::new();
            perms.insert("bypass_rate_limits".to_string(), false);
            perms.insert("view_audit_logs".to_string(), false);
            perms.insert("access_financial_data".to_string(), true);
            perms
        },
    };

    let guest_role = RoleConfig {
        role_name: "guest".to_string(),
        security_level: Some(SecurityLevel::new(3)?), // Lower security for guests
        features: Some(Features::minimal()),
        custom_patterns: vec![
            r"(?i)create\s+account\s+bypass".to_string(),
            r"(?i)access\s+without\s+login".to_string(),
        ],
        response_strategy: Some(ResponseStrategy::Block),
        permissions: {
            let mut perms = HashMap::new();
            perms.insert("access_public_info".to_string(), true);
            perms.insert("create_account".to_string(), true);
            perms.insert("access_financial_data".to_string(), false);
            perms
        },
    };

    enterprise_config.advanced_options.role_configurations.insert("administrator".to_string(), admin_role);
    enterprise_config.advanced_options.role_configurations.insert("standard_user".to_string(), user_role);
    enterprise_config.advanced_options.role_configurations.insert("guest".to_string(), guest_role);

    println!("✓ Created enterprise configuration with {} roles", 
        enterprise_config.advanced_options.role_configurations.len()
    );

    // Example 2: Time-based security rules
    println!("\n⏰ Time-Based Security Configuration");
    println!("===================================");

    let time_based_config = CustomConfigBuilder::from_preset(Preset::CustomerService)
        .with_name("Time-Based Security Configuration")
        .with_description("Configuration with different security levels based on time of day")
        .build();

    let time_rules = TimeBasedRules {
        business_hours: TimeConfig {
            security_level_override: Some(SecurityLevel::new(5)?), // Balanced during business hours
            response_strategy_override: Some(ResponseStrategy::Warn),
            features_override: Some({
                let mut features = Features::balanced();
                features.semantic_detection = false; // Keep it fast during peak hours
                features
            }),
            threshold_adjustments: {
                let mut adjustments = HashMap::new();
                adjustments.insert("pattern_matching".to_string(), 0.8); // Slightly relaxed
                adjustments.insert("social_engineering_detection".to_string(), 0.7);
                adjustments
            },
        },
        after_hours: TimeConfig {
            security_level_override: Some(SecurityLevel::new(8)?), // Higher security after hours
            response_strategy_override: Some(ResponseStrategy::Block),
            features_override: Some(Features::comprehensive()),
            threshold_adjustments: {
                let mut adjustments = HashMap::new();
                adjustments.insert("pattern_matching".to_string(), 0.6); // Stricter
                adjustments.insert("encoding_detection".to_string(), 0.5);
                adjustments
            },
        },
        weekend: TimeConfig {
            security_level_override: Some(SecurityLevel::new(9)?), // Very high security on weekends
            response_strategy_override: Some(ResponseStrategy::Block),
            features_override: Some(Features::all_enabled()),
            threshold_adjustments: {
                let mut adjustments = HashMap::new();
                adjustments.insert("all_categories".to_string(), 0.5); // Maximum sensitivity
                adjustments
            },
        },
        holiday: TimeConfig {
            security_level_override: Some(SecurityLevel::new(10)?), // Maximum security on holidays
            response_strategy_override: Some(ResponseStrategy::Block),
            features_override: Some(Features::all_enabled()),
            threshold_adjustments: {
                let mut adjustments = HashMap::new();
                adjustments.insert("all_categories".to_string(), 0.4); // Ultra-sensitive
                adjustments
            },
        },
        timezone: "UTC".to_string(),
    };

    let mut time_based_config = time_based_config;
    time_based_config.advanced_options.time_based_rules = Some(time_rules);

    println!("✓ Created time-based configuration with 4 time periods");
    println!("  - Business Hours: Security Level {}", 5);
    println!("  - After Hours: Security Level {}", 8);
    println!("  - Weekend: Security Level {}", 9);
    println!("  - Holiday: Security Level {}", 10);

    // Example 3: Multi-language and locale-specific configuration
    println!("\n🌍 Multi-Language and Locale Configuration");
    println!("==========================================");

    let mut multilang_config = CustomConfigBuilder::from_preset(Preset::ChatBot)
        .with_name("Multi-Language Global Configuration")
        .with_description("Configuration supporting multiple languages and locales")
        .with_tags(vec!["global", "multilingual", "i18n"])
        .build();

    // English language settings
    let english_settings = LanguageSettings {
        custom_patterns: vec![
            r"(?i)ignore\s+previous\s+instructions".to_string(),
            r"(?i)act\s+as\s+if\s+you're".to_string(),
        ],
        threshold_adjustment: 0.0, // No adjustment for primary language
        normalize_unicode: true,
        character_set: Some("UTF-8".to_string()),
    };

    // Spanish language settings
    let spanish_settings = LanguageSettings {
        custom_patterns: vec![
            r"(?i)ignora\s+las\s+instrucciones\s+anteriores".to_string(),
            r"(?i)actúa\s+como\s+si\s+fueras".to_string(),
        ],
        threshold_adjustment: 0.1, // Slightly higher threshold for non-primary language
        normalize_unicode: true,
        character_set: Some("UTF-8".to_string()),
    };

    // French language settings
    let french_settings = LanguageSettings {
        custom_patterns: vec![
            r"(?i)ignore\s+les\s+instructions\s+précédentes".to_string(),
            r"(?i)agis\s+comme\s+si\s+tu\s+étais".to_string(),
        ],
        threshold_adjustment: 0.1,
        normalize_unicode: true,
        character_set: Some("UTF-8".to_string()),
    };

    multilang_config.advanced_options.language_settings.insert("en".to_string(), english_settings);
    multilang_config.advanced_options.language_settings.insert("es".to_string(), spanish_settings);
    multilang_config.advanced_options.language_settings.insert("fr".to_string(), french_settings);

    // Locale-specific settings
    let us_locale = LocaleSettings {
        locale: "en-US".to_string(),
        compliance_requirements: vec!["CCPA".to_string(), "HIPAA".to_string()],
        custom_patterns: vec![
            r"(?i)ssn\s*:?\s*\d{3}-?\d{2}-?\d{4}".to_string(), // US SSN pattern
        ],
        privacy_regulations: vec!["CCPA".to_string()],
        cultural_adjustments: {
            let mut adjustments = HashMap::new();
            adjustments.insert("formality_level".to_string(), 0.6);
            adjustments
        },
    };

    let eu_locale = LocaleSettings {
        locale: "en-EU".to_string(),
        compliance_requirements: vec!["GDPR".to_string()],
        custom_patterns: vec![
            r"(?i)personal\s+data\s+processing".to_string(),
            r"(?i)right\s+to\s+be\s+forgotten".to_string(),
        ],
        privacy_regulations: vec!["GDPR".to_string()],
        cultural_adjustments: {
            let mut adjustments = HashMap::new();
            adjustments.insert("privacy_sensitivity".to_string(), 0.9);
            adjustments
        },
    };

    multilang_config.advanced_options.locale_settings.insert("en-US".to_string(), us_locale);
    multilang_config.advanced_options.locale_settings.insert("en-EU".to_string(), eu_locale);

    println!("✓ Created multi-language configuration");
    println!("  - Languages: {} supported", multilang_config.advanced_options.language_settings.len());
    println!("  - Locales: {} configured", multilang_config.advanced_options.locale_settings.len());

    // Example 4: Context-aware configuration with conversation tracking
    println!("\n🧠 Context-Aware Configuration");
    println!("===============================");

    let context_config = CustomConfigBuilder::from_preset(Preset::Educational)
        .with_name("Context-Aware Educational Assistant")
        .with_description("Educational configuration with advanced context awareness")
        .with_context_history(15) // Track last 15 messages
        .configure_context_awareness(|ctx| {
            ctx.track_user_patterns = true;
            ctx.trust_score_adjustment = 0.2; // Adjust confidence based on user trust
            ctx.context_window_size = 5; // Consider 5-message windows for patterns
        })
        .build_validated()?;

    println!("✓ Created context-aware configuration");
    println!("  - History Length: {} messages", 
        context_config.advanced_options.context_awareness.history_length
    );
    println!("  - User Pattern Tracking: {}", 
        context_config.advanced_options.context_awareness.track_user_patterns
    );
    println!("  - Trust Score Adjustment: {}", 
        context_config.advanced_options.context_awareness.trust_score_adjustment
    );

    // Example 5: Advanced threat weight customization
    println!("\n⚖️ Advanced Threat Weight Configuration");
    println!("=======================================");

    let mut threat_weighted_config = CustomConfigBuilder::maximum_security()
        .with_name("Custom Threat Weight Configuration")
        .with_description("Configuration with fine-tuned threat weights")
        .build();

    // Customize threat weights based on business priorities
    let threat_weights = &mut threat_weighted_config.advanced_options.threat_weights;
    threat_weights.insert("InstructionOverride".to_string(), 2.0); // Very high priority
    threat_weights.insert("DataExtraction".to_string(), 1.8); // High priority
    threat_weights.insert("Jailbreak".to_string(), 1.5); // High priority
    threat_weights.insert("CodeInjection".to_string(), 1.3); // Medium-high priority
    threat_weights.insert("SocialEngineering".to_string(), 1.0); // Standard priority
    threat_weights.insert("RolePlaying".to_string(), 0.8); // Lower priority
    threat_weights.insert("EncodingBypass".to_string(), 0.6); // Lowest priority

    // Customize category thresholds
    let category_thresholds = &mut threat_weighted_config.advanced_options.category_thresholds;
    category_thresholds.insert("instruction_override".to_string(), 0.3); // Very sensitive
    category_thresholds.insert("data_extraction".to_string(), 0.4); // Very sensitive
    category_thresholds.insert("jailbreak".to_string(), 0.5); // Sensitive
    category_thresholds.insert("social_engineering".to_string(), 0.7); // Moderate
    category_thresholds.insert("role_playing".to_string(), 0.8); // Relaxed

    println!("✓ Created threat-weighted configuration");
    println!("  - Custom Threat Weights: {}", threat_weights.len());
    println!("  - Custom Category Thresholds: {}", category_thresholds.len());

    // Example 6: Export all configurations and display summaries
    println!("\n📄 Exporting Advanced Configurations");
    println!("====================================");

    enterprise_config.save_to_file("/tmp/enterprise_config.json")?;
    time_based_config.save_to_file("/tmp/time_based_config.yaml")?;
    multilang_config.save_to_file("/tmp/multilang_config.json")?;
    context_config.save_to_file("/tmp/context_config.yaml")?;
    threat_weighted_config.save_to_file("/tmp/threat_weighted_config.json")?;

    println!("✓ Exported all configurations to /tmp/");

    // Display comprehensive summaries
    println!("\n📋 Advanced Configuration Summaries");
    println!("===================================");

    let configs = vec![
        (&enterprise_config, "Enterprise"),
        (&time_based_config, "Time-Based"),
        (&multilang_config, "Multi-Language"),
        (&context_config, "Context-Aware"),
        (&threat_weighted_config, "Threat-Weighted"),
    ];

    for (config, config_type) in configs {
        println!("\n{} Configuration:", config_type);
        println!("  Name: {}", config.name);
        println!("  Security Level: {}", config.detection_config.security_level.level());
        println!("  Base Preset: {:?}", config.base_preset);
        println!("  Features: {}/{} enabled", 
            config.features.enabled_count(), 
            config.features.total_count()
        );
        println!("  Role Configs: {}", config.advanced_options.role_configurations.len());
        println!("  Language Settings: {}", config.advanced_options.language_settings.len());
        println!("  Locale Settings: {}", config.advanced_options.locale_settings.len());
        println!("  Time-Based Rules: {}", 
            if config.advanced_options.time_based_rules.is_some() { "Yes" } else { "No" }
        );
        println!("  Context Awareness: {}", 
            if config.advanced_options.context_awareness.consider_history { "Enabled" } else { "Disabled" }
        );
        println!("  Custom Thresholds: {}", config.advanced_options.category_thresholds.len());
        println!("  Threat Weights: {}", config.advanced_options.threat_weights.len());
        println!("  Tags: [{}]", config.tags.join(", "));
    }

    println!("\n✅ Advanced multi-layer configuration examples completed!");
    println!("\nKey Features Demonstrated:");
    println!("  🏢 Role-based access control with different security levels");
    println!("  ⏰ Time-based security rules for different periods");
    println!("  🌍 Multi-language and locale-specific configurations");
    println!("  🧠 Context-aware processing with conversation tracking");
    println!("  ⚖️ Fine-tuned threat weights and category thresholds");
    println!("  📄 Configuration export and import capabilities");

    Ok(())
}