//! Configuration inheritance and composition example.
//!
//! This example demonstrates how to create hierarchical configurations
//! through inheritance, composition, and merging of multiple configurations.

use fluxprompt::{FluxPrompt, config_builder::CustomConfigBuilder};
use fluxprompt::custom_config::CustomConfig;
use fluxprompt::config::ResponseStrategy;
use fluxprompt::presets::Preset;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Configuration Inheritance and Composition Example");
    println!("=================================================");

    // Example 1: Base configuration that serves as a foundation
    println!("\n🏗️ Creating Base Configuration");
    println!("==============================");

    let base_config = CustomConfigBuilder::from_preset(Preset::ChatBot)
        .with_name("Organization Base Configuration")
        .with_description("Base configuration for all organization applications")
        .with_version("1.0.0")
        .with_tags(vec!["base", "organization-standard"])
        .with_metadata("organization", "Acme Corp")
        .with_metadata("compliance", "internal-standards")
        .with_security_level(5)?  // Balanced base level
        .with_response_strategy(ResponseStrategy::Warn)
        .add_custom_pattern(r"(?i)confidential\s+(?:information|data)")?
        .add_custom_pattern(r"(?i)internal\s+use\s+only")?
        .override_threshold("pattern_matching", 0.7)?
        .with_timeout(Duration::from_secs(5))
        .max_concurrent_analyses(100)
        .with_rate_limits(60, 1000, 8000)
        .with_metadata("created_by", "security_team")
        .build_validated()?;

    println!("✓ Created base configuration: {}", base_config.name);
    println!("  - Security Level: {}", base_config.detection_config.security_level.level());
    println!("  - Base Patterns: {}", base_config.detection_config.pattern_config.custom_patterns.len());

    // Example 2: Environment-specific configurations that inherit from base
    println!("\n🌱 Environment-Specific Configurations");
    println!("======================================");

    // Development environment (inherits base, adds dev-specific settings)
    let dev_config = CustomConfigBuilder::from_config(base_config.clone())
        .with_name("Development Environment Configuration")
        .with_description("Development configuration with relaxed security")
        .with_version("1.1.0-dev")
        .with_tag("development")
        .with_tag("environment")
        // Override security level for development
        .with_security_level(3)?  // More permissive
        .with_response_strategy(ResponseStrategy::Allow)
        // Add development-specific patterns
        .add_custom_pattern(r"(?i)debug\s+mode\s+enabled")?
        .add_custom_pattern(r"(?i)test\s+credentials")?
        // Relaxed thresholds for development
        .override_threshold("pattern_matching", 0.8)?
        .override_threshold("social_engineering_detection", 0.9)?
        // Performance optimizations for development
        .max_concurrent_analyses(200)
        .with_timeout(Duration::from_secs(2))
        .disable_feature("semantic_detection")?  // Speed up dev environment
        .with_metadata("environment", "development")
        .with_metadata("debug_enabled", "true")
        .build_validated()?;

    // Staging environment (inherits base, moderate security)
    let staging_config = CustomConfigBuilder::from_config(base_config.clone())
        .with_name("Staging Environment Configuration")
        .with_description("Staging configuration with production-like security")
        .with_version("1.1.0-staging")
        .with_tag("staging")
        .with_tag("environment")
        // Slightly higher security than base
        .with_security_level(6)?
        .with_response_strategy(ResponseStrategy::Sanitize)
        // Staging-specific patterns
        .add_custom_pattern(r"(?i)staging\s+(?:data|environment)")?
        .add_custom_pattern(r"(?i)test\s+(?:user|account)")?
        // Balanced performance for staging
        .with_timeout(Duration::from_secs(7))
        .max_concurrent_analyses(75)
        .with_metadata("environment", "staging")
        .build_validated()?;

    // Production environment (inherits base, maximum security)
    let prod_config = CustomConfigBuilder::from_config(base_config.clone())
        .with_name("Production Environment Configuration")
        .with_description("Production configuration with enhanced security")
        .with_version("1.1.0-prod")
        .with_tag("production")
        .with_tag("environment")
        // Maximum security for production
        .with_security_level(8)?
        .with_response_strategy(ResponseStrategy::Block)
        // Production-specific patterns
        .add_custom_pattern(r"(?i)production\s+(?:data|environment)")?
        .add_custom_pattern(r"(?i)live\s+(?:system|data)")?
        .add_custom_pattern(r"(?i)customer\s+(?:data|pii)")?
        // Strict thresholds for production
        .override_threshold("pattern_matching", 0.5)?
        .override_threshold("data_extraction", 0.4)?
        // Production performance settings
        .with_timeout(Duration::from_secs(10))
        .max_concurrent_analyses(50)
        .enable_feature("semantic_detection")?
        .with_rate_limits(30, 500, 3000)  // Strict rate limits
        .with_metadata("environment", "production")
        .with_metadata("compliance_required", "true")
        .build_validated()?;

    println!("✓ Created environment-specific configurations:");
    println!("  - Development: Security Level {}", dev_config.detection_config.security_level.level());
    println!("  - Staging: Security Level {}", staging_config.detection_config.security_level.level());
    println!("  - Production: Security Level {}", prod_config.detection_config.security_level.level());

    // Example 3: Feature-specific configuration overlays
    println!("\n🔧 Feature-Specific Configuration Overlays");
    println!("==========================================");

    // High-traffic feature overlay
    let high_traffic_overlay = CustomConfigBuilder::new()
        .with_name("High Traffic Overlay")
        .with_description("Performance optimizations for high-traffic features")
        .with_tag("overlay")
        .with_tag("performance")
        // Performance-focused settings
        .max_concurrent_analyses(300)
        .with_timeout(Duration::from_secs(1))
        .with_rate_limits(200, 5000, 50000)
        .disable_feature("semantic_detection")?  // Disable expensive features
        .disable_feature("heuristic_analysis")?
        .with_metadata("optimization", "high_traffic")
        .build_validated()?;

    // Security-critical feature overlay
    let security_overlay = CustomConfigBuilder::new()
        .with_name("Security-Critical Overlay")
        .with_description("Enhanced security for critical features")
        .with_tag("overlay")
        .with_tag("security")
        // Security-focused settings
        .with_security_level(10)?  // Maximum security
        .with_response_strategy(ResponseStrategy::Block)
        .override_threshold("all_categories", 0.3)?  // Very sensitive
        .enable_feature("semantic_detection")?
        .enable_feature("multi_modal_detection")?
        .with_rate_limits(10, 100, 500)  // Very strict limits
        .with_metadata("security_level", "critical")
        .build_validated()?;

    println!("✓ Created feature overlays:");
    println!("  - High Traffic: {} concurrent analyses", high_traffic_overlay.detection_config.resource_config.max_concurrent_analyses);
    println!("  - Security Critical: Security Level {}", security_overlay.detection_config.security_level.level());

    // Example 4: Configuration composition through merging
    println!("\n🎯 Configuration Composition");
    println!("============================");

    // Create a high-traffic production configuration by merging base + prod + high-traffic
    let mut high_traffic_prod = prod_config.clone();
    high_traffic_prod.merge_with(&high_traffic_overlay);
    high_traffic_prod.name = "High-Traffic Production Configuration".to_string();
    high_traffic_prod.description = "Production configuration optimized for high traffic".to_string();

    println!("✓ Created high-traffic production config:");
    println!("  - Base Security Level: {}", prod_config.detection_config.security_level.level());
    println!("  - After High-Traffic Overlay: {} concurrent analyses", 
        high_traffic_prod.detection_config.resource_config.max_concurrent_analyses);

    // Create a security-critical staging configuration
    let mut secure_staging = staging_config.clone();
    secure_staging.merge_with(&security_overlay);
    secure_staging.name = "Security-Critical Staging Configuration".to_string();
    secure_staging.description = "Staging configuration with enhanced security for critical features".to_string();

    println!("✓ Created security-critical staging config:");
    println!("  - Base Security Level: {}", staging_config.detection_config.security_level.level());
    println!("  - After Security Overlay: Security Level {}", 
        secure_staging.detection_config.security_level.level());

    // Example 5: Configuration templates for different domains
    println!("\n📋 Domain-Specific Templates");
    println!("============================");

    // E-commerce template (inherits base + specific patterns)
    let ecommerce_template = CustomConfigBuilder::from_config(base_config.clone())
        .with_name("E-commerce Application Template")
        .with_description("Template for e-commerce applications")
        .with_tag("template")
        .with_tag("ecommerce")
        // E-commerce specific patterns
        .add_custom_pattern(r"(?i)credit\s+card\s+(?:number|info)")?
        .add_custom_pattern(r"(?i)payment\s+(?:details|information)")?
        .add_custom_pattern(r"(?i)cvv\s+(?:code|number)")?
        .add_custom_pattern(r"(?i)billing\s+address")?
        // E-commerce specific thresholds
        .override_threshold("data_extraction", 0.4)?
        .set_category_sensitivity("payment_info", 9)?
        .with_metadata("domain", "ecommerce")
        .with_metadata("pci_compliance", "required")
        .build_validated()?;

    // SaaS platform template
    let saas_template = CustomConfigBuilder::from_config(base_config.clone())
        .with_name("SaaS Platform Template")
        .with_description("Template for SaaS applications")
        .with_tag("template")
        .with_tag("saas")
        // SaaS specific patterns
        .add_custom_pattern(r"(?i)api\s+(?:key|secret|token)")?
        .add_custom_pattern(r"(?i)tenant\s+(?:data|isolation)")?
        .add_custom_pattern(r"(?i)multi-?tenant\s+bypass")?
        // SaaS specific settings
        .override_threshold("code_injection", 0.5)?
        .set_category_sensitivity("api_security", 8)?
        .with_context_history(20)  // Track longer conversations
        .with_metadata("domain", "saas")
        .with_metadata("multi_tenant", "true")
        .build_validated()?;

    println!("✓ Created domain templates:");
    println!("  - E-commerce: {} payment-related patterns", 
        ecommerce_template.detection_config.pattern_config.custom_patterns
            .iter().filter(|p| p.contains("payment") || p.contains("credit") || p.contains("cvv")).count()
    );
    println!("  - SaaS: {} API security patterns",
        saas_template.detection_config.pattern_config.custom_patterns
            .iter().filter(|p| p.contains("api") || p.contains("tenant")).count()
    );

    // Example 6: Dynamic configuration selection based on inheritance hierarchy
    println!("\n🎪 Dynamic Configuration Selection");
    println!("==================================");

    // Function to select appropriate configuration based on context
    fn select_config(
        base: &CustomConfig,
        environment: &str,
        domain: &str,
        traffic_level: &str,
        security_level: &str,
    ) -> CustomConfig {
        let mut selected = base.clone();
        
        // Apply environment configuration
        match environment {
            "development" => {
                selected.detection_config.security_level = 
                    crate::config::SecurityLevel::new(3).unwrap();
                selected.detection_config.response_strategy = ResponseStrategy::Allow;
            },
            "staging" => {
                selected.detection_config.security_level = 
                    crate::config::SecurityLevel::new(6).unwrap();
                selected.detection_config.response_strategy = ResponseStrategy::Sanitize;
            },
            "production" => {
                selected.detection_config.security_level = 
                    crate::config::SecurityLevel::new(8).unwrap();
                selected.detection_config.response_strategy = ResponseStrategy::Block;
            },
            _ => {}
        }
        
        selected.name = format!("{} - {} - {} - {} - {}", 
            base.name, environment, domain, traffic_level, security_level);
        
        selected
    }

    // Test different configuration combinations
    let test_scenarios = vec![
        ("production", "ecommerce", "high", "critical"),
        ("staging", "saas", "medium", "normal"),
        ("development", "general", "low", "minimal"),
    ];

    for (env, domain, traffic, security) in test_scenarios {
        let config = select_config(&base_config, env, domain, traffic, security);
        println!("📊 Selected configuration: {}", config.name);
        println!("   Security Level: {}", config.detection_config.security_level.level());
        println!("   Response Strategy: {:?}", config.detection_config.response_strategy);
    }

    // Example 7: Export configuration hierarchy
    println!("\n💾 Exporting Configuration Hierarchy");
    println!("====================================");

    let configs_to_export = vec![
        (&base_config, "base_config"),
        (&dev_config, "dev_config"),
        (&staging_config, "staging_config"),
        (&prod_config, "prod_config"),
        (&ecommerce_template, "ecommerce_template"),
        (&saas_template, "saas_template"),
        (&high_traffic_prod, "high_traffic_prod"),
        (&secure_staging, "secure_staging"),
    ];

    for (config, filename) in configs_to_export {
        let file_path = format!("/tmp/{}.json", filename);
        config.save_to_file(&file_path)?;
        println!("✓ Exported {}", filename);
    }

    // Example 8: Configuration validation and compatibility
    println!("\n✅ Configuration Validation and Compatibility");
    println!("=============================================");

    let all_configs = vec![
        &base_config, &dev_config, &staging_config, &prod_config,
        &ecommerce_template, &saas_template, &high_traffic_prod, &secure_staging,
    ];

    for config in all_configs {
        let summary = config.summary();
        let status = if summary.validation_status { "✓ Valid" } else { "✗ Invalid" };
        
        println!("{}: {}", config.name, status);
        println!("  - Security Level: {}", summary.security_level.level());
        println!("  - Features: {}/{} enabled", summary.enabled_features_count, summary.total_features_count);
        println!("  - Tags: [{}]", summary.tags.join(", "));
        
        if summary.has_advanced_options {
            println!("  - Advanced Options: Configured");
        }
        
        // Check inheritance chain
        if let Some(preset) = &summary.base_preset {
            println!("  - Inherits from: {:?} preset", preset);
        }
    }

    println!("\n✅ Configuration inheritance and composition examples completed!");
    
    println!("\n📚 Key Concepts Demonstrated:");
    println!("=============================");
    println!("🏗️ Base Configuration: Foundation that other configs inherit from");
    println!("🌱 Environment Configs: Development, staging, production variations");
    println!("🔧 Feature Overlays: Reusable configuration snippets for specific needs");
    println!("🎯 Configuration Merging: Combining multiple configs with priority rules");
    println!("📋 Domain Templates: Pre-configured settings for specific application types");
    println!("🎪 Dynamic Selection: Runtime configuration choice based on context");
    println!("✅ Validation: Ensuring all inherited configurations remain valid");

    println!("\n🎯 Best Practices for Configuration Inheritance:");
    println!("================================================");
    println!("• Start with a solid base configuration that defines organization standards");
    println!("• Use environment-specific configurations for dev/staging/prod variations");
    println!("• Create feature overlays for reusable configuration snippets");
    println!("• Validate all configurations after inheritance and merging");
    println!("• Use clear naming conventions to show inheritance relationships");
    println!("• Document configuration dependencies and inheritance chains");
    println!("• Test configuration combinations before deploying to production");

    Ok(())
}