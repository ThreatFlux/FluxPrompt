//! Domain-specific configuration examples.
//!
//! This example demonstrates how to create configurations optimized for
//! specific domains such as healthcare, finance, education, and development.

use fluxprompt::config_builder::CustomConfigBuilder;
use fluxprompt::custom_config::{LocaleSettings, RateLimitStrategy, RoleConfig};
use fluxprompt::config::{ResponseStrategy, SecurityLevel};
use fluxprompt::features::{Features, FeaturesBuilder};
use fluxprompt::presets::Preset;
use std::collections::HashMap;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Domain-Specific Configuration Examples");
    println!("======================================");

    // Example 1: Healthcare/Medical Domain Configuration
    println!("\n🏥 Healthcare Domain Configuration");
    println!("=================================");

    let healthcare_config = CustomConfigBuilder::from_preset(Preset::Healthcare)
        .with_name("HIPAA-Compliant Medical Assistant")
        .with_description("Healthcare configuration with HIPAA compliance and PII protection")
        .with_version("3.0.0")
        .with_tags(vec!["healthcare", "hipaa", "pii-protection", "medical"])
        .with_metadata("compliance_framework", "HIPAA,HITECH,FDA")
        .with_metadata("certification", "SOC2-Type-II")
        .with_metadata("audit_requirements", "quarterly")
        // Enhanced security for medical data
        .with_security_level(9)?  // Near-maximum security
        .with_response_strategy(ResponseStrategy::Block) // Zero tolerance for violations
        // Configure features for medical context
        .configure_features(|f| {
            f.with_pattern_matching(true)
                .with_semantic_detection(true) // Important for PII detection
                .with_heuristic_analysis(true)
                .with_encoding_detection(true)
                .with_social_engineering_detection(true)
                .with_context_hijacking_detection(true)
                .with_role_play_detection(true)
                .with_data_extraction_detection(true) // Critical for healthcare
                .with_multi_modal_detection(true) // Scan all content types
                .with_custom_patterns(true)
                .with_jailbreak_detection(true)
                .with_instruction_override_detection(true)
                .with_code_injection_detection(true)
                .with_system_prompt_leak_detection(true)
        })
        // Medical-specific patterns
        .add_custom_pattern(r"(?i)patient\s+(?:id|identifier|number)\s*:?\s*\d+")?
        .add_custom_pattern(r"(?i)medical\s+record\s+(?:number|id)\s*:?\s*\d+")?
        .add_custom_pattern(r"(?i)ssn\s*:?\s*\d{3}-?\d{2}-?\d{4}")?  // Social Security Numbers
        .add_custom_pattern(r"(?i)dob\s*:?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}")?  // Date of birth
        .add_custom_pattern(r"(?i)insurance\s+(?:policy|id|number)\s*:?\s*\d+")?
        .add_custom_pattern(r"(?i)diagnosis\s+code\s*:?\s*[A-Z]\d{2}\.\d+")?  // ICD-10 codes
        .add_custom_pattern(r"(?i)prescription\s+number\s*:?\s*\d+")?
        // PHI-related patterns
        .add_custom_pattern(r"(?i)bypass\s+hipaa")?
        .add_custom_pattern(r"(?i)ignore\s+privacy\s+rules")?
        .add_custom_pattern(r"(?i)share\s+patient\s+data")?
        // Very strict thresholds for healthcare
        .override_threshold("data_extraction", 0.3)?  // Very sensitive to data extraction
        .override_threshold("social_engineering", 0.4)?
        .override_threshold("pii_detection", 0.2)?  // Maximum sensitivity for PII
        // Enhanced resource allocation for thorough analysis
        .with_timeout(Duration::from_secs(20))  // Allow time for comprehensive analysis
        .max_concurrent_analyses(50)  // Conservative concurrency for thorough processing
        .max_memory_mb(1024)  // Adequate memory for ML models
        .pattern_cache_size(2000)
        // Strict rate limiting
        .with_rate_limits(30, 500, 2000)  // Conservative limits
        .configure_rate_limiting(|rate_config| {
            rate_config.enforcement_strategy = RateLimitStrategy::StricterSecurity;
            rate_config.burst_allowance = 5; // Very limited burst
        })
        // Enable semantic analysis with medical model
        .enable_semantic_analysis(Some("clinical-bert".to_string()))
        .semantic_threshold(0.7)?  // Moderate threshold for medical context
        .semantic_context_length(1024)
        // Healthcare-specific response templates
        .with_response_template("phi_detected", "This request appears to involve protected health information. I cannot process requests that may violate HIPAA regulations.")
        .with_response_template("medical_data", "I cannot provide access to or process medical records, patient data, or other protected health information.")
        .with_response_template("compliance_violation", "This request may violate healthcare compliance requirements. Please consult with your compliance officer.")
        // Context awareness for medical conversations
        .with_context_history(10)  // Remember medical context
        .configure_context_awareness(|ctx| {
            ctx.track_user_patterns = true;
            ctx.trust_score_adjustment = -0.2; // Bias towards more security in healthcare
        })
        // Preprocessing for medical text
        .max_text_length(10000)  // Allow for longer medical documents
        .preserve_formatting(true)  // Important for medical data structure
        .normalize_unicode(true)
        .decode_encodings(true)
        .build_validated()?;

    println!("✓ Created HIPAA-compliant healthcare configuration");
    println!("  - Security Level: {} (near-maximum)", healthcare_config.detection_config.security_level.level());
    println!("  - Medical Patterns: {} custom patterns", healthcare_config.detection_config.pattern_config.custom_patterns.len());
    println!("  - Semantic Analysis: {} (clinical model)", healthcare_config.detection_config.semantic_config.enabled);
    println!("  - Rate Limiting: {}/min (conservative)", healthcare_config.advanced_options.rate_limiting.requests_per_minute);

    // Example 2: Financial Services Domain Configuration
    println!("\n💰 Financial Services Domain Configuration");
    println!("==========================================");

    let financial_config = CustomConfigBuilder::from_preset(Preset::Financial)
        .with_name("Banking & Financial Services Assistant")
        .with_description("High-security configuration for banking and financial services")
        .with_tags(vec!["finance", "banking", "pci-dss", "sox-compliance"])
        .with_metadata("compliance", "PCI-DSS,SOX,FFIEC,GLBA")
        .with_metadata("risk_level", "high")
        .with_metadata("data_classification", "confidential")
        // Maximum security for financial data
        .with_security_level(10)?  // Maximum security
        .with_response_strategy(ResponseStrategy::Block)
        // All features enabled for comprehensive protection
        .with_features(Features::all_enabled())
        // Financial-specific patterns
        .add_custom_pattern(r"(?i)account\s+number\s*:?\s*\d{8,17}")?  // Bank account numbers
        .add_custom_pattern(r"(?i)routing\s+number\s*:?\s*\d{9}")?  // US routing numbers
        .add_custom_pattern(r"(?i)credit\s+card\s*(?:number)?\s*:?\s*(?:\d{4}[-\s]?){3,4}\d+")?  // Credit card numbers
        .add_custom_pattern(r"(?i)cvv\s*:?\s*\d{3,4}")?  // CVV codes
        .add_custom_pattern(r"(?i)pin\s*(?:number)?\s*:?\s*\d{4,6}")?  // PIN numbers
        .add_custom_pattern(r"(?i)swift\s+code\s*:?\s*[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?")?  // SWIFT codes
        .add_custom_pattern(r"(?i)iban\s*:?\s*[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}")?  // IBAN
        .add_custom_pattern(r"(?i)tax\s+id\s*:?\s*\d{2}-?\d{7}")?  // Tax ID numbers
        // Financial fraud patterns
        .add_custom_pattern(r"(?i)transfer\s+funds?\s+to\s+account")?
        .add_custom_pattern(r"(?i)bypass\s+(?:audit|compliance|regulation)")?
        .add_custom_pattern(r"(?i)override\s+transaction\s+limit")?
        .add_custom_pattern(r"(?i)fake\s+(?:transaction|transfer|payment)")?
        // Ultra-strict thresholds
        .override_threshold("data_extraction", 0.2)?  // Maximum sensitivity
        .override_threshold("instruction_override", 0.25)?
        .override_threshold("jailbreak", 0.3)?
        .override_threshold("social_engineering", 0.35)?
        .set_category_sensitivity("financial_fraud", 10)?  // Maximum sensitivity
        // Conservative resource settings for thorough analysis
        .with_timeout(Duration::from_secs(30))  // Allow comprehensive analysis
        .max_concurrent_analyses(25)  // Very conservative for security
        .max_memory_mb(2048)  // Maximum resources for ML models
        .pattern_cache_size(3000)
        // Very strict rate limiting
        .with_rate_limits(20, 300, 1000)  // Very conservative
        .configure_rate_limiting(|rate_config| {
            rate_config.enforcement_strategy = RateLimitStrategy::StricterSecurity;
            rate_config.burst_allowance = 3; // Minimal burst allowance
        })
        // Enable all semantic capabilities
        .enable_semantic_analysis(Some("finbert".to_string()))
        .semantic_threshold(0.6)?  // Lower threshold for higher sensitivity
        .semantic_context_length(2048)
        // Financial-specific response templates
        .with_response_template("financial_data", "I cannot process requests involving financial account information, transaction details, or payment data.")
        .with_response_template("fraud_attempt", "This request appears to be attempting financial fraud or unauthorized access. All activities are logged and monitored.")
        .with_response_template("compliance", "This request may violate financial regulations and compliance requirements.")
        // Enhanced context tracking for financial conversations
        .with_context_history(20)  // Extended history for financial context
        .configure_context_awareness(|ctx| {
            ctx.track_user_patterns = true;
            ctx.trust_score_adjustment = -0.3; // Strong bias towards security
        })
        .build_validated()?;

    println!("✓ Created financial services configuration");
    println!("  - Security Level: {} (maximum)", financial_config.detection_config.security_level.level());
    println!("  - Financial Patterns: {} custom patterns", financial_config.detection_config.pattern_config.custom_patterns.len());
    println!("  - All Features: {}/{} enabled", financial_config.features.enabled_count(), financial_config.features.total_count());
    println!("  - Rate Limiting: {}/min (very strict)", financial_config.advanced_options.rate_limiting.requests_per_minute);

    // Example 3: Educational Domain Configuration
    println!("\n🎓 Educational Domain Configuration");
    println!("==================================");

    let educational_config = CustomConfigBuilder::from_preset(Preset::Educational)
        .with_name("Educational Learning Assistant")
        .with_description("Student-friendly configuration promoting academic integrity")
        .with_tags(vec!["education", "learning", "academic-integrity", "student-support"])
        .with_metadata("target_audience", "students,teachers,researchers")
        .with_metadata("age_appropriate", "13+")
        .with_metadata("academic_level", "high-school,college,university")
        // Moderate security - allow learning while preventing cheating
        .with_security_level(4)?  // Moderate - allow educational content
        .with_response_strategy(ResponseStrategy::Sanitize)  // Guide rather than block
        // Education-optimized features
        .configure_features(|f| {
            f.with_pattern_matching(true)
                .with_heuristic_analysis(false)  // Reduce false positives on educational content
                .with_semantic_detection(false)  // Keep simple for speed
                .with_encoding_detection(true)
                .with_social_engineering_detection(false)  // Allow persuasive educational content
                .with_context_hijacking_detection(true)
                .with_role_play_detection(false)  // Allow educational role-playing
                .with_data_extraction_detection(true)  // Prevent cheating attempts
                .with_multi_modal_detection(false)  // Keep it simple
                .with_custom_patterns(true)
                .with_jailbreak_detection(true)
                .with_instruction_override_detection(true)
                .with_code_injection_detection(true)  // Prevent misuse
                .with_system_prompt_leak_detection(true)
        })
        // Academic integrity patterns
        .add_custom_pattern(r"(?i)(?:do\s+my|complete\s+my|solve\s+my)\s+homework")?
        .add_custom_pattern(r"(?i)(?:write|complete)\s+my\s+(?:essay|assignment|paper)")?
        .add_custom_pattern(r"(?i)give\s+me\s+the\s+answers?\s+to")?
        .add_custom_pattern(r"(?i)cheat\s+on\s+(?:exam|test|quiz)")?
        .add_custom_pattern(r"(?i)plagiarize\s+(?:this|from)")?
        .add_custom_pattern(r"(?i)bypass\s+(?:turnitin|plagiarism\s+check)")?
        // Learning-friendly patterns that should be allowed
        .add_pattern_allowlist("explain the concept of")
        .add_pattern_allowlist("help me understand")
        .add_pattern_allowlist("can you teach me")
        .add_pattern_allowlist("what is the difference between")
        .add_pattern_allowlist("show me an example of")
        .add_pattern_allowlist("how does this work")
        // Balanced thresholds for educational context
        .override_threshold("data_extraction", 0.6)?  // Detect cheating attempts
        .override_threshold("academic_dishonesty", 0.5)?
        .set_category_sensitivity("homework_completion", 8)?  // High sensitivity to homework requests
        .set_category_sensitivity("concept_explanation", 2)?  // Low sensitivity to learning requests
        // Performance-oriented settings for student use
        .with_timeout(Duration::from_secs(5))  // Quick responses for students
        .max_concurrent_analyses(200)  // High concurrency for classroom use
        .max_memory_mb(256)  // Efficient resource usage
        // Student-friendly rate limiting
        .with_rate_limits(60, 1000, 5000)  // Generous for learning activities
        .configure_rate_limiting(|rate_config| {
            rate_config.enforcement_strategy = RateLimitStrategy::WarnAndAllow;
            rate_config.burst_allowance = 20; // Allow research bursts
        })
        // Educational response templates
        .with_response_template("academic_integrity", "I'm here to help you learn and understand concepts, but I can't complete assignments for you. Let me guide you through the learning process instead.")
        .with_response_template("homework_help", "I can explain concepts and provide examples, but you need to apply the knowledge to complete your own work.")
        .with_response_template("learning_support", "Great question! Let me help you understand this concept step by step.")
        // Learning-focused context awareness
        .with_context_history(8)  // Remember learning context
        .configure_context_awareness(|ctx| {
            ctx.track_user_patterns = false;  // Respect student privacy
            ctx.trust_score_adjustment = 0.1;  // Slightly more permissive for learning
        })
        // Educational text processing
        .max_text_length(15000)  // Allow longer academic content
        .preserve_formatting(true)  // Important for academic citations
        .build_validated()?;

    println!("✓ Created educational configuration");
    println!("  - Security Level: {} (learning-friendly)", educational_config.detection_config.security_level.level());
    println!("  - Academic Integrity Patterns: {} patterns", educational_config.detection_config.pattern_config.custom_patterns.len());
    println!("  - Learning Allowlist: {} patterns", educational_config.advanced_options.pattern_allowlists.len());
    println!("  - Rate Limiting: {}/min (generous for students)", educational_config.advanced_options.rate_limiting.requests_per_minute);

    // Example 4: Software Development Domain Configuration
    println!("\n💻 Software Development Domain Configuration");
    println!("===========================================");

    let development_config = CustomConfigBuilder::from_preset(Preset::Development)
        .with_name("Developer-Friendly Code Assistant")
        .with_description("Development configuration optimized for coding productivity")
        .with_tags(vec!["development", "coding", "programming", "developer-tools"])
        .with_metadata("target_users", "developers,engineers,programmers")
        .with_metadata("programming_languages", "python,javascript,java,go,rust,c++")
        .with_metadata("environment", "development,staging")
        // Low security for development productivity
        .with_security_level(2)?  // Very permissive for development
        .with_response_strategy(ResponseStrategy::Warn)  // Warn but allow
        // Development-optimized features
        .configure_features(|f| {
            f.with_pattern_matching(true)
                .with_heuristic_analysis(false)  // Avoid false positives on code
                .with_semantic_detection(false)  // Keep it fast
                .with_encoding_detection(false)  // Don't interfere with code encodings
                .with_social_engineering_detection(false)  // Allow technical discussions
                .with_context_hijacking_detection(false)  // Allow code context switching
                .with_role_play_detection(false)  // Allow code examples and scenarios
                .with_data_extraction_detection(false)  // Don't block data processing code
                .with_multi_modal_detection(false)
                .with_custom_patterns(true)
                .with_jailbreak_detection(true)  // Basic protection
                .with_instruction_override_detection(true)  // Basic protection
                .with_code_injection_detection(false)  // Don't block legitimate code
                .with_system_prompt_leak_detection(false)  // Allow system interaction examples
        })
        // Development-specific safety patterns (minimal)
        .add_custom_pattern(r"(?i)rm\s+-rf\s+/")?  // Dangerous file operations
        .add_custom_pattern(r"(?i)delete\s+from\s+\*")?  // Dangerous SQL
        .add_custom_pattern(r"(?i)drop\s+database")?  // Dangerous DB operations
        .add_custom_pattern(r"(?i)format\s+c:")?  // Dangerous system commands
        // Code-friendly allowlist
        .add_pattern_allowlist("import os")
        .add_pattern_allowlist("exec(")
        .add_pattern_allowlist("eval(")
        .add_pattern_allowlist("subprocess.call")
        .add_pattern_allowlist("system(")
        .add_pattern_allowlist("shell_exec")
        .add_pattern_allowlist("CREATE TABLE")
        .add_pattern_allowlist("DROP TABLE")
        .add_pattern_allowlist("SELECT * FROM")
        // Very relaxed thresholds for development
        .override_threshold("pattern_matching", 0.9)?  // Only catch obvious issues
        .override_threshold("instruction_override", 0.8)?
        .set_category_sensitivity("code_safety", 3)?  // Low sensitivity for code patterns
        // Performance settings for development speed
        .with_timeout(Duration::from_secs(2))  // Fast responses
        .max_concurrent_analyses(500)  // High concurrency for development teams
        .max_memory_mb(128)  // Minimal resource usage
        .pattern_cache_size(200)  // Small cache for speed
        // Developer-friendly rate limiting
        .with_rate_limits(200, 5000, 50000)  // Very generous for development
        .configure_rate_limiting(|rate_config| {
            rate_config.enforcement_strategy = RateLimitStrategy::WarnAndAllow;
            rate_config.burst_allowance = 100; // Large bursts for development work
        })
        // Development response templates
        .with_response_template("code_safety", "⚠️ This code pattern could be risky in production. Consider security implications.")
        .with_response_template("best_practice", "💡 Consider using a safer alternative for production environments.")
        .with_response_template("security_note", "🔒 Remember to validate inputs and sanitize outputs in production code.")
        // Minimal context for performance
        .with_context_history(3)  // Minimal context tracking
        .configure_context_awareness(|ctx| {
            ctx.track_user_patterns = false;  // No tracking for developer privacy
            ctx.trust_score_adjustment = 0.3;  // Very permissive
        })
        // Development-friendly text processing
        .max_text_length(100000)  // Allow large code files
        .preserve_formatting(true)  // Critical for code structure
        .normalize_unicode(false)  // Preserve exact code formatting
        .decode_encodings(false)  // Don't interfere with code encodings
        .build_validated()?;

    println!("✓ Created development configuration");
    println!("  - Security Level: {} (developer-friendly)", development_config.detection_config.security_level.level());
    println!("  - Safety Patterns: {} minimal patterns", development_config.detection_config.pattern_config.custom_patterns.len());
    println!("  - Code Allowlist: {} patterns", development_config.advanced_options.pattern_allowlists.len());
    println!("  - Rate Limiting: {}/min (very generous)", development_config.advanced_options.rate_limiting.requests_per_minute);

    // Example 5: Export all domain-specific configurations
    println!("\n📄 Exporting Domain-Specific Configurations");
    println!("============================================");

    healthcare_config.save_to_file("/tmp/healthcare_domain_config.json")?;
    financial_config.save_to_file("/tmp/financial_domain_config.yaml")?;
    educational_config.save_to_file("/tmp/educational_domain_config.json")?;
    development_config.save_to_file("/tmp/development_domain_config.yaml")?;

    println!("✓ Exported all domain-specific configurations to /tmp/");

    // Domain comparison table
    println!("\n📊 Domain Configuration Comparison");
    println!("==================================");
    
    let configs = vec![
        (&healthcare_config, "Healthcare", "🏥"),
        (&financial_config, "Financial", "💰"),
        (&educational_config, "Educational", "🎓"),
        (&development_config, "Development", "💻"),
    ];

    println!("┌─────────────┬──────────┬──────────────┬────────────┬─────────────┬──────────────┐");
    println!("│ Domain      │ Security │ Rate Limit   │ Features   │ Patterns    │ Strategy     │");
    println!("├─────────────┼──────────┼──────────────┼────────────┼─────────────┼──────────────┤");
    
    for (config, domain, emoji) in configs {
        println!("│ {:<9} {} │ {:<8} │ {:<12} │ {:<10} │ {:<11} │ {:<12} │",
            emoji,
            domain,
            config.detection_config.security_level.level(),
            format!("{}/min", config.advanced_options.rate_limiting.requests_per_minute),
            format!("{}/{}", config.features.enabled_count(), config.features.total_count()),
            config.detection_config.pattern_config.custom_patterns.len(),
            match config.detection_config.response_strategy {
                ResponseStrategy::Block => "Block",
                ResponseStrategy::Sanitize => "Sanitize",
                ResponseStrategy::Warn => "Warn",
                ResponseStrategy::Allow => "Allow",
                ResponseStrategy::Custom(_) => "Custom",
            }
        );
    }
    
    println!("└─────────────┴──────────┴──────────────┴────────────┴─────────────┴──────────────┘");

    println!("\n✅ Domain-specific configuration examples completed!");
    println!("\nDomain Characteristics:");
    println!("  🏥 Healthcare: Maximum security, HIPAA compliance, PII protection");
    println!("  💰 Financial: Ultra-strict security, fraud prevention, regulatory compliance");
    println!("  🎓 Educational: Balanced approach, academic integrity, learning-friendly");
    println!("  💻 Development: Minimal interference, productivity-focused, developer-friendly");

    println!("\nBest Practices by Domain:");
    println!("  • Healthcare: Use semantic analysis for PII detection, strict rate limiting");
    println!("  • Financial: Enable all features, ultra-low thresholds, comprehensive logging");
    println!("  • Educational: Balance security with learning, guide rather than block");
    println!("  • Development: Minimize false positives, preserve code formatting, high performance");

    Ok(())
}