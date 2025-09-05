//! Configuration presets for common use cases.
//!
//! This module provides pre-configured security profiles optimized for different
//! application types and security requirements.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

use crate::config::{
    DetectionConfig, PatternConfig, ResourceConfig, ResponseStrategy, SecurityLevel, SemanticConfig,
};
use crate::features::Features;
use crate::types::PreprocessingConfig;

/// Predefined configuration presets for common use cases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum Preset {
    /// High accuracy with low false positives for chatbots
    #[default]
    ChatBot,
    /// Allow technical terms, block exploits for code assistants
    CodeAssistant,
    /// Professional tone with moderate security for customer service
    CustomerService,
    /// Allow learning content, block attacks for educational platforms
    Educational,
    /// Maximum security with strict validation for financial applications
    Financial,
    /// HIPAA compliant with PII protection for healthcare
    Healthcare,
    /// Minimal filtering with comprehensive logging for development
    Development,
    /// User-defined custom configuration
    Custom,
}

impl Preset {
    /// Returns a human-readable description of the preset.
    pub fn description(&self) -> &str {
        match self {
            Preset::ChatBot => "High accuracy, low false positives for general chatbots",
            Preset::CodeAssistant => "Technical-friendly with exploit protection for code helpers",
            Preset::CustomerService => "Professional tone with moderate security filtering",
            Preset::Educational => "Learning-focused with attack prevention",
            Preset::Financial => "Maximum security for financial and sensitive applications",
            Preset::Healthcare => "HIPAA compliant with comprehensive PII protection",
            Preset::Development => "Developer-friendly with minimal interference",
            Preset::Custom => "User-defined custom configuration",
        }
    }

    /// Returns the recommended security level for this preset.
    pub fn security_level(&self) -> SecurityLevel {
        match self {
            Preset::ChatBot => SecurityLevel::new(5).unwrap(), // Balanced
            Preset::CodeAssistant => SecurityLevel::new(4).unwrap(), // Moderate
            Preset::CustomerService => SecurityLevel::new(6).unwrap(), // Enhanced
            Preset::Educational => SecurityLevel::new(3).unwrap(), // Light
            Preset::Financial => SecurityLevel::new(9).unwrap(), // Near-paranoid
            Preset::Healthcare => SecurityLevel::new(8).unwrap(), // Very strict
            Preset::Development => SecurityLevel::new(2).unwrap(), // Permissive
            Preset::Custom => SecurityLevel::new(5).unwrap(),  // Default balanced
        }
    }

    /// Returns the recommended response strategy for this preset.
    pub fn response_strategy(&self) -> ResponseStrategy {
        match self {
            Preset::ChatBot => ResponseStrategy::Sanitize,
            Preset::CodeAssistant => ResponseStrategy::Warn,
            Preset::CustomerService => ResponseStrategy::Block,
            Preset::Educational => ResponseStrategy::Sanitize,
            Preset::Financial => ResponseStrategy::Block,
            Preset::Healthcare => ResponseStrategy::Block,
            Preset::Development => ResponseStrategy::Allow,
            Preset::Custom => ResponseStrategy::Block,
        }
    }

    /// Returns the recommended features configuration for this preset.
    pub fn features(&self) -> Features {
        match self {
            Preset::ChatBot => Features {
                pattern_matching: true,
                heuristic_analysis: true,
                semantic_detection: false,
                encoding_detection: true,
                social_engineering_detection: true,
                context_hijacking_detection: true,
                role_play_detection: true,
                data_extraction_detection: false,
                multi_modal_detection: false,
                custom_patterns: true,
                jailbreak_detection: true,
                instruction_override_detection: true,
                code_injection_detection: false,
                system_prompt_leak_detection: true,
            },
            Preset::CodeAssistant => Features {
                pattern_matching: true,
                heuristic_analysis: false, // Reduce false positives on technical content
                semantic_detection: false,
                encoding_detection: true,
                social_engineering_detection: false, // Allow technical discussions
                context_hijacking_detection: true,
                role_play_detection: false, // Allow code examples
                data_extraction_detection: true,
                multi_modal_detection: false,
                custom_patterns: true,
                jailbreak_detection: true,
                instruction_override_detection: true,
                code_injection_detection: true,
                system_prompt_leak_detection: true,
            },
            Preset::CustomerService => Features {
                pattern_matching: true,
                heuristic_analysis: true,
                semantic_detection: false,
                encoding_detection: true,
                social_engineering_detection: true,
                context_hijacking_detection: true,
                role_play_detection: true,
                data_extraction_detection: true,
                multi_modal_detection: false,
                custom_patterns: true,
                jailbreak_detection: true,
                instruction_override_detection: true,
                code_injection_detection: false,
                system_prompt_leak_detection: true,
            },
            Preset::Educational => Features {
                pattern_matching: true,
                heuristic_analysis: false, // Allow educational discussions
                semantic_detection: false,
                encoding_detection: true,
                social_engineering_detection: false, // Allow learning scenarios
                context_hijacking_detection: true,
                role_play_detection: false, // Allow educational role-play
                data_extraction_detection: true,
                multi_modal_detection: false,
                custom_patterns: true,
                jailbreak_detection: true,
                instruction_override_detection: true,
                code_injection_detection: true,
                system_prompt_leak_detection: true,
            },
            Preset::Financial => Features::all_enabled(), // Maximum security
            Preset::Healthcare => Features {
                pattern_matching: true,
                heuristic_analysis: true,
                semantic_detection: true, // Enhanced detection for PII
                encoding_detection: true,
                social_engineering_detection: true,
                context_hijacking_detection: true,
                role_play_detection: true,
                data_extraction_detection: true,
                multi_modal_detection: true, // Scan all content types
                custom_patterns: true,
                jailbreak_detection: true,
                instruction_override_detection: true,
                code_injection_detection: true,
                system_prompt_leak_detection: true,
            },
            Preset::Development => Features {
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
                jailbreak_detection: true, // Keep basic protections
                instruction_override_detection: true,
                code_injection_detection: false,
                system_prompt_leak_detection: false,
            },
            Preset::Custom => Features::balanced(),
        }
    }

    /// Returns the recommended pattern configuration for this preset.
    pub fn pattern_config(&self) -> PatternConfig {
        match self {
            Preset::ChatBot => PatternConfig {
                enabled_categories: None, // Auto-populate based on security level
                custom_patterns: vec![
                    r"(?i)act\s+as\s+(?:dan|jailbreak|unrestricted)".to_string(),
                    r"(?i)pretend\s+you're\s+not\s+an?\s+ai".to_string(),
                ],
                case_sensitive: false,
                max_patterns: 2000,
            },
            Preset::CodeAssistant => PatternConfig {
                enabled_categories: Some(vec![
                    "instruction_override".to_string(),
                    "jailbreak".to_string(),
                    "encoding_bypass".to_string(),
                    "data_extraction".to_string(),
                ]),
                custom_patterns: vec![
                    r"(?i)execute\s+(?:system|shell|command)".to_string(),
                    r"(?i)run\s+(?:malicious|harmful)\s+code".to_string(),
                ],
                case_sensitive: false,
                max_patterns: 1500,
            },
            Preset::CustomerService => PatternConfig {
                enabled_categories: None,
                custom_patterns: vec![
                    r"(?i)customer\s+service\s+override".to_string(),
                    r"(?i)escalate\s+to\s+manager\s+mode".to_string(),
                ],
                case_sensitive: false,
                max_patterns: 2500,
            },
            Preset::Educational => PatternConfig {
                enabled_categories: Some(vec![
                    "instruction_override".to_string(),
                    "jailbreak".to_string(),
                    "data_extraction".to_string(),
                ]),
                custom_patterns: vec![
                    r"(?i)cheat\s+on\s+(?:exam|test|homework)".to_string(),
                    r"(?i)give\s+me\s+the\s+answers?".to_string(),
                ],
                case_sensitive: false,
                max_patterns: 1000,
            },
            Preset::Financial => PatternConfig {
                enabled_categories: None, // Use all categories
                custom_patterns: vec![
                    r"(?i)bypass\s+(?:audit|compliance|regulation)".to_string(),
                    r"(?i)ignore\s+(?:privacy|security)\s+policies".to_string(),
                    r"(?i)transfer\s+(?:funds|money)\s+to".to_string(),
                    r"(?i)account\s+(?:number|details|credentials)".to_string(),
                ],
                case_sensitive: false,
                max_patterns: 5000,
            },
            Preset::Healthcare => PatternConfig {
                enabled_categories: None, // Use all categories
                custom_patterns: vec![
                    r"(?i)patient\s+(?:records?|data|information)".to_string(),
                    r"(?i)medical\s+(?:records?|history|data)".to_string(),
                    r"(?i)hipaa\s+(?:bypass|violation|ignore)".to_string(),
                    r"(?i)ssn|social\s+security\s+number".to_string(),
                    r"(?i)(?:dob|date\s+of\s+birth)".to_string(),
                ],
                case_sensitive: false,
                max_patterns: 4000,
            },
            Preset::Development => PatternConfig {
                enabled_categories: Some(vec![
                    "instruction_override".to_string(),
                    "jailbreak".to_string(),
                ]),
                custom_patterns: vec![
                    r"(?i)rm\s+-rf\s+/".to_string(),
                    r"(?i)delete\s+all\s+files".to_string(),
                ],
                case_sensitive: false,
                max_patterns: 500,
            },
            Preset::Custom => PatternConfig::default(),
        }
    }

    /// Returns the recommended semantic configuration for this preset.
    pub fn semantic_config(&self) -> SemanticConfig {
        match self {
            Preset::ChatBot => SemanticConfig {
                enabled: false, // Keep it fast
                model_name: None,
                similarity_threshold: 0.8,
                max_context_length: 512,
            },
            Preset::CodeAssistant => SemanticConfig {
                enabled: false, // Avoid false positives on technical content
                model_name: None,
                similarity_threshold: 0.85,
                max_context_length: 1024,
            },
            Preset::CustomerService => SemanticConfig {
                enabled: false,
                model_name: None,
                similarity_threshold: 0.75,
                max_context_length: 512,
            },
            Preset::Educational => SemanticConfig {
                enabled: false,
                model_name: None,
                similarity_threshold: 0.8,
                max_context_length: 512,
            },
            Preset::Financial => SemanticConfig {
                enabled: true, // Maximum detection
                model_name: Some("sentence-transformers/all-MiniLM-L6-v2".to_string()),
                similarity_threshold: 0.7, // Lower threshold for higher sensitivity
                max_context_length: 1024,
            },
            Preset::Healthcare => SemanticConfig {
                enabled: true, // PII detection benefits from semantic analysis
                model_name: Some("sentence-transformers/all-MiniLM-L6-v2".to_string()),
                similarity_threshold: 0.75,
                max_context_length: 1024,
            },
            Preset::Development => SemanticConfig {
                enabled: false, // Keep it minimal
                model_name: None,
                similarity_threshold: 0.9,
                max_context_length: 256,
            },
            Preset::Custom => SemanticConfig::default(),
        }
    }

    /// Returns the recommended preprocessing configuration for this preset.
    pub fn preprocessing_config(&self) -> PreprocessingConfig {
        match self {
            Preset::ChatBot => PreprocessingConfig {
                normalize_unicode: true,
                decode_encodings: true,
                max_length: 5_000,
                preserve_formatting: false,
            },
            Preset::CodeAssistant => PreprocessingConfig {
                normalize_unicode: true,
                decode_encodings: true,
                max_length: 20_000,        // Allow longer code snippets
                preserve_formatting: true, // Important for code
            },
            Preset::CustomerService => PreprocessingConfig {
                normalize_unicode: true,
                decode_encodings: true,
                max_length: 3_000,
                preserve_formatting: false,
            },
            Preset::Educational => PreprocessingConfig {
                normalize_unicode: true,
                decode_encodings: true,
                max_length: 10_000, // Allow longer educational content
                preserve_formatting: true,
            },
            Preset::Financial => PreprocessingConfig {
                normalize_unicode: true,
                decode_encodings: true,
                max_length: 5_000,
                preserve_formatting: true, // Preserve structure for audit trails
            },
            Preset::Healthcare => PreprocessingConfig {
                normalize_unicode: true,
                decode_encodings: true,
                max_length: 8_000,
                preserve_formatting: true, // Important for medical data
            },
            Preset::Development => PreprocessingConfig {
                normalize_unicode: false, // Preserve raw input
                decode_encodings: false,
                max_length: 50_000, // Allow large code files
                preserve_formatting: true,
            },
            Preset::Custom => PreprocessingConfig::default(),
        }
    }

    /// Returns the recommended resource configuration for this preset.
    pub fn resource_config(&self) -> ResourceConfig {
        match self {
            Preset::ChatBot => ResourceConfig {
                max_concurrent_analyses: 200, // High throughput for chatbots
                analysis_timeout: Duration::from_secs(5),
                max_memory_mb: 256,
                pattern_cache_size: 1000,
            },
            Preset::CodeAssistant => ResourceConfig {
                max_concurrent_analyses: 50, // Lower concurrency for complex analysis
                analysis_timeout: Duration::from_secs(15), // More time for code analysis
                max_memory_mb: 512,
                pattern_cache_size: 500,
            },
            Preset::CustomerService => ResourceConfig {
                max_concurrent_analyses: 100,
                analysis_timeout: Duration::from_secs(3), // Fast response for customers
                max_memory_mb: 256,
                pattern_cache_size: 800,
            },
            Preset::Educational => ResourceConfig {
                max_concurrent_analyses: 150,
                analysis_timeout: Duration::from_secs(8),
                max_memory_mb: 384,
                pattern_cache_size: 600,
            },
            Preset::Financial => ResourceConfig {
                max_concurrent_analyses: 25,               // Conservative for security
                analysis_timeout: Duration::from_secs(30), // Thorough analysis
                max_memory_mb: 1024, // More resources for comprehensive detection
                pattern_cache_size: 2000,
            },
            Preset::Healthcare => ResourceConfig {
                max_concurrent_analyses: 50,
                analysis_timeout: Duration::from_secs(20),
                max_memory_mb: 768,
                pattern_cache_size: 1500,
            },
            Preset::Development => ResourceConfig {
                max_concurrent_analyses: 10, // Minimal overhead
                analysis_timeout: Duration::from_secs(2),
                max_memory_mb: 128,
                pattern_cache_size: 200,
            },
            Preset::Custom => ResourceConfig::default(),
        }
    }

    /// Returns custom configuration values specific to this preset.
    pub fn custom_config(&self) -> HashMap<String, String> {
        let mut config = HashMap::new();

        match self {
            Preset::ChatBot => {
                config.insert("preset_type".to_string(), "chatbot".to_string());
                config.insert("optimize_for".to_string(), "user_experience".to_string());
                config.insert("false_positive_tolerance".to_string(), "low".to_string());
            }
            Preset::CodeAssistant => {
                config.insert("preset_type".to_string(), "code_assistant".to_string());
                config.insert("optimize_for".to_string(), "technical_accuracy".to_string());
                config.insert("code_context_aware".to_string(), "true".to_string());
                config.insert("programming_languages".to_string(), "all".to_string());
            }
            Preset::CustomerService => {
                config.insert("preset_type".to_string(), "customer_service".to_string());
                config.insert("optimize_for".to_string(), "professionalism".to_string());
                config.insert("escalation_triggers".to_string(), "enabled".to_string());
            }
            Preset::Educational => {
                config.insert("preset_type".to_string(), "educational".to_string());
                config.insert("optimize_for".to_string(), "learning_support".to_string());
                config.insert("academic_integrity".to_string(), "enforced".to_string());
                config.insert("age_appropriate".to_string(), "true".to_string());
            }
            Preset::Financial => {
                config.insert("preset_type".to_string(), "financial".to_string());
                config.insert("optimize_for".to_string(), "maximum_security".to_string());
                config.insert("compliance_mode".to_string(), "strict".to_string());
                config.insert("audit_logging".to_string(), "comprehensive".to_string());
                config.insert("pci_dss_compliant".to_string(), "true".to_string());
                config.insert("sox_compliant".to_string(), "true".to_string());
            }
            Preset::Healthcare => {
                config.insert("preset_type".to_string(), "healthcare".to_string());
                config.insert("optimize_for".to_string(), "privacy_protection".to_string());
                config.insert("hipaa_compliant".to_string(), "true".to_string());
                config.insert("phi_protection".to_string(), "enabled".to_string());
                config.insert("gdpr_compliant".to_string(), "true".to_string());
                config.insert("pii_detection".to_string(), "enhanced".to_string());
            }
            Preset::Development => {
                config.insert("preset_type".to_string(), "development".to_string());
                config.insert(
                    "optimize_for".to_string(),
                    "developer_productivity".to_string(),
                );
                config.insert("debug_mode".to_string(), "enabled".to_string());
                config.insert("verbose_logging".to_string(), "true".to_string());
                config.insert(
                    "bypass_warnings".to_string(),
                    "development_only".to_string(),
                );
            }
            Preset::Custom => {
                config.insert("preset_type".to_string(), "custom".to_string());
                config.insert("optimize_for".to_string(), "user_defined".to_string());
            }
        }

        config
    }

    /// Creates a complete DetectionConfig from this preset.
    pub fn to_detection_config(&self) -> DetectionConfig {
        DetectionConfig {
            security_level: self.security_level(),
            severity_level: None, // Use new security level system
            response_strategy: self.response_strategy(),
            pattern_config: self.pattern_config(),
            semantic_config: self.semantic_config(),
            preprocessing_config: self.preprocessing_config(),
            resource_config: self.resource_config(),
            enable_metrics: true,
            custom_config: self.custom_config(),
        }
    }

    /// Returns all available presets with their descriptions.
    pub fn all_presets() -> Vec<(Preset, &'static str)> {
        vec![
            (Preset::ChatBot, Preset::ChatBot.description()),
            (Preset::CodeAssistant, Preset::CodeAssistant.description()),
            (
                Preset::CustomerService,
                Preset::CustomerService.description(),
            ),
            (Preset::Educational, Preset::Educational.description()),
            (Preset::Financial, Preset::Financial.description()),
            (Preset::Healthcare, Preset::Healthcare.description()),
            (Preset::Development, Preset::Development.description()),
            (Preset::Custom, Preset::Custom.description()),
        ]
    }

    /// Returns the preset that best matches the given requirements.
    pub fn recommend_for_use_case(
        use_case: &str,
        security_priority: &str,
        performance_priority: &str,
    ) -> Vec<Preset> {
        let use_case_lower = use_case.to_lowercase();
        let security_lower = security_priority.to_lowercase();
        let performance_lower = performance_priority.to_lowercase();

        let mut recommendations = Vec::new();

        // Primary recommendations based on use case
        if use_case_lower.contains("chat") || use_case_lower.contains("conversation") {
            recommendations.push(Preset::ChatBot);
        }
        if use_case_lower.contains("code")
            || use_case_lower.contains("programming")
            || use_case_lower.contains("development")
        {
            recommendations.push(Preset::CodeAssistant);
        }
        if use_case_lower.contains("customer")
            || use_case_lower.contains("support")
            || use_case_lower.contains("service")
        {
            recommendations.push(Preset::CustomerService);
        }
        if use_case_lower.contains("education")
            || use_case_lower.contains("learning")
            || use_case_lower.contains("school")
        {
            recommendations.push(Preset::Educational);
        }
        if use_case_lower.contains("financial")
            || use_case_lower.contains("banking")
            || use_case_lower.contains("payment")
        {
            recommendations.push(Preset::Financial);
        }
        if use_case_lower.contains("health")
            || use_case_lower.contains("medical")
            || use_case_lower.contains("hipaa")
        {
            recommendations.push(Preset::Healthcare);
        }
        if use_case_lower.contains("dev")
            || use_case_lower.contains("test")
            || use_case_lower.contains("debug")
        {
            recommendations.push(Preset::Development);
        }

        // Adjust based on security priority
        if security_lower.contains("high")
            || security_lower.contains("maximum")
            || security_lower.contains("strict")
        {
            if !recommendations.contains(&Preset::Financial) {
                recommendations.push(Preset::Financial);
            }
            if !recommendations.contains(&Preset::Healthcare) {
                recommendations.push(Preset::Healthcare);
            }
        } else if (security_lower.contains("low") || security_lower.contains("minimal"))
            && !recommendations.contains(&Preset::Development)
        {
            recommendations.push(Preset::Development);
        }

        // Adjust based on performance priority
        if performance_lower.contains("high")
            || performance_lower.contains("fast")
            || performance_lower.contains("speed")
        {
            recommendations.retain(|p| !matches!(p, Preset::Financial | Preset::Healthcare));
            if !recommendations.contains(&Preset::Development) {
                recommendations.push(Preset::Development);
            }
            if !recommendations.contains(&Preset::ChatBot) {
                recommendations.push(Preset::ChatBot);
            }
        }

        // If no specific recommendations, suggest balanced options
        if recommendations.is_empty() {
            recommendations.push(Preset::ChatBot);
            recommendations.push(Preset::Custom);
        }

        recommendations
    }
}


impl std::fmt::Display for Preset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Preset::ChatBot => write!(f, "ChatBot"),
            Preset::CodeAssistant => write!(f, "CodeAssistant"),
            Preset::CustomerService => write!(f, "CustomerService"),
            Preset::Educational => write!(f, "Educational"),
            Preset::Financial => write!(f, "Financial"),
            Preset::Healthcare => write!(f, "Healthcare"),
            Preset::Development => write!(f, "Development"),
            Preset::Custom => write!(f, "Custom"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preset_descriptions() {
        let all_presets = Preset::all_presets();
        assert_eq!(all_presets.len(), 8);

        for (preset, description) in all_presets {
            assert!(!description.is_empty());
            assert_eq!(description, preset.description());
        }
    }

    #[test]
    fn test_preset_security_levels() {
        assert_eq!(Preset::ChatBot.security_level().level(), 5);
        assert_eq!(Preset::CodeAssistant.security_level().level(), 4);
        assert_eq!(Preset::CustomerService.security_level().level(), 6);
        assert_eq!(Preset::Educational.security_level().level(), 3);
        assert_eq!(Preset::Financial.security_level().level(), 9);
        assert_eq!(Preset::Healthcare.security_level().level(), 8);
        assert_eq!(Preset::Development.security_level().level(), 2);
        assert_eq!(Preset::Custom.security_level().level(), 5);
    }

    #[test]
    fn test_preset_response_strategies() {
        assert_eq!(
            Preset::ChatBot.response_strategy(),
            ResponseStrategy::Sanitize
        );
        assert_eq!(
            Preset::CodeAssistant.response_strategy(),
            ResponseStrategy::Warn
        );
        assert_eq!(
            Preset::CustomerService.response_strategy(),
            ResponseStrategy::Block
        );
        assert_eq!(
            Preset::Educational.response_strategy(),
            ResponseStrategy::Sanitize
        );
        assert_eq!(
            Preset::Financial.response_strategy(),
            ResponseStrategy::Block
        );
        assert_eq!(
            Preset::Healthcare.response_strategy(),
            ResponseStrategy::Block
        );
        assert_eq!(
            Preset::Development.response_strategy(),
            ResponseStrategy::Allow
        );
        assert_eq!(Preset::Custom.response_strategy(), ResponseStrategy::Block);
    }

    #[test]
    fn test_preset_features() {
        let chatbot_features = Preset::ChatBot.features();
        assert!(chatbot_features.pattern_matching);
        assert!(!chatbot_features.semantic_detection);
        assert!(chatbot_features.social_engineering_detection);

        let code_features = Preset::CodeAssistant.features();
        assert!(code_features.pattern_matching);
        assert!(!code_features.heuristic_analysis);
        assert!(!code_features.social_engineering_detection);
        assert!(code_features.code_injection_detection);

        let financial_features = Preset::Financial.features();
        assert_eq!(
            financial_features.enabled_count(),
            financial_features.total_count()
        );

        let dev_features = Preset::Development.features();
        assert!(dev_features.pattern_matching);
        assert!(!dev_features.heuristic_analysis);
        assert!(!dev_features.semantic_detection);
    }

    #[test]
    fn test_preset_pattern_configs() {
        let chatbot_config = Preset::ChatBot.pattern_config();
        assert!(!chatbot_config.custom_patterns.is_empty());
        assert_eq!(chatbot_config.max_patterns, 2000);

        let financial_config = Preset::Financial.pattern_config();
        assert!(financial_config.custom_patterns.len() >= 4);
        assert_eq!(financial_config.max_patterns, 5000);

        let dev_config = Preset::Development.pattern_config();
        assert_eq!(dev_config.max_patterns, 500);
    }

    #[test]
    fn test_preset_semantic_configs() {
        let financial_semantic = Preset::Financial.semantic_config();
        assert!(financial_semantic.enabled);
        assert!(financial_semantic.model_name.is_some());

        let healthcare_semantic = Preset::Healthcare.semantic_config();
        assert!(healthcare_semantic.enabled);

        let chatbot_semantic = Preset::ChatBot.semantic_config();
        assert!(!chatbot_semantic.enabled);

        let dev_semantic = Preset::Development.semantic_config();
        assert!(!dev_semantic.enabled);
    }

    #[test]
    fn test_preset_preprocessing_configs() {
        let code_preprocessing = Preset::CodeAssistant.preprocessing_config();
        assert_eq!(code_preprocessing.max_length, 20_000);
        assert!(code_preprocessing.preserve_formatting);

        let dev_preprocessing = Preset::Development.preprocessing_config();
        assert_eq!(dev_preprocessing.max_length, 50_000);
        assert!(!dev_preprocessing.normalize_unicode);
        assert!(!dev_preprocessing.decode_encodings);

        let customer_preprocessing = Preset::CustomerService.preprocessing_config();
        assert_eq!(customer_preprocessing.max_length, 3_000);
        assert!(!customer_preprocessing.preserve_formatting);
    }

    #[test]
    fn test_preset_resource_configs() {
        let chatbot_resource = Preset::ChatBot.resource_config();
        assert_eq!(chatbot_resource.max_concurrent_analyses, 200);
        assert_eq!(chatbot_resource.analysis_timeout, Duration::from_secs(5));

        let financial_resource = Preset::Financial.resource_config();
        assert_eq!(financial_resource.max_concurrent_analyses, 25);
        assert_eq!(financial_resource.analysis_timeout, Duration::from_secs(30));
        assert_eq!(financial_resource.max_memory_mb, 1024);

        let dev_resource = Preset::Development.resource_config();
        assert_eq!(dev_resource.max_concurrent_analyses, 10);
        assert_eq!(dev_resource.max_memory_mb, 128);
    }

    #[test]
    fn test_preset_custom_configs() {
        let financial_custom = Preset::Financial.custom_config();
        assert!(financial_custom.contains_key("preset_type"));
        assert!(!financial_custom.contains_key("hipaa_compliant")); // Financial, not healthcare
        assert!(financial_custom.contains_key("pci_dss_compliant"));
        assert!(financial_custom.contains_key("sox_compliant"));

        let healthcare_custom = Preset::Healthcare.custom_config();
        assert!(healthcare_custom.contains_key("hipaa_compliant"));
        assert!(healthcare_custom.contains_key("phi_protection"));
        assert!(healthcare_custom.contains_key("gdpr_compliant"));

        let dev_custom = Preset::Development.custom_config();
        assert!(dev_custom.contains_key("debug_mode"));
        assert!(dev_custom.contains_key("verbose_logging"));
    }

    #[test]
    fn test_preset_to_detection_config() {
        let chatbot_config = Preset::ChatBot.to_detection_config();
        assert_eq!(chatbot_config.security_level.level(), 5);
        assert_eq!(chatbot_config.response_strategy, ResponseStrategy::Sanitize);
        assert!(chatbot_config.enable_metrics);
        assert!(chatbot_config.custom_config.contains_key("preset_type"));

        let financial_config = Preset::Financial.to_detection_config();
        assert_eq!(financial_config.security_level.level(), 9);
        assert_eq!(financial_config.response_strategy, ResponseStrategy::Block);
        assert!(financial_config.semantic_config.enabled);
    }

    #[test]
    fn test_preset_recommendations() {
        let chat_recs = Preset::recommend_for_use_case("chatbot application", "medium", "high");
        assert!(chat_recs.contains(&Preset::ChatBot));

        let financial_recs = Preset::recommend_for_use_case("banking system", "maximum", "low");
        assert!(financial_recs.contains(&Preset::Financial));

        let code_recs = Preset::recommend_for_use_case("code assistant", "low", "high");
        assert!(
            code_recs.contains(&Preset::CodeAssistant) || code_recs.contains(&Preset::Development)
        );

        let healthcare_recs = Preset::recommend_for_use_case("medical records", "high", "medium");
        assert!(healthcare_recs.contains(&Preset::Healthcare));

        // Test fallback
        let generic_recs = Preset::recommend_for_use_case("generic app", "medium", "medium");
        assert!(!generic_recs.is_empty());
        assert!(generic_recs.contains(&Preset::ChatBot) || generic_recs.contains(&Preset::Custom));
    }

    #[test]
    fn test_preset_serialization() {
        for preset in [
            Preset::ChatBot,
            Preset::CodeAssistant,
            Preset::CustomerService,
            Preset::Educational,
            Preset::Financial,
            Preset::Healthcare,
            Preset::Development,
            Preset::Custom,
        ] {
            let json = serde_json::to_string(&preset).unwrap();
            let deserialized: Preset = serde_json::from_str(&json).unwrap();
            assert_eq!(preset, deserialized);
        }
    }

    #[test]
    fn test_preset_display() {
        assert_eq!(format!("{}", Preset::ChatBot), "ChatBot");
        assert_eq!(format!("{}", Preset::CodeAssistant), "CodeAssistant");
        assert_eq!(format!("{}", Preset::Financial), "Financial");
        assert_eq!(format!("{}", Preset::Healthcare), "Healthcare");
    }

    #[test]
    fn test_preset_default() {
        let default_preset = Preset::default();
        assert_eq!(default_preset, Preset::ChatBot);
    }

    #[test]
    fn test_preset_configurations_validity() {
        for preset in [
            Preset::ChatBot,
            Preset::CodeAssistant,
            Preset::CustomerService,
            Preset::Educational,
            Preset::Financial,
            Preset::Healthcare,
            Preset::Development,
            Preset::Custom,
        ] {
            let config = preset.to_detection_config();
            assert!(
                config.validate().is_ok(),
                "Preset {:?} should produce valid config",
                preset
            );
        }
    }

    #[test]
    fn test_preset_features_consistency() {
        // Financial should have all features enabled
        let financial_features = Preset::Financial.features();
        assert_eq!(financial_features, Features::all_enabled());

        // Development should have minimal features
        let dev_features = Preset::Development.features();
        assert!(dev_features.enabled_count() < financial_features.enabled_count());

        // Healthcare should have comprehensive features for PII protection
        let healthcare_features = Preset::Healthcare.features();
        assert!(healthcare_features.semantic_detection);
        assert!(healthcare_features.multi_modal_detection);
        assert!(healthcare_features.data_extraction_detection);
    }
}
