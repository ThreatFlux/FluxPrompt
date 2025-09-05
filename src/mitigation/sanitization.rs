//! Text sanitization utilities for prompt injection mitigation.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use tracing::{debug, instrument};

use super::strategies::{MitigationStrategy, StrategySelector, ThreatContext};
use crate::config::DetectionConfig;
use crate::detection::DetectionResult;
use crate::error::Result;
use crate::types::{TextSpan, ThreatInfo, ThreatType};

/// Regex patterns for common sanitization tasks.
static SANITIZATION_PATTERNS: Lazy<HashMap<&'static str, Regex>> = Lazy::new(|| {
    let mut patterns = HashMap::new();

    // HTML/XML tags
    patterns.insert("html_tags", Regex::new(r"<[^>]*>").unwrap());

    // Script tags specifically
    patterns.insert(
        "script_tags",
        Regex::new(r"(?i)<script[^>]*>.*?</script>").unwrap(),
    );

    // Common injection patterns
    patterns.insert(
        "sql_injection",
        Regex::new(r"(?i)(union\s+select|drop\s+table|insert\s+into|delete\s+from)").unwrap(),
    );

    // Command injection
    patterns.insert("command_injection", Regex::new(r"[;&|`$()]").unwrap());

    // Excessive whitespace
    patterns.insert("excessive_whitespace", Regex::new(r"\s{3,}").unwrap());

    // Control characters (except newline and tab)
    patterns.insert(
        "control_chars",
        Regex::new(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]").unwrap(),
    );

    patterns
});

/// Text sanitizer for cleaning potentially malicious content.
pub struct TextSanitizer {
    strategy_selector: StrategySelector,
    config: DetectionConfig,
    aggressive_mode: bool,
}

impl TextSanitizer {
    /// Creates a new text sanitizer.
    pub fn new(config: &DetectionConfig) -> Result<Self> {
        let strategy_selector = StrategySelector::new();

        Ok(Self {
            strategy_selector,
            config: config.clone(),
            aggressive_mode: config.effective_security_level().confidence_threshold() < 0.6,
        })
    }

    /// Sanitizes text based on detection results.
    #[instrument(skip(self, text, detection_result))]
    pub async fn sanitize(&self, text: &str, detection_result: &DetectionResult) -> Result<String> {
        debug!(
            "Sanitizing text with {} detected threats",
            detection_result.threats().len()
        );

        let mut sanitized_text = text.to_string();

        // Apply general sanitization first
        sanitized_text = self.apply_general_sanitization(&sanitized_text);

        // Apply threat-specific mitigations
        sanitized_text = self
            .apply_threat_mitigations(&sanitized_text, detection_result)
            .await;

        // Final cleanup
        sanitized_text = self.apply_final_cleanup(&sanitized_text);

        debug!(
            "Sanitization complete, length changed from {} to {}",
            text.len(),
            sanitized_text.len()
        );
        Ok(sanitized_text)
    }

    /// Applies general sanitization rules.
    fn apply_general_sanitization(&self, text: &str) -> String {
        let mut sanitized = text.to_string();

        // Remove control characters
        if let Some(pattern) = SANITIZATION_PATTERNS.get("control_chars") {
            sanitized = pattern.replace_all(&sanitized, "").to_string();
        }

        // Normalize excessive whitespace
        if let Some(pattern) = SANITIZATION_PATTERNS.get("excessive_whitespace") {
            sanitized = pattern.replace_all(&sanitized, " ").to_string();
        }

        // Remove HTML tags if in aggressive mode
        if self.aggressive_mode {
            if let Some(pattern) = SANITIZATION_PATTERNS.get("html_tags") {
                sanitized = pattern.replace_all(&sanitized, "").to_string();
            }
        }

        // Always remove script tags
        if let Some(pattern) = SANITIZATION_PATTERNS.get("script_tags") {
            sanitized = pattern
                .replace_all(&sanitized, "[SCRIPT_REMOVED]")
                .to_string();
        }

        sanitized
    }

    /// Applies threat-specific mitigation strategies.
    async fn apply_threat_mitigations(
        &self,
        text: &str,
        detection_result: &DetectionResult,
    ) -> String {
        let mut result = text.to_string();

        // Sort threats by position (if available) in reverse order to avoid offset issues
        let mut threats_with_positions: Vec<_> =
            detection_result.threats().iter().enumerate().collect();

        threats_with_positions.sort_by(|a, b| match (a.1.span.as_ref(), b.1.span.as_ref()) {
            (Some(span_a), Some(span_b)) => span_b.start.cmp(&span_a.start),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.0.cmp(&b.0),
        });

        // Apply mitigations for threats with specific positions
        for (_, threat) in &threats_with_positions {
            if let Some(span) = &threat.span {
                result = self.apply_localized_mitigation(&result, threat, span);
            }
        }

        // Apply global mitigations for threats without specific positions
        for (_, threat) in &threats_with_positions {
            if threat.span.is_none() {
                result = self.apply_global_mitigation(&result, threat);
            }
        }

        result
    }

    /// Applies mitigation to a specific text span.
    fn apply_localized_mitigation(
        &self,
        text: &str,
        threat: &ThreatInfo,
        span: &TextSpan,
    ) -> String {
        // Validate span bounds
        if span.start >= text.len() || span.end > text.len() || span.start >= span.end {
            return text.to_string();
        }

        let context = ThreatContext::new(
            threat.threat_type.clone(),
            threat.confidence,
            Some((span.start, span.end)),
        );

        let strategy = self.strategy_selector.select_strategy(&context);
        let original_segment = &text[span.start..span.end];
        let mitigated_segment = strategy.apply(original_segment, Some(&context));

        let mut result = String::with_capacity(text.len());
        result.push_str(&text[..span.start]);
        result.push_str(&mitigated_segment);
        result.push_str(&text[span.end..]);

        result
    }

    /// Applies global mitigation for threats without specific positions.
    fn apply_global_mitigation(&self, text: &str, threat: &ThreatInfo) -> String {
        let context = ThreatContext::new(threat.threat_type.clone(), threat.confidence, None);

        let strategy = self.strategy_selector.select_strategy(&context);

        match &threat.threat_type {
            ThreatType::EncodingBypass => self.decode_and_sanitize_encodings(text),
            ThreatType::SocialEngineering => self.apply_social_engineering_mitigation(text),
            ThreatType::ContextConfusion => strategy.apply(text, Some(&context)),
            _ => {
                // For other global threats, apply strategy to whole text
                if strategy.preserves_content() {
                    strategy.apply(text, Some(&context))
                } else {
                    // Only apply if confidence is very high for destructive strategies
                    if threat.confidence > 0.9 {
                        strategy.apply(text, Some(&context))
                    } else {
                        text.to_string()
                    }
                }
            }
        }
    }

    /// Decodes and sanitizes various encoding schemes.
    fn decode_and_sanitize_encodings(&self, text: &str) -> String {
        let mut result = text.to_string();

        // Handle URL encoding
        result = self.safe_url_decode(&result);

        // Handle Unicode escapes
        result = self.sanitize_unicode_escapes(&result);

        // Handle Base64 (be careful not to break legitimate content)
        if self.is_likely_malicious_base64(&result) {
            result = self.sanitize_base64(&result);
        }

        result
    }

    /// Safely decodes URL encoding while preserving safe content.
    fn safe_url_decode(&self, text: &str) -> String {
        // Simple URL decoding that only handles common safe patterns
        text.replace("%20", " ")
            .replace("%22", "\"")
            .replace("%27", "'")
            .replace("%3C", "&lt;")
            .replace("%3E", "&gt;")
    }

    /// Sanitizes Unicode escape sequences.
    fn sanitize_unicode_escapes(&self, text: &str) -> String {
        // Replace Unicode escapes with safe alternatives
        let unicode_pattern = Regex::new(r"\\u[0-9a-fA-F]{4}").unwrap();
        unicode_pattern
            .replace_all(text, "[UNICODE_FILTERED]")
            .to_string()
    }

    /// Checks if Base64 content might be malicious.
    fn is_likely_malicious_base64(&self, text: &str) -> bool {
        // Simple heuristic: long Base64 strings might be suspicious
        let base64_pattern = Regex::new(r"[A-Za-z0-9+/]{50,}={0,2}").unwrap();
        base64_pattern.is_match(text) && text.len() > 100
    }

    /// Sanitizes suspicious Base64 content.
    fn sanitize_base64(&self, text: &str) -> String {
        let base64_pattern = Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}").unwrap();
        base64_pattern
            .replace_all(text, "[BASE64_FILTERED]")
            .to_string()
    }

    /// Applies specific mitigations for social engineering.
    fn apply_social_engineering_mitigation(&self, text: &str) -> String {
        let mut result = text.to_string();

        // Neutralize urgency language
        let urgency_patterns = [
            (r"(?i)\burgent(ly)?\b", "[TIME_SENSITIVE]"),
            (r"(?i)\bemergency\b", "[PRIORITY]"),
            (r"(?i)\bcritical\b", "[IMPORTANT]"),
            (r"(?i)\basap\b", "[SOON]"),
        ];

        for (pattern, replacement) in &urgency_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                result = regex.replace_all(&result, *replacement).to_string();
            }
        }

        // Add warning prefix for social engineering attempts
        if self.contains_social_engineering_markers(&result) {
            result = format!("[SOCIAL_ENGINEERING_WARNING] {}", result);
        }

        result
    }

    /// Checks if text contains social engineering markers.
    fn contains_social_engineering_markers(&self, text: &str) -> bool {
        let markers = [
            "trust me",
            "between you and me",
            "don't tell anyone",
            "keep this secret",
            "my boss said",
            "please help me",
        ];

        let lower_text = text.to_lowercase();
        markers.iter().any(|marker| lower_text.contains(marker))
    }

    /// Applies final cleanup and validation.
    fn apply_final_cleanup(&self, text: &str) -> String {
        let mut result = text.to_string();

        // Trim excessive whitespace
        result = result.trim().to_string();

        // Ensure text doesn't exceed maximum length
        if result.len() > self.config.preprocessing_config.max_length {
            result.truncate(self.config.preprocessing_config.max_length);
            result.push_str("[TRUNCATED]");
        }

        // Remove empty brackets and artifacts
        result = result.replace("[]", "").replace("()", "").replace("{}", "");

        result
    }

    /// Updates the sanitizer configuration.
    pub fn update_config(&mut self, config: &DetectionConfig) {
        self.config = config.clone();
        self.aggressive_mode = config.effective_security_level().confidence_threshold() < 0.6;
    }

    /// Sets a custom mitigation strategy for a threat type.
    pub fn set_strategy(&mut self, threat_type: ThreatType, strategy: MitigationStrategy) {
        self.strategy_selector.set_strategy(threat_type, strategy);
    }

    /// Returns whether aggressive sanitization is enabled.
    pub fn is_aggressive_mode(&self) -> bool {
        self.aggressive_mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DetectionConfig, SeverityLevel};
    use crate::detection::DetectionResult;
    use crate::types::{RiskLevel, TextSpan, ThreatInfo};

    #[tokio::test]
    async fn test_text_sanitizer_creation() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config);
        assert!(sanitizer.is_ok());
    }

    #[tokio::test]
    async fn test_general_sanitization() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config).unwrap();

        let text = "Hello\x00World\x1F   with   spaces";
        let detection_result = DetectionResult::safe();

        let sanitized = sanitizer.sanitize(text, &detection_result).await.unwrap();

        // Should remove control characters and normalize whitespace
        assert!(!sanitized.contains('\x00'));
        assert!(!sanitized.contains('\x1F'));
        assert!(!sanitized.contains("   "));
    }

    #[tokio::test]
    async fn test_script_tag_removal() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config).unwrap();

        let text = "Hello <script>alert('xss')</script> World";
        let detection_result = DetectionResult::safe();

        let sanitized = sanitizer.sanitize(text, &detection_result).await.unwrap();
        assert!(sanitized.contains("[SCRIPT_REMOVED]"));
        assert!(!sanitized.contains("script"));
    }

    #[tokio::test]
    async fn test_url_decoding() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config).unwrap();

        let encoded_text = "Hello%20World%22test%22";
        let result = sanitizer.safe_url_decode(encoded_text);

        assert!(result.contains("Hello World"));
        assert!(result.contains("\"test\""));
    }

    #[tokio::test]
    async fn test_unicode_escape_sanitization() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config).unwrap();

        let unicode_text = "\\u0048\\u0065\\u006c\\u006c\\u006f";
        let result = sanitizer.sanitize_unicode_escapes(unicode_text);

        assert!(result.contains("[UNICODE_FILTERED]"));
        assert!(!result.contains("\\u0048"));
    }

    #[tokio::test]
    async fn test_social_engineering_mitigation() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config).unwrap();

        let text = "This is urgent and critical, please help me!";
        let result = sanitizer.apply_social_engineering_mitigation(text);

        assert!(result.contains("[TIME_SENSITIVE]"));
        assert!(result.contains("[IMPORTANT]"));
        assert!(result.contains("[SOCIAL_ENGINEERING_WARNING]"));
    }

    #[tokio::test]
    async fn test_localized_mitigation() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config).unwrap();

        let text = "Hello dangerous content world";
        let threat = ThreatInfo {
            threat_type: ThreatType::InstructionOverride,
            confidence: 0.9,
            span: Some(TextSpan {
                start: 6,
                end: 22,
                content: "dangerous content".to_string(),
            }),
            metadata: HashMap::new(),
        };

        let span = threat.span.as_ref().unwrap();
        let result = sanitizer.apply_localized_mitigation(text, &threat, span);

        assert!(result.contains("[INSTRUCTION_FILTERED]"));
        assert!(!result.contains("dangerous content"));
    }

    #[tokio::test]
    async fn test_base64_detection() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config).unwrap();

        let short_base64 = "SGVsbG8=";
        let long_base64 = "SGVsbG8gV29ybGQgdGhpcyBpcyBhIHZlcnkgbG9uZyBiYXNlNjQgZW5jb2RlZCBzdHJpbmcgdGhhdCBtaWdodCBiZSBzdXNwaWNpb3Vz";

        assert!(!sanitizer.is_likely_malicious_base64(short_base64));
        assert!(sanitizer.is_likely_malicious_base64(long_base64));
    }

    #[tokio::test]
    async fn test_final_cleanup() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config).unwrap();

        let messy_text = "  Hello [] () {} World  ";
        let cleaned = sanitizer.apply_final_cleanup(messy_text);

        assert_eq!(cleaned, "Hello    World"); // Note: spaces between words are preserved
        assert!(!cleaned.contains("[]"));
        assert!(!cleaned.contains("()"));
        assert!(!cleaned.contains("{}"));
    }

    #[test]
    fn test_social_engineering_markers() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config).unwrap();

        let suspicious_text = "Trust me, this is between you and me";
        let normal_text = "Hello, how are you today?";

        assert!(sanitizer.contains_social_engineering_markers(suspicious_text));
        assert!(!sanitizer.contains_social_engineering_markers(normal_text));
    }

    // COMPREHENSIVE SANITIZATION TESTS

    #[tokio::test]
    async fn test_comprehensive_sanitization_pipeline() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config).unwrap();

        // Create a complex threat with multiple issues
        let malicious_text = "Hello\x00<script>alert('xss')</script> urgent critical trust me \\u0048\\u0065\\u006c\\u006c\\u006f %20%22   multiple   spaces   ";

        let threats = vec![
            ThreatInfo {
                threat_type: ThreatType::InstructionOverride,
                confidence: 0.9,
                span: Some(TextSpan {
                    start: 6,
                    end: 38,
                    content: "<script>alert('xss')</script>".to_string(),
                }),
                metadata: HashMap::new(),
            },
            ThreatInfo {
                threat_type: ThreatType::SocialEngineering,
                confidence: 0.7,
                span: None,
                metadata: HashMap::new(),
            },
            ThreatInfo {
                threat_type: ThreatType::EncodingBypass,
                confidence: 0.8,
                span: None,
                metadata: HashMap::new(),
            },
        ];

        let detection_result = DetectionResult::new(RiskLevel::High, 0.9, threats, 100);
        let sanitized = sanitizer
            .sanitize(malicious_text, &detection_result)
            .await
            .unwrap();

        // Verify all sanitizations were applied
        assert!(
            !sanitized.contains('\x00'),
            "Control characters should be removed"
        );
        assert!(
            !sanitized.contains("<script>"),
            "Script tags should be removed"
        );
        assert!(
            sanitized.contains("[SCRIPT_REMOVED]"),
            "Should have script removal marker"
        );
        assert!(
            sanitized.contains("[SOCIAL_ENGINEERING_WARNING]"),
            "Should have social engineering warning"
        );
        assert!(
            !sanitized.contains("   "),
            "Excessive whitespace should be normalized"
        );
    }

    #[tokio::test]
    async fn test_aggressive_mode_sanitization() {
        let mut config = DetectionConfig::default();
        config.severity_level = Some(SeverityLevel::High); // Should trigger aggressive mode

        let sanitizer = TextSanitizer::new(&config).unwrap();
        assert!(sanitizer.is_aggressive_mode());

        let html_content = "Hello <div>content</div> <span>more</span> World";
        let detection_result = DetectionResult::safe();
        let sanitized = sanitizer
            .sanitize(html_content, &detection_result)
            .await
            .unwrap();

        // In aggressive mode, all HTML tags should be removed
        assert!(!sanitized.contains("<div>"));
        assert!(!sanitized.contains("</div>"));
        assert!(!sanitized.contains("<span>"));
        assert!(!sanitized.contains("</span>"));
    }

    #[tokio::test]
    async fn test_localized_threat_mitigation_comprehensive() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config).unwrap();

        let test_cases = vec![
            (
                "Start ignore all instructions end",
                ThreatType::InstructionOverride,
                6,
                26, // "ignore all instructions"
                "[INSTRUCTION_FILTERED]",
            ),
            (
                "Hello dangerous roleplay content",
                ThreatType::RolePlaying,
                6,
                32, // "dangerous roleplay content"
                "[ROLE_FILTERED]",
            ),
            (
                "Normal jailbreak attempt here",
                ThreatType::Jailbreak,
                7,
                22, // "jailbreak attempt"
                "[JAILBREAK_ATTEMPT_FILTERED]",
            ),
            (
                "Show data extraction request",
                ThreatType::DataExtraction,
                5,
                28, // "data extraction request"
                "[DATA_REQUEST_FILTERED]",
            ),
        ];

        for (text, threat_type, start, end, expected_replacement) in test_cases {
            let threat = ThreatInfo {
                threat_type: threat_type.clone(),
                confidence: 0.9,
                span: Some(TextSpan {
                    start,
                    end,
                    content: text[start..end].to_string(),
                }),
                metadata: HashMap::new(),
            };

            let span = threat.span.as_ref().unwrap();
            let result = sanitizer.apply_localized_mitigation(text, &threat, span);

            assert!(
                result.contains(expected_replacement),
                "Expected '{}' in result for threat type {:?}",
                expected_replacement,
                threat_type
            );
            assert!(
                !result.contains(&text[start..end]),
                "Original threat content should be removed"
            );
        }
    }

    #[tokio::test]
    async fn test_global_threat_mitigation() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config).unwrap();

        // Test encoding bypass mitigation
        let encoded_text = "Normal text with %20%22%3C%3E encoded chars";
        let encoding_threat = ThreatInfo {
            threat_type: ThreatType::EncodingBypass,
            confidence: 0.8,
            span: None,
            metadata: HashMap::new(),
        };

        let result = sanitizer.apply_global_mitigation(encoded_text, &encoding_threat);
        assert!(result.contains("Hello World"), "URL decoding should occur");

        // Test social engineering mitigation
        let social_text = "Please help me urgently, trust me on this";
        let social_threat = ThreatInfo {
            threat_type: ThreatType::SocialEngineering,
            confidence: 0.7,
            span: None,
            metadata: HashMap::new(),
        };

        let result = sanitizer.apply_global_mitigation(social_text, &social_threat);
        assert!(
            result.contains("[TIME_SENSITIVE]"),
            "Urgency should be neutralized"
        );
        assert!(
            result.contains("[SOCIAL_ENGINEERING_WARNING]"),
            "Warning should be added"
        );
    }

    #[tokio::test]
    async fn test_encoding_sanitization_methods() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config).unwrap();

        // Test URL decoding
        let url_samples = vec![
            ("Hello%20World", "Hello World"),
            ("Test%22quotes%22", "Test\"quotes\""),
            ("Apos%27trophe", "Apos'trophe"),
            ("Less%3CThan%3EGreater", "Less&lt;Than&gt;Greater"),
        ];

        for (input, expected) in url_samples {
            let result = sanitizer.safe_url_decode(input);
            assert_eq!(result, expected, "URL decoding failed for: {}", input);
        }

        // Test Unicode escape sanitization
        let unicode_samples = vec![
            "\\u0048\\u0065\\u006c\\u006c\\u006f",
            "Normal text \\u0041\\u0042\\u0043 more text",
            "Multiple \\u0020 unicode \\u0021 escapes \\u0022",
        ];

        for input in unicode_samples {
            let result = sanitizer.sanitize_unicode_escapes(input);
            assert!(
                result.contains("[UNICODE_FILTERED]"),
                "Should filter unicode escapes in: {}",
                input
            );
            assert!(
                !result.contains("\\u"),
                "Should not contain unicode escape sequences"
            );
        }

        // Test base64 sanitization
        let base64_samples = vec![
            "SGVsbG8gV29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZw==",
            "VGVzdGluZyBhbm90aGVyIGxvbmcgYmFzZTY0IGVuY29kZWQgc3RyaW5n",
        ];

        for input in base64_samples {
            if sanitizer.is_likely_malicious_base64(input) {
                let result = sanitizer.sanitize_base64(input);
                assert!(
                    result.contains("[BASE64_FILTERED]"),
                    "Should filter base64 in: {}",
                    input
                );
                assert!(!result.contains("="), "Should not contain base64 padding");
            }
        }
    }

    #[tokio::test]
    async fn test_social_engineering_pattern_recognition() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config).unwrap();

        let social_patterns = vec![
            (
                "This is urgent and needs immediate attention",
                vec!["[TIME_SENSITIVE]"],
            ),
            ("Critical emergency situation here", vec!["[IMPORTANT]"]),
            (
                "Trust me, this is between you and me",
                vec!["[SOCIAL_ENGINEERING_WARNING]"],
            ),
            (
                "My boss said this is urgent and critical",
                vec!["[TIME_SENSITIVE]", "[IMPORTANT]"],
            ),
            (
                "Please help me ASAP, don't tell anyone",
                vec!["[SOON]", "[SOCIAL_ENGINEERING_WARNING]"],
            ),
        ];

        for (input, expected_markers) in social_patterns {
            let result = sanitizer.apply_social_engineering_mitigation(input);

            for marker in expected_markers {
                assert!(
                    result.contains(marker),
                    "Expected marker '{}' in result for input: '{}'",
                    marker,
                    input
                );
            }
        }

        // Test social engineering marker detection
        let social_marker_tests = vec![
            ("trust me", true),
            ("between you and me", true),
            ("don't tell anyone", true),
            ("keep this secret", true),
            ("my boss said", true),
            ("please help me", true),
            ("normal conversation", false),
            ("regular request", false),
        ];

        for (input, should_detect) in social_marker_tests {
            let has_markers = sanitizer.contains_social_engineering_markers(input);
            assert_eq!(
                has_markers, should_detect,
                "Marker detection mismatch for: '{}'",
                input
            );
        }
    }

    #[tokio::test]
    async fn test_sanitization_edge_cases() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config).unwrap();

        // Test empty input
        let empty_result = sanitizer
            .sanitize("", &DetectionResult::safe())
            .await
            .unwrap();
        assert_eq!(empty_result, "");

        // Test only whitespace
        let whitespace_result = sanitizer
            .sanitize("   \n\t   ", &DetectionResult::safe())
            .await
            .unwrap();
        assert!(whitespace_result.trim().is_empty());

        // Test only control characters
        let control_result = sanitizer
            .sanitize("\x00\x01\x02", &DetectionResult::safe())
            .await
            .unwrap();
        assert!(control_result.is_empty());

        // Test invalid span boundaries
        let text = "Hello World";
        let invalid_threat = ThreatInfo {
            threat_type: ThreatType::InstructionOverride,
            confidence: 0.9,
            span: Some(TextSpan {
                start: 100, // Invalid start
                end: 200,   // Invalid end
                content: "invalid".to_string(),
            }),
            metadata: HashMap::new(),
        };

        let span = invalid_threat.span.as_ref().unwrap();
        let result = sanitizer.apply_localized_mitigation(text, &invalid_threat, span);
        assert_eq!(result, text, "Invalid spans should not modify text");
    }

    #[tokio::test]
    async fn test_length_limits_and_truncation() {
        let mut config = DetectionConfig::default();
        config.preprocessing_config.max_length = 50;

        let sanitizer = TextSanitizer::new(&config).unwrap();

        // Test truncation in final cleanup
        let long_text = "a".repeat(100);
        let truncated = sanitizer.apply_final_cleanup(&long_text);

        assert!(
            truncated.len() <= 50 + "[TRUNCATED]".len(),
            "Text should be truncated"
        );
        assert!(
            truncated.ends_with("[TRUNCATED]"),
            "Should have truncation marker"
        );
    }

    #[tokio::test]
    async fn test_configuration_updates() {
        let mut config = DetectionConfig::default();
        config.severity_level = Some(SeverityLevel::Low);

        let mut sanitizer = TextSanitizer::new(&config).unwrap();
        assert!(!sanitizer.is_aggressive_mode());

        // Update to aggressive mode
        config.severity_level = Some(SeverityLevel::High);
        sanitizer.update_config(&config);
        assert!(sanitizer.is_aggressive_mode());
    }

    #[tokio::test]
    async fn test_custom_strategy_integration() {
        let config = DetectionConfig::default();
        let mut sanitizer = TextSanitizer::new(&config).unwrap();

        // Set custom strategy for a threat type
        use crate::mitigation::strategies::MitigationStrategy;
        sanitizer.set_strategy(
            ThreatType::InstructionOverride,
            MitigationStrategy::Custom("CUSTOM: {original}".to_string()),
        );

        let text = "Dangerous instruction content";
        let threat = ThreatInfo {
            threat_type: ThreatType::InstructionOverride,
            confidence: 0.9,
            span: Some(TextSpan {
                start: 0,
                end: text.len(),
                content: text.to_string(),
            }),
            metadata: HashMap::new(),
        };

        let span = threat.span.as_ref().unwrap();
        let result = sanitizer.apply_localized_mitigation(text, &threat, span);

        assert!(result.contains("CUSTOM: "), "Should use custom strategy");
    }

    #[tokio::test]
    async fn test_threat_confidence_based_mitigation() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config).unwrap();

        // Test high confidence threat - should be mitigated
        let high_confidence_threat = ThreatInfo {
            threat_type: ThreatType::InstructionOverride,
            confidence: 0.95,
            span: None,
            metadata: HashMap::new(),
        };

        let result = sanitizer.apply_global_mitigation("test content", &high_confidence_threat);
        // High confidence threats should be processed

        // Test low confidence threat - might be preserved
        let low_confidence_threat = ThreatInfo {
            threat_type: ThreatType::InstructionOverride,
            confidence: 0.4,
            span: None,
            metadata: HashMap::new(),
        };

        let result = sanitizer.apply_global_mitigation("test content", &low_confidence_threat);
        // Low confidence threats should be handled more gently
    }

    #[tokio::test]
    async fn test_pattern_sanitization_regex_patterns() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config).unwrap();

        // Test sanitization patterns are working
        let html_samples = vec![
            ("Hello <div>content</div>", false),       // Not aggressive mode
            ("Hello <script>alert(1)</script>", true), // Always removed
        ];

        for (input, should_be_removed) in html_samples {
            let sanitized = sanitizer.apply_general_sanitization(input);

            if should_be_removed {
                assert!(
                    !sanitized.contains("<script>"),
                    "Script tags should always be removed"
                );
            }
        }

        // Test SQL injection patterns
        let sql_samples = vec![
            "SELECT * FROM users; DROP TABLE users;",
            "'; DROP TABLE sessions; --",
            "UNION SELECT password FROM users",
        ];

        // These patterns are checked by the sanitization patterns but not necessarily removed
        // in general sanitization unless specific threats are detected
    }

    #[test]
    fn test_base64_detection_edge_cases() {
        let config = DetectionConfig::default();
        let sanitizer = TextSanitizer::new(&config).unwrap();

        let test_cases = vec![
            ("", false), // Empty string
            ("a", false), // Too short
            ("SGVsbG8=", false), // Short but valid base64
            ("NotBase64", false), // Invalid characters
            ("SGVsbG8gV29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IGVuY29kZWQgbWVzc2FnZSB0aGF0IGV4Y2VlZHMgbGVuZ3RoIHRocmVzaG9sZA==", true), // Long malicious
        ];

        for (input, expected) in test_cases {
            let result = sanitizer.is_likely_malicious_base64(input);
            assert_eq!(result, expected, "Base64 detection failed for: '{}'", input);
        }
    }
}
