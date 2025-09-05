//! Core types and data structures for FluxPrompt.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

use crate::detection::DetectionResult;

/// Risk levels for prompt injection detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum RiskLevel {
    /// No risk detected
    #[default]
    None = 0,
    /// Low risk - suspicious patterns but likely benign
    Low = 1,
    /// Medium risk - potential injection attempt
    Medium = 2,
    /// High risk - likely injection attempt
    High = 3,
    /// Critical risk - definite injection attempt
    Critical = 4,
}

impl RiskLevel {
    /// Returns true if the risk level indicates an injection attempt.
    pub fn is_injection(&self) -> bool {
        matches!(
            self,
            RiskLevel::Medium | RiskLevel::High | RiskLevel::Critical
        )
    }

    /// Returns the numeric value of the risk level.
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::None => write!(f, "None"),
            RiskLevel::Low => write!(f, "Low"),
            RiskLevel::Medium => write!(f, "Medium"),
            RiskLevel::High => write!(f, "High"),
            RiskLevel::Critical => write!(f, "Critical"),
        }
    }
}

/// Types of threats that can be detected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatType {
    /// Direct instruction override attempt
    InstructionOverride,
    /// Role playing attack
    RolePlaying,
    /// Context confusion attack
    ContextConfusion,
    /// Encoding bypass attempt
    EncodingBypass,
    /// Jailbreak pattern
    Jailbreak,
    /// Social engineering attempt
    SocialEngineering,
    /// Data extraction attempt
    DataExtraction,
    /// System prompt leak attempt
    SystemPromptLeak,
    /// Code injection attempt
    CodeInjection,
    /// Custom threat pattern
    Custom(String),
}

impl ThreatType {
    /// Returns a human-readable description of the threat type.
    pub fn description(&self) -> &str {
        match self {
            ThreatType::InstructionOverride => "Direct instruction override attempt",
            ThreatType::RolePlaying => "Role playing attack",
            ThreatType::ContextConfusion => "Context confusion attack",
            ThreatType::EncodingBypass => "Encoding bypass attempt",
            ThreatType::Jailbreak => "Jailbreak pattern",
            ThreatType::SocialEngineering => "Social engineering attempt",
            ThreatType::DataExtraction => "Data extraction attempt",
            ThreatType::SystemPromptLeak => "System prompt leak attempt",
            ThreatType::CodeInjection => "Code injection attempt",
            ThreatType::Custom(name) => name,
        }
    }

    /// Returns the severity weight for this threat type.
    pub fn severity_weight(&self) -> f32 {
        match self {
            ThreatType::InstructionOverride => 0.9,
            ThreatType::RolePlaying => 0.7,
            ThreatType::ContextConfusion => 0.8,
            ThreatType::EncodingBypass => 0.6,
            ThreatType::Jailbreak => 0.95,
            ThreatType::SocialEngineering => 0.5,
            ThreatType::DataExtraction => 0.85,
            ThreatType::SystemPromptLeak => 0.9,
            ThreatType::CodeInjection => 0.95,
            ThreatType::Custom(_) => 0.5,
        }
    }
}

impl std::fmt::Display for ThreatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// Detailed information about a detected threat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInfo {
    /// Type of threat detected
    pub threat_type: ThreatType,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f32,
    /// Text span where the threat was detected
    pub span: Option<TextSpan>,
    /// Additional metadata about the threat
    pub metadata: HashMap<String, String>,
}

/// Text span indicating location of detected content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextSpan {
    /// Start position in the text
    pub start: usize,
    /// End position in the text
    pub end: usize,
    /// The actual text content
    pub content: String,
}

impl TextSpan {
    /// Creates a new text span.
    pub fn new(start: usize, end: usize, content: String) -> Self {
        Self {
            start,
            end,
            content,
        }
    }

    /// Returns the length of the span.
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Returns true if the span is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ThreatInfo {
    /// Creates a new threat info.
    pub fn new(threat_type: ThreatType, confidence: f32, span: Option<TextSpan>) -> Self {
        Self {
            threat_type,
            confidence,
            span,
            metadata: HashMap::new(),
        }
    }

    /// Adds metadata to this threat.
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Returns true if this threat has a high confidence score.
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.8
    }

    /// Returns the severity level of this threat.
    pub fn severity_level(&self) -> &str {
        match self.confidence {
            f if f >= 0.9 => "Critical",
            f if f >= 0.7 => "High",
            f if f >= 0.5 => "Medium",
            f if f >= 0.3 => "Low",
            _ => "Very Low",
        }
    }
}

/// Complete analysis result for a prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptAnalysis {
    /// Unique identifier for this analysis
    pub id: Uuid,
    /// Timestamp when analysis was performed
    pub timestamp: SystemTime,
    /// Duration of the analysis
    pub analysis_duration: Duration,
    /// The detection result
    pub detection_result: DetectionResult,
    /// Mitigated version of the prompt (if applicable)
    pub mitigated_prompt: Option<String>,
    /// Additional analysis metadata
    pub metadata: HashMap<String, String>,
}

impl PromptAnalysis {
    /// Creates a new prompt analysis.
    pub fn new(detection_result: DetectionResult, mitigated_prompt: Option<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: SystemTime::now(),
            analysis_duration: Duration::from_millis(0), // Will be set by the analyzer
            detection_result,
            mitigated_prompt,
            metadata: HashMap::new(),
        }
    }

    /// Returns the detection result.
    pub fn detection_result(&self) -> &DetectionResult {
        &self.detection_result
    }

    /// Returns the mitigated prompt if available.
    pub fn mitigated_prompt(&self) -> Option<&str> {
        self.mitigated_prompt.as_deref()
    }

    /// Returns true if an injection was detected.
    pub fn is_injection_detected(&self) -> bool {
        self.detection_result.is_injection_detected()
    }

    /// Returns the risk level of the analysis.
    pub fn risk_level(&self) -> RiskLevel {
        self.detection_result.risk_level()
    }

    /// Returns detected threat types.
    pub fn threat_types(&self) -> Vec<&ThreatType> {
        self.detection_result
            .threats()
            .iter()
            .map(|t| &t.threat_type)
            .collect()
    }

    /// Adds metadata to the analysis.
    pub fn add_metadata<K: Into<String>, V: Into<String>>(&mut self, key: K, value: V) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Sets the analysis duration.
    pub fn set_duration(&mut self, duration: Duration) {
        self.analysis_duration = duration;
    }
}

/// Configuration for text preprocessing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreprocessingConfig {
    /// Whether to normalize unicode characters
    pub normalize_unicode: bool,
    /// Whether to decode common encodings
    pub decode_encodings: bool,
    /// Maximum text length to analyze
    pub max_length: usize,
    /// Whether to preserve original formatting
    pub preserve_formatting: bool,
}

impl Default for PreprocessingConfig {
    fn default() -> Self {
        Self {
            normalize_unicode: true,
            decode_encodings: true,
            max_length: 10_000,
            preserve_formatting: false,
        }
    }
}

/// Statistics about detection performance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionStats {
    /// Total number of prompts analyzed
    pub total_analyzed: u64,
    /// Number of injections detected
    pub injections_detected: u64,
    /// Average analysis time in milliseconds
    pub avg_analysis_time_ms: f64,
    /// Detection accuracy (if known)
    pub accuracy: Option<f32>,
    /// False positive rate (if known)
    pub false_positive_rate: Option<f32>,
}

impl Default for DetectionStats {
    fn default() -> Self {
        Self {
            total_analyzed: 0,
            injections_detected: 0,
            avg_analysis_time_ms: 0.0,
            accuracy: None,
            false_positive_rate: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Critical > RiskLevel::High);
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert!(RiskLevel::Medium > RiskLevel::Low);
        assert!(RiskLevel::Low > RiskLevel::None);
    }

    #[test]
    fn test_risk_level_injection_detection() {
        assert!(!RiskLevel::None.is_injection());
        assert!(!RiskLevel::Low.is_injection());
        assert!(RiskLevel::Medium.is_injection());
        assert!(RiskLevel::High.is_injection());
        assert!(RiskLevel::Critical.is_injection());
    }

    #[test]
    fn test_threat_type_severity() {
        assert!(
            ThreatType::Jailbreak.severity_weight()
                > ThreatType::SocialEngineering.severity_weight()
        );
        assert!(
            ThreatType::CodeInjection.severity_weight()
                > ThreatType::EncodingBypass.severity_weight()
        );
    }

    #[test]
    fn test_prompt_analysis_creation() {
        use crate::detection::DetectionResult;

        let detection_result = DetectionResult::safe();
        let analysis = PromptAnalysis::new(detection_result, None);

        assert!(!analysis.is_injection_detected());
        assert_eq!(analysis.risk_level(), RiskLevel::None);
    }
}
