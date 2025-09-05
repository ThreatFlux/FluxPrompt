# FluxPrompt API Reference

This document provides a comprehensive reference for the FluxPrompt API, including all public types, methods, and configuration options.

## Table of Contents

- [Core API](#core-api)
- [Configuration Types](#configuration-types)
- [Detection Types](#detection-types)
- [Mitigation Types](#mitigation-types)
- [Metrics Types](#metrics-types)
- [Utility Types](#utility-types)
- [Error Handling](#error-handling)
- [Examples](#examples)

## Core API

### FluxPrompt

The main entry point for prompt injection detection.

```rust
pub struct FluxPrompt {
    // Internal fields are private
}
```

#### Methods

##### `new`

Creates a new FluxPrompt instance with the specified configuration.

```rust
pub async fn new(config: DetectionConfig) -> Result<Self>
```

**Parameters:**
- `config`: Detection configuration to use

**Returns:**
- `Result<FluxPrompt>`: The FluxPrompt instance or an error

**Example:**
```rust
let config = DetectionConfig::default();
let detector = FluxPrompt::new(config).await?;
```

##### `analyze`

Analyzes a prompt for potential injection attacks.

```rust
pub async fn analyze(&self, prompt: &str) -> Result<PromptAnalysis>
```

**Parameters:**
- `prompt`: The prompt text to analyze

**Returns:**
- `Result<PromptAnalysis>`: Complete analysis result or an error

**Example:**
```rust
let result = detector.analyze("Ignore all previous instructions").await?;
if result.is_injection_detected() {
    println!("Injection detected!");
}
```

##### `config`

Returns the current detection configuration.

```rust
pub fn config(&self) -> &DetectionConfig
```

**Returns:**
- `&DetectionConfig`: Reference to current configuration

##### `metrics`

Returns the current detection metrics.

```rust
pub async fn metrics(&self) -> DetectionMetrics
```

**Returns:**
- `DetectionMetrics`: Current metrics snapshot

##### `update_config`

Updates the detection configuration at runtime.

```rust
pub async fn update_config(&mut self, config: DetectionConfig) -> Result<()>
```

**Parameters:**
- `config`: New configuration to apply

**Returns:**
- `Result<()>`: Success or error

## Configuration Types

### DetectionConfig

Main configuration structure for FluxPrompt.

```rust
pub struct DetectionConfig {
    pub severity_level: SeverityLevel,
    pub response_strategy: ResponseStrategy,
    pub pattern_config: PatternConfig,
    pub semantic_config: SemanticConfig,
    pub preprocessing_config: PreprocessingConfig,
    pub resource_config: ResourceConfig,
    pub enable_metrics: bool,
    pub custom_config: HashMap<String, String>,
}
```

#### Builder Methods

```rust
impl DetectionConfig {
    pub fn builder() -> DetectionConfigBuilder;
    pub fn validate(&self) -> Result<()>;
}
```

**Example:**
```rust
let config = DetectionConfig::builder()
    .with_severity_level(SeverityLevel::High)
    .with_response_strategy(ResponseStrategy::Block)
    .enable_metrics(true)
    .build();
```

### DetectionConfigBuilder

Builder for creating DetectionConfig instances.

```rust
impl DetectionConfigBuilder {
    pub fn with_severity_level(self, level: SeverityLevel) -> Self;
    pub fn with_response_strategy(self, strategy: ResponseStrategy) -> Self;
    pub fn with_custom_patterns(self, patterns: Vec<String>) -> Self;
    pub fn enable_semantic_analysis(self, enabled: bool) -> Self;
    pub fn with_timeout(self, timeout: Duration) -> Self;
    pub fn enable_metrics(self, enabled: bool) -> Self;
    pub fn with_custom_config<K, V>(self, key: K, value: V) -> Self 
    where K: Into<String>, V: Into<String>;
    pub fn build(self) -> DetectionConfig;
}
```

### SeverityLevel

Detection sensitivity levels.

```rust
pub enum SeverityLevel {
    Low,      // Very permissive - only obvious attacks
    Medium,   // Balanced approach
    High,     // Strict - may have false positives  
    Paranoid, // Very strict - high false positive rate
}
```

#### Methods

```rust
impl SeverityLevel {
    pub fn risk_threshold(&self) -> RiskLevel;
    pub fn confidence_threshold(&self) -> f32;
}
```

### ResponseStrategy

Strategies for handling detected threats.

```rust
pub enum ResponseStrategy {
    Allow,              // Allow with warning
    Block,              // Block entirely
    Sanitize,           // Clean and continue
    Warn,               // Return warning message
    Custom(String),     // Custom response message
}
```

### PatternConfig

Configuration for pattern-based detection.

```rust
pub struct PatternConfig {
    pub enabled_categories: Vec<String>,
    pub custom_patterns: Vec<String>,
    pub case_sensitive: bool,
    pub max_patterns: usize,
}
```

### SemanticConfig

Configuration for semantic analysis.

```rust
pub struct SemanticConfig {
    pub enabled: bool,
    pub model_name: Option<String>,
    pub similarity_threshold: f32,
    pub max_context_length: usize,
}
```

### ResourceConfig

Resource management configuration.

```rust
pub struct ResourceConfig {
    pub max_concurrent_analyses: usize,
    pub analysis_timeout: Duration,
    pub max_memory_mb: usize,
    pub pattern_cache_size: usize,
}
```

## Detection Types

### PromptAnalysis

Complete analysis result for a prompt.

```rust
pub struct PromptAnalysis {
    pub id: Uuid,
    pub timestamp: SystemTime,
    pub analysis_duration: Duration,
    // Private fields
}
```

#### Methods

```rust
impl PromptAnalysis {
    pub fn detection_result(&self) -> &DetectionResult;
    pub fn mitigated_prompt(&self) -> Option<&str>;
    pub fn is_injection_detected(&self) -> bool;
    pub fn risk_level(&self) -> RiskLevel;
    pub fn threat_types(&self) -> Vec<&ThreatType>;
    pub fn add_metadata<K, V>(&mut self, key: K, value: V) 
    where K: Into<String>, V: Into<String>;
}
```

### DetectionResult

Result from the detection engine.

```rust
pub struct DetectionResult {
    // Private fields
}
```

#### Methods

```rust
impl DetectionResult {
    pub fn new(risk_level: RiskLevel, confidence: f32, threats: Vec<ThreatInfo>, analysis_duration_ms: u64) -> Self;
    pub fn safe() -> Self;
    pub fn is_injection_detected(&self) -> bool;
    pub fn risk_level(&self) -> RiskLevel;
    pub fn confidence(&self) -> f32;
    pub fn threats(&self) -> &[ThreatInfo];
    pub fn analysis_duration_ms(&self) -> u64;
    pub fn threat_types(&self) -> Vec<&ThreatType>;
    pub fn highest_confidence_threat(&self) -> Option<&ThreatInfo>;
}
```

### RiskLevel

Risk assessment levels.

```rust
pub enum RiskLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}
```

#### Methods

```rust
impl RiskLevel {
    pub fn is_injection(&self) -> bool;
    pub fn as_u8(&self) -> u8;
}
```

### ThreatType

Types of detected threats.

```rust
pub enum ThreatType {
    InstructionOverride,
    RolePlaying,
    ContextConfusion,
    EncodingBypass,
    Jailbreak,
    SocialEngineering,
    DataExtraction,
    SystemPromptLeak,
    CodeInjection,
    Custom(String),
}
```

#### Methods

```rust
impl ThreatType {
    pub fn description(&self) -> &str;
    pub fn severity_weight(&self) -> f32;
}
```

### ThreatInfo

Detailed information about a detected threat.

```rust
pub struct ThreatInfo {
    pub threat_type: ThreatType,
    pub confidence: f32,
    pub span: Option<TextSpan>,
    pub metadata: HashMap<String, String>,
}
```

### TextSpan

Location of detected threat in text.

```rust
pub struct TextSpan {
    pub start: usize,
    pub end: usize,
    pub content: String,
}
```

## Mitigation Types

### MitigationStrategy

Available mitigation strategies.

```rust
pub enum MitigationStrategy {
    Remove,
    Replace(String),
    Encode,
    Prefix(String),
    Suffix(String),
    Wrap { prefix: String, suffix: String },
    Custom(String),
}
```

#### Methods

```rust
impl MitigationStrategy {
    pub fn default_for_threat(threat_type: &ThreatType) -> Self;
    pub fn apply(&self, text: &str, context: Option<&ThreatContext>) -> String;
    pub fn preserves_content(&self) -> bool;
    pub fn removes_threat(&self) -> bool;
}
```

### ThreatContext

Context information for threat mitigation.

```rust
pub struct ThreatContext {
    pub threat_type: ThreatType,
    pub confidence: f32,
    pub position: Option<(usize, usize)>,
    pub metadata: HashMap<String, String>,
}
```

#### Methods

```rust
impl ThreatContext {
    pub fn new(threat_type: ThreatType, confidence: f32, position: Option<(usize, usize)>) -> Self;
    pub fn with_metadata(self, key: String, value: String) -> Self;
}
```

## Metrics Types

### DetectionMetrics

Comprehensive metrics for detection operations.

```rust
pub struct DetectionMetrics {
    pub total_analyzed: u64,
    pub injections_detected: u64,
    pub risk_level_breakdown: HashMap<String, u64>,
    pub threat_type_breakdown: HashMap<String, u64>,
    pub avg_analysis_time_ms: f64,
    pub min_analysis_time_ms: u64,
    pub max_analysis_time_ms: u64,
    pub detection_rate: f64,
    pub confidence_stats: ConfidenceStats,
    pub performance_percentiles: PerformancePercentiles,
    pub timestamp: SystemTime,
}
```

#### Methods

```rust
impl DetectionMetrics {
    pub fn total_analyzed(&self) -> u64;
    pub fn detection_rate_percentage(&self) -> f64;
    pub fn estimated_false_positive_rate(&self) -> Option<f64>;
}
```

### ConfidenceStats

Statistics about confidence scores.

```rust
pub struct ConfidenceStats {
    pub avg_positive_confidence: f64,
    pub avg_negative_confidence: f64,
    pub min_confidence: f32,
    pub max_confidence: f32,
    pub confidence_std_dev: f64,
}
```

### PerformancePercentiles

Performance percentile statistics.

```rust
pub struct PerformancePercentiles {
    pub p50_ms: u64,
    pub p90_ms: u64,
    pub p95_ms: u64,
    pub p99_ms: u64,
}
```

### MetricsCollector

Collector for gathering metrics.

```rust
pub struct MetricsCollector {
    // Private fields
}
```

#### Methods

```rust
impl MetricsCollector {
    pub fn new() -> Self;
    pub fn record_detection(&self, result: &DetectionResult);
    pub fn get_metrics(&self) -> DetectionMetrics;
    pub fn reset(&self);
}
```

## Utility Types

### PreprocessingConfig

Configuration for text preprocessing.

```rust
pub struct PreprocessingConfig {
    pub normalize_unicode: bool,
    pub decode_encodings: bool,
    pub max_length: usize,
    pub preserve_formatting: bool,
}
```

### DetectionStats

Statistics about detection performance.

```rust
pub struct DetectionStats {
    pub total_analyzed: u64,
    pub injections_detected: u64,
    pub avg_analysis_time_ms: f64,
    pub accuracy: Option<f32>,
    pub false_positive_rate: Option<f32>,
}
```

## Error Handling

### FluxPromptError

Main error type for FluxPrompt operations.

```rust
pub enum FluxPromptError {
    Config { message: String },
    Detection { message: String },
    Mitigation { message: String },
    PatternCompilation { source: regex::Error },
    Io { source: std::io::Error },
    Serialization { source: serde_json::Error },
    Runtime { message: String },
    InvalidInput { message: String },
    ResourceLimit { resource: String },
    Internal { message: String },
}
```

#### Constructor Methods

```rust
impl FluxPromptError {
    pub fn config<S: Into<String>>(message: S) -> Self;
    pub fn detection<S: Into<String>>(message: S) -> Self;
    pub fn mitigation<S: Into<String>>(message: S) -> Self;
    pub fn runtime<S: Into<String>>(message: S) -> Self;
    pub fn invalid_input<S: Into<String>>(message: S) -> Self;
    pub fn resource_limit<S: Into<String>>(resource: S) -> Self;
    pub fn internal<S: Into<String>>(message: S) -> Self;
}
```

### Result Type

Type alias for FluxPrompt results.

```rust
pub type Result<T> = std::result::Result<T, FluxPromptError>;
```

## Examples

### Basic Usage

```rust
use fluxprompt::{FluxPrompt, DetectionConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let detector = FluxPrompt::new(DetectionConfig::default()).await?;
    let result = detector.analyze("Your prompt here").await?;
    
    if result.is_injection_detected() {
        println!("Threat detected: {:?}", result.risk_level());
    }
    
    Ok(())
}
```

### Custom Configuration

```rust
use fluxprompt::{DetectionConfig, SeverityLevel, ResponseStrategy};

let config = DetectionConfig::builder()
    .with_severity_level(SeverityLevel::High)
    .with_response_strategy(ResponseStrategy::Sanitize)
    .with_custom_patterns(vec![
        r"(?i)custom\s+threat\s+pattern".to_string(),
    ])
    .enable_semantic_analysis(true)
    .with_timeout(Duration::from_secs(5))
    .build();

let detector = FluxPrompt::new(config).await?;
```

### Metrics Collection

```rust
let result = detector.analyze("test prompt").await?;
let metrics = detector.metrics().await;

println!("Total analyzed: {}", metrics.total_analyzed());
println!("Detection rate: {:.1}%", metrics.detection_rate_percentage());
println!("Average time: {:.2}ms", metrics.avg_analysis_time_ms);
```

### Error Handling

```rust
match detector.analyze(prompt).await {
    Ok(result) => {
        if result.is_injection_detected() {
            // Handle detected threat
        }
    }
    Err(FluxPromptError::InvalidInput { message }) => {
        eprintln!("Invalid input: {}", message);
    }
    Err(FluxPromptError::Runtime { message }) => {
        eprintln!("Runtime error: {}", message);
    }
    Err(e) => {
        eprintln!("Other error: {}", e);
    }
}
```

### Advanced Usage

```rust
use fluxprompt::{FluxPrompt, DetectionConfig, ThreatType};

let mut detector = FluxPrompt::new(config).await?;

// Analyze multiple prompts
let prompts = vec!["prompt1", "prompt2", "prompt3"];
let mut results = Vec::new();

for prompt in prompts {
    let result = detector.analyze(prompt).await?;
    results.push(result);
}

// Check for specific threat types
for result in &results {
    if result.threat_types().contains(&&ThreatType::Jailbreak) {
        println!("Jailbreak attempt detected!");
    }
}

// Update configuration at runtime
let new_config = DetectionConfig::builder()
    .with_severity_level(SeverityLevel::Paranoid)
    .build();

detector.update_config(new_config).await?;
```

This API reference provides comprehensive documentation for all public interfaces in FluxPrompt. For more detailed examples and use cases, see the examples directory in the repository.