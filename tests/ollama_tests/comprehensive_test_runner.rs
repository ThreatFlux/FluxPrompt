//! Comprehensive Test Runner for FluxPrompt + Ollama Integration
//!
//! This test runner evaluates the effectiveness of FluxPrompt in protecting
//! Ollama-based LLM interactions. It tests detection accuracy, response latency,
//! and overall security posture against a comprehensive set of attack vectors.

use fluxprompt::{DetectionConfig, FluxPrompt, ResponseStrategy, SeverityLevel};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{error, info, warn};

// Include the secure gateway from the example
include!("../../examples/ollama_integration.rs");

/// Test prompt structure from JSON files
#[derive(Debug, Deserialize, Clone)]
struct TestPrompt {
    prompt: String,
    description: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    expected_safe: bool,
}

/// Test category structure
#[derive(Debug, Deserialize)]
struct TestCategory {
    category: String,
    prompts: Vec<TestPrompt>,
}

/// Attack prompts file structure
#[derive(Debug, Deserialize)]
struct AttackPromptsFile {
    attack_prompts: Vec<TestCategory>,
}

/// Benign prompts file structure
#[derive(Debug, Deserialize)]
struct BenignPromptsFile {
    benign_prompts: Vec<TestCategory>,
}

/// Individual test result
#[derive(Debug, Clone)]
struct TestResult {
    prompt: String,
    category: String,
    description: String,
    expected_malicious: bool,
    detected_as_malicious: bool,
    blocked: bool,
    sanitized: bool,
    detection_time_ms: u64,
    llm_response_time_ms: u64,
    total_time_ms: u64,
    threats_detected: Vec<String>,
    blocking_reasons: Vec<String>,
    severity: String,
}

impl TestResult {
    /// Check if the test result is correct
    fn is_correct_detection(&self) -> bool {
        self.expected_malicious == self.detected_as_malicious
    }

    /// Check if this is a false positive
    fn is_false_positive(&self) -> bool {
        !self.expected_malicious && self.detected_as_malicious
    }

    /// Check if this is a false negative
    fn is_false_negative(&self) -> bool {
        self.expected_malicious && !self.detected_as_malicious
    }
}

/// Comprehensive test suite results
#[derive(Debug)]
struct TestSuiteResults {
    results: Vec<TestResult>,
    total_tests: usize,
    correct_detections: usize,
    false_positives: usize,
    false_negatives: usize,
    total_attack_prompts: usize,
    detected_attacks: usize,
    total_benign_prompts: usize,
    incorrectly_flagged_benign: usize,
    avg_detection_time_ms: f64,
    avg_total_time_ms: f64,
    models_tested: Vec<String>,
}

impl TestSuiteResults {
    fn new(results: Vec<TestResult>, models: Vec<String>) -> Self {
        let total_tests = results.len();
        let correct_detections = results.iter().filter(|r| r.is_correct_detection()).count();
        let false_positives = results.iter().filter(|r| r.is_false_positive()).count();
        let false_negatives = results.iter().filter(|r| r.is_false_negative()).count();

        let total_attack_prompts = results.iter().filter(|r| r.expected_malicious).count();
        let detected_attacks = results.iter()
            .filter(|r| r.expected_malicious && r.detected_as_malicious)
            .count();

        let total_benign_prompts = results.iter().filter(|r| !r.expected_malicious).count();
        let incorrectly_flagged_benign = results.iter()
            .filter(|r| !r.expected_malicious && r.detected_as_malicious)
            .count();

        let avg_detection_time_ms = if total_tests > 0 {
            results.iter().map(|r| r.detection_time_ms).sum::<u64>() as f64 / total_tests as f64
        } else {
            0.0
        };

        let avg_total_time_ms = if total_tests > 0 {
            results.iter().map(|r| r.total_time_ms).sum::<u64>() as f64 / total_tests as f64
        } else {
            0.0
        };

        Self {
            results,
            total_tests,
            correct_detections,
            false_positives,
            false_negatives,
            total_attack_prompts,
            detected_attacks,
            total_benign_prompts,
            incorrectly_flagged_benign,
            avg_detection_time_ms,
            avg_total_time_ms,
            models_tested: models,
        }
    }

    /// Calculate accuracy percentage
    fn accuracy_percentage(&self) -> f64 {
        if self.total_tests == 0 {
            0.0
        } else {
            (self.correct_detections as f64 / self.total_tests as f64) * 100.0
        }
    }

    /// Calculate precision (of detected attacks, how many were actually malicious)
    fn precision_percentage(&self) -> f64 {
        let total_detected = self.detected_attacks + self.incorrectly_flagged_benign;
        if total_detected == 0 {
            0.0
        } else {
            (self.detected_attacks as f64 / total_detected as f64) * 100.0
        }
    }

    /// Calculate recall (of actual attacks, how many were detected)
    fn recall_percentage(&self) -> f64 {
        if self.total_attack_prompts == 0 {
            0.0
        } else {
            (self.detected_attacks as f64 / self.total_attack_prompts as f64) * 100.0
        }
    }

    /// Calculate F1 score
    fn f1_score(&self) -> f64 {
        let precision = self.precision_percentage() / 100.0;
        let recall = self.recall_percentage() / 100.0;

        if precision + recall == 0.0 {
            0.0
        } else {
            2.0 * (precision * recall) / (precision + recall)
        }
    }
}

/// Comprehensive test runner
pub struct ComprehensiveTestRunner {
    gateway: SecureLLMGateway,
    models: Vec<String>,
}

impl ComprehensiveTestRunner {
    /// Create a new test runner
    pub async fn new(models: Vec<String>) -> Result<Self, Box<dyn std::error::Error>> {
        let config = SecureLLMConfig::default();
        let gateway = SecureLLMGateway::new(config).await?;

        Ok(Self {
            gateway,
            models,
        })
    }

    /// Load attack prompts from JSON file
    fn load_attack_prompts(&self) -> Result<Vec<TestPrompt>, Box<dyn std::error::Error>> {
        let file_content = fs::read_to_string("tests/ollama_tests/attack_prompts.json")?;
        let attack_file: AttackPromptsFile = serde_json::from_str(&file_content)?;

        let mut all_prompts = Vec::new();
        for category in attack_file.attack_prompts {
            for mut prompt in category.prompts {
                prompt.severity = if prompt.severity.is_empty() {
                    "medium".to_string()
                } else {
                    prompt.severity
                };
                all_prompts.push(prompt);
            }
        }

        Ok(all_prompts)
    }

    /// Load benign prompts from JSON file
    fn load_benign_prompts(&self) -> Result<Vec<TestPrompt>, Box<dyn std::error::Error>> {
        let file_content = fs::read_to_string("tests/ollama_tests/benign_prompts.json")?;
        let benign_file: BenignPromptsFile = serde_json::from_str(&file_content)?;

        let mut all_prompts = Vec::new();
        for category in benign_file.benign_prompts {
            for prompt in category.prompts {
                all_prompts.push(prompt);
            }
        }

        Ok(all_prompts)
    }

    /// Run a single test
    async fn run_single_test(
        &self,
        prompt: &TestPrompt,
        model: &str,
        category: &str,
        expected_malicious: bool,
    ) -> Result<TestResult, Box<dyn std::error::Error>> {
        let start_time = Instant::now();

        // Process the prompt through the secure gateway
        let result = self.gateway.process_prompt(&prompt.prompt, Some(model)).await?;

        let total_time = start_time.elapsed().as_millis() as u64;

        // Extract threat information
        let threats_detected = if result.prompt_was_malicious {
            result.blocked_reasons.clone()
        } else {
            Vec::new()
        };

        Ok(TestResult {
            prompt: prompt.prompt.clone(),
            category: category.to_string(),
            description: prompt.description.clone(),
            expected_malicious,
            detected_as_malicious: result.prompt_was_malicious,
            blocked: result.llm_response.is_none(),
            sanitized: result.sanitized_prompt.is_some(),
            detection_time_ms: result.detection_time_ms,
            llm_response_time_ms: result.llm_response_time_ms,
            total_time_ms: total_time,
            threats_detected,
            blocking_reasons: result.blocked_reasons,
            severity: prompt.severity.clone(),
        })
    }

    /// Run comprehensive test suite
    pub async fn run_comprehensive_tests(&self) -> Result<TestSuiteResults, Box<dyn std::error::Error>> {
        println!("🚀 Starting Comprehensive FluxPrompt + Ollama Test Suite");
        println!("========================================================\n");

        // Load test data
        println!("📥 Loading test data...");
        let attack_prompts = self.load_attack_prompts()?;
        let benign_prompts = self.load_benign_prompts()?;

        println!("   Attack prompts loaded: {}", attack_prompts.len());
        println!("   Benign prompts loaded: {}", benign_prompts.len());
        println!("   Models to test: {:?}\n", self.models);

        let mut all_results = Vec::new();
        let total_tests = (attack_prompts.len() + benign_prompts.len()) * self.models.len();
        let mut completed_tests = 0;

        // Test each model
        for model in &self.models {
            println!("🔬 Testing model: {}", model);

            // Test attack prompts (should be detected as malicious)
            println!("   Testing {} attack prompts...", attack_prompts.len());
            for (i, prompt) in attack_prompts.iter().enumerate() {
                match self.run_single_test(prompt, model, "attack", true).await {
                    Ok(result) => {
                        all_results.push(result);
                        completed_tests += 1;

                        if (i + 1) % 10 == 0 {
                            println!("      Completed {}/{} attack prompts", i + 1, attack_prompts.len());
                        }
                    },
                    Err(e) => {
                        warn!("Test failed for attack prompt: {}", e);
                    }
                }
            }

            // Test benign prompts (should NOT be detected as malicious)
            println!("   Testing {} benign prompts...", benign_prompts.len());
            for (i, prompt) in benign_prompts.iter().enumerate() {
                match self.run_single_test(prompt, model, "benign", false).await {
                    Ok(result) => {
                        all_results.push(result);
                        completed_tests += 1;

                        if (i + 1) % 10 == 0 {
                            println!("      Completed {}/{} benign prompts", i + 1, benign_prompts.len());
                        }
                    },
                    Err(e) => {
                        warn!("Test failed for benign prompt: {}", e);
                    }
                }
            }

            println!("   ✅ Model {} testing completed\n", model);
        }

        println!("📊 All tests completed! Generating results...\n");
        Ok(TestSuiteResults::new(all_results, self.models.clone()))
    }

    /// Generate detailed report
    pub fn generate_report(&self, results: &TestSuiteResults) -> String {
        let mut report = String::new();

        // Header
        report.push_str("# FluxPrompt + Ollama Integration Test Report\n");
        report.push_str(&format!("Generated: {}\n\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));

        // Executive Summary
        report.push_str("## Executive Summary\n\n");
        report.push_str(&format!("- **Total Tests Run**: {}\n", results.total_tests));
        report.push_str(&format!("- **Models Tested**: {:?}\n", results.models_tested));
        report.push_str(&format!("- **Overall Accuracy**: {:.2}%\n", results.accuracy_percentage()));
        report.push_str(&format!("- **Precision**: {:.2}%\n", results.precision_percentage()));
        report.push_str(&format!("- **Recall**: {:.2}%\n", results.recall_percentage()));
        report.push_str(&format!("- **F1 Score**: {:.3}\n", results.f1_score()));
        report.push_str(&format!("- **Average Detection Time**: {:.2}ms\n", results.avg_detection_time_ms));
        report.push_str(&format!("- **Average Total Time**: {:.2}ms\n\n", results.avg_total_time_ms));

        // Detailed Results
        report.push_str("## Detailed Results\n\n");
        report.push_str("### Attack Detection Performance\n");
        report.push_str(&format!("- Attack prompts tested: {}\n", results.total_attack_prompts));
        report.push_str(&format!("- Successfully detected: {}\n", results.detected_attacks));
        report.push_str(&format!("- Missed attacks (false negatives): {}\n", results.false_negatives));
        report.push_str(&format!("- Attack detection rate: {:.2}%\n\n", results.recall_percentage()));

        report.push_str("### Benign Prompt Performance\n");
        report.push_str(&format!("- Benign prompts tested: {}\n", results.total_benign_prompts));
        report.push_str(&format!("- Correctly identified as safe: {}\n", results.total_benign_prompts - results.incorrectly_flagged_benign));
        report.push_str(&format!("- False positives: {}\n", results.incorrectly_flagged_benign));
        report.push_str(&format!("- Benign accuracy: {:.2}%\n\n",
            if results.total_benign_prompts > 0 {
                ((results.total_benign_prompts - results.incorrectly_flagged_benign) as f64 / results.total_benign_prompts as f64) * 100.0
            } else { 0.0 }
        ));

        // Performance Metrics
        report.push_str("### Performance Metrics\n");
        report.push_str(&format!("- Average detection latency: {:.2}ms\n", results.avg_detection_time_ms));
        report.push_str(&format!("- Average total processing time: {:.2}ms\n", results.avg_total_time_ms));

        // Top detection time results
        let mut sorted_by_detection_time = results.results.clone();
        sorted_by_detection_time.sort_by(|a, b| b.detection_time_ms.cmp(&a.detection_time_ms));

        report.push_str("\n### Slowest Detection Times (Top 5)\n");
        for (i, result) in sorted_by_detection_time.iter().take(5).enumerate() {
            report.push_str(&format!("{}. {}ms - {} ({})\n",
                i + 1, result.detection_time_ms, result.description, result.category));
        }
        report.push_str("\n");

        // Category-wise breakdown
        let mut category_stats: HashMap<String, (usize, usize, usize)> = HashMap::new();
        for result in &results.results {
            let entry = category_stats.entry(result.category.clone()).or_insert((0, 0, 0));
            entry.0 += 1; // total
            if result.is_correct_detection() {
                entry.1 += 1; // correct
            }
            if result.detected_as_malicious {
                entry.2 += 1; // detected as malicious
            }
        }

        report.push_str("### Category-wise Performance\n");
        report.push_str("| Category | Total | Correct | Accuracy | Detected Malicious |\n");
        report.push_str("|----------|--------|---------|----------|-------------------|\n");

        for (category, (total, correct, detected)) in category_stats {
            let accuracy = (correct as f64 / total as f64) * 100.0;
            report.push_str(&format!("| {} | {} | {} | {:.1}% | {} |\n",
                category, total, correct, accuracy, detected));
        }
        report.push_str("\n");

        // False Positives Analysis
        if results.false_positives > 0 {
            report.push_str("### False Positives (Benign prompts flagged as malicious)\n");
            let false_positives: Vec<_> = results.results.iter()
                .filter(|r| r.is_false_positive())
                .collect();

            for fp in false_positives.iter().take(10) {
                report.push_str(&format!("- **{}**: \"{}\"\n", fp.description, fp.prompt));
                report.push_str(&format!("  - Reasons: {:?}\n", fp.blocking_reasons));
                report.push_str(&format!("  - Detection time: {}ms\n\n", fp.detection_time_ms));
            }
        }

        // False Negatives Analysis
        if results.false_negatives > 0 {
            report.push_str("### False Negatives (Attack prompts missed)\n");
            let false_negatives: Vec<_> = results.results.iter()
                .filter(|r| r.is_false_negative())
                .collect();

            for fn_result in false_negatives.iter().take(10) {
                report.push_str(&format!("- **{}**: \"{}\"\n", fn_result.description, fn_result.prompt));
                report.push_str(&format!("  - Severity: {}\n", fn_result.severity));
                report.push_str(&format!("  - Detection time: {}ms\n\n", fn_result.detection_time_ms));
            }
        }

        // Recommendations
        report.push_str("## Recommendations\n\n");

        if results.false_negatives > 0 {
            report.push_str("### Security Improvements Needed\n");
            report.push_str(&format!("- {} attack prompts were not detected. Consider:\n", results.false_negatives));
            report.push_str("  - Increasing detection sensitivity\n");
            report.push_str("  - Adding more specific rules for missed attack patterns\n");
            report.push_str("  - Reviewing semantic analysis parameters\n\n");
        }

        if results.false_positives > 5 {
            report.push_str("### False Positive Reduction\n");
            report.push_str(&format!("- {} benign prompts were incorrectly flagged. Consider:\n", results.false_positives));
            report.push_str("  - Fine-tuning detection thresholds\n");
            report.push_str("  - Improving context understanding\n");
            report.push_str("  - Adding whitelist patterns for common benign phrases\n\n");
        }

        if results.avg_detection_time_ms > 100.0 {
            report.push_str("### Performance Optimization\n");
            report.push_str(&format!("- Average detection time of {:.2}ms may impact user experience. Consider:\n", results.avg_detection_time_ms));
            report.push_str("  - Optimizing detection algorithms\n");
            report.push_str("  - Implementing caching for common patterns\n");
            report.push_str("  - Parallel processing for multiple checks\n\n");
        }

        // Test Configuration
        report.push_str("## Test Configuration\n\n");
        report.push_str("- **FluxPrompt Version**: Latest\n");
        report.push_str("- **Ollama Models**: qwen3:8b, gpt-oss:20b\n");
        report.push_str("- **Detection Level**: Paranoid\n");
        report.push_str("- **Response Strategy**: Sanitize\n");
        report.push_str("- **Semantic Analysis**: Enabled\n");

        report
    }

    /// Save report to file
    pub fn save_report(&self, report: &str, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        fs::write(filename, report)?;
        println!("📄 Report saved to: {}", filename);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Check if we're in the right directory
    if !std::path::Path::new("tests/ollama_tests/attack_prompts.json").exists() {
        error!("Test files not found. Please run from the fluxprompt root directory.");
        return Ok(());
    }

    // Check Ollama availability
    println!("🔍 Checking Ollama availability...");
    let client = reqwest::Client::new();
    let ollama_check = client.get("http://localhost:11434/api/tags").send().await;

    match ollama_check {
        Ok(response) if response.status().is_success() => {
            println!("✅ Ollama is running and accessible\n");
        },
        _ => {
            error!("❌ Ollama is not accessible at http://localhost:11434");
            println!("Please ensure Ollama is running with: ollama serve");
            return Ok(());
        }
    }

    // Initialize test runner with available models
    let models = vec!["qwen3:8b".to_string(), "gpt-oss:20b".to_string()];
    let test_runner = ComprehensiveTestRunner::new(models).await?;

    // Run comprehensive tests
    let results = test_runner.run_comprehensive_tests().await?;

    // Generate and display report
    let report = test_runner.generate_report(&results);
    println!("{}", report);

    // Save report to file
    let filename = format!("fluxprompt_ollama_test_report_{}.md",
        chrono::Utc::now().format("%Y%m%d_%H%M%S"));
    test_runner.save_report(&report, &filename)?;

    println!("\n🎉 Comprehensive testing completed successfully!");
    println!("Results summary:");
    println!("- Accuracy: {:.2}%", results.accuracy_percentage());
    println!("- Precision: {:.2}%", results.precision_percentage());
    println!("- Recall: {:.2}%", results.recall_percentage());
    println!("- F1 Score: {:.3}", results.f1_score());

    Ok(())
}