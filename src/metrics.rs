//! Metrics collection and monitoring for FluxPrompt operations.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::detection::DetectionResult;
// Note: DetectionStats, RiskLevel, ThreatType available if needed for future use

/// Comprehensive metrics for detection operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionMetrics {
    /// Total number of prompts analyzed
    pub total_analyzed: u64,
    /// Number of injections detected
    pub injections_detected: u64,
    /// Breakdown by risk level
    pub risk_level_breakdown: HashMap<String, u64>,
    /// Breakdown by threat type
    pub threat_type_breakdown: HashMap<String, u64>,
    /// Average analysis time in milliseconds
    pub avg_analysis_time_ms: f64,
    /// Minimum analysis time in milliseconds
    pub min_analysis_time_ms: u64,
    /// Maximum analysis time in milliseconds
    pub max_analysis_time_ms: u64,
    /// Total analysis time in milliseconds
    pub total_analysis_time_ms: u64,
    /// Detection rate (percentage of prompts that were flagged)
    pub detection_rate: f64,
    /// Confidence score statistics
    pub confidence_stats: ConfidenceStats,
    /// Timestamp of metrics collection
    pub timestamp: SystemTime,
    /// Performance percentiles
    pub performance_percentiles: PerformancePercentiles,
}

/// Statistics about confidence scores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceStats {
    /// Average confidence for positive detections
    pub avg_positive_confidence: f64,
    /// Average confidence for negative detections
    pub avg_negative_confidence: f64,
    /// Minimum confidence score seen
    pub min_confidence: f32,
    /// Maximum confidence score seen
    pub max_confidence: f32,
    /// Standard deviation of confidence scores
    pub confidence_std_dev: f64,
}

/// Performance percentile statistics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerformancePercentiles {
    /// 50th percentile (median) analysis time in ms
    pub p50_ms: u64,
    /// 90th percentile analysis time in ms
    pub p90_ms: u64,
    /// 95th percentile analysis time in ms
    pub p95_ms: u64,
    /// 99th percentile analysis time in ms
    pub p99_ms: u64,
}

impl Default for DetectionMetrics {
    fn default() -> Self {
        Self {
            total_analyzed: 0,
            injections_detected: 0,
            risk_level_breakdown: HashMap::new(),
            threat_type_breakdown: HashMap::new(),
            avg_analysis_time_ms: 0.0,
            min_analysis_time_ms: u64::MAX,
            max_analysis_time_ms: 0,
            total_analysis_time_ms: 0,
            detection_rate: 0.0,
            confidence_stats: ConfidenceStats::default(),
            timestamp: SystemTime::now(),
            performance_percentiles: PerformancePercentiles::default(),
        }
    }
}

impl Default for ConfidenceStats {
    fn default() -> Self {
        Self {
            avg_positive_confidence: 0.0,
            avg_negative_confidence: 0.0,
            min_confidence: 1.0,
            max_confidence: 0.0,
            confidence_std_dev: 0.0,
        }
    }
}

impl DetectionMetrics {
    /// Returns the total number of prompts analyzed.
    pub fn total_analyzed(&self) -> u64 {
        self.total_analyzed
    }

    /// Returns the detection rate as a percentage.
    pub fn detection_rate_percentage(&self) -> f64 {
        self.detection_rate * 100.0
    }

    /// Returns the false positive rate estimate (requires ground truth data).
    pub fn estimated_false_positive_rate(&self) -> Option<f64> {
        // This would require additional tracking of ground truth data
        // For now, return None to indicate it's not available
        None
    }
}

/// Collector for gathering and computing detection metrics.
pub struct MetricsCollector {
    // Atomic counters for thread-safe operations
    total_analyzed: AtomicU64,
    injections_detected: AtomicU64,
    total_analysis_time_ms: AtomicU64,

    // Thread-safe maps for breakdowns
    risk_level_counts: DashMap<String, u64>,
    threat_type_counts: DashMap<String, u64>,

    // Store individual measurements for percentile calculations
    analysis_times: DashMap<u64, u64>, // timestamp -> duration_ms
    confidence_scores: DashMap<u64, f32>, // timestamp -> confidence

    // Additional stats
    min_analysis_time_ms: AtomicU64,
    max_analysis_time_ms: AtomicU64,

    // Confidence tracking
    positive_confidences: DashMap<u64, f32>,
    negative_confidences: DashMap<u64, f32>,
}

impl MetricsCollector {
    /// Creates a new metrics collector.
    pub fn new() -> Self {
        Self {
            total_analyzed: AtomicU64::new(0),
            injections_detected: AtomicU64::new(0),
            total_analysis_time_ms: AtomicU64::new(0),
            risk_level_counts: DashMap::new(),
            threat_type_counts: DashMap::new(),
            analysis_times: DashMap::new(),
            confidence_scores: DashMap::new(),
            min_analysis_time_ms: AtomicU64::new(u64::MAX),
            max_analysis_time_ms: AtomicU64::new(0),
            positive_confidences: DashMap::new(),
            negative_confidences: DashMap::new(),
        }
    }

    /// Records a detection result.
    pub fn record_detection(&self, result: &DetectionResult) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Update basic counters
        self.total_analyzed.fetch_add(1, Ordering::Relaxed);

        if result.is_injection_detected() {
            self.injections_detected.fetch_add(1, Ordering::Relaxed);
        }

        // Record analysis time
        let analysis_time = result.analysis_duration_ms();
        self.total_analysis_time_ms
            .fetch_add(analysis_time, Ordering::Relaxed);
        self.analysis_times.insert(timestamp, analysis_time);

        // Update min/max analysis times
        self.update_min_max_time(analysis_time);

        // Record risk level
        let risk_level = format!("{:?}", result.risk_level());
        *self.risk_level_counts.entry(risk_level).or_insert(0) += 1;

        // Record threat types
        for threat in result.threats() {
            let threat_type = format!("{:?}", threat.threat_type);
            *self.threat_type_counts.entry(threat_type).or_insert(0) += 1;
        }

        // Record confidence
        let confidence = result.confidence();
        self.confidence_scores.insert(timestamp, confidence);

        if result.is_injection_detected() {
            self.positive_confidences.insert(timestamp, confidence);
        } else {
            self.negative_confidences.insert(timestamp, confidence);
        }

        // Cleanup old entries periodically to prevent memory leaks
        self.cleanup_old_entries(timestamp);
    }

    /// Updates minimum and maximum analysis times.
    fn update_min_max_time(&self, analysis_time: u64) {
        // Update minimum
        let mut current_min = self.min_analysis_time_ms.load(Ordering::Relaxed);
        while current_min > analysis_time {
            match self.min_analysis_time_ms.compare_exchange_weak(
                current_min,
                analysis_time,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(new_current) => current_min = new_current,
            }
        }

        // Update maximum
        let mut current_max = self.max_analysis_time_ms.load(Ordering::Relaxed);
        while current_max < analysis_time {
            match self.max_analysis_time_ms.compare_exchange_weak(
                current_max,
                analysis_time,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(new_current) => current_max = new_current,
            }
        }
    }

    /// Cleans up old entries to prevent memory leaks.
    fn cleanup_old_entries(&self, current_timestamp: u64) {
        // Keep only the last hour of data for percentile calculations
        let cutoff = current_timestamp.saturating_sub(3600 * 1000); // 1 hour in milliseconds

        // Only cleanup every 1000 entries to avoid constant overhead
        if current_timestamp % 1000 == 0 {
            self.analysis_times
                .retain(|&timestamp, _| timestamp > cutoff);
            self.confidence_scores
                .retain(|&timestamp, _| timestamp > cutoff);
            self.positive_confidences
                .retain(|&timestamp, _| timestamp > cutoff);
            self.negative_confidences
                .retain(|&timestamp, _| timestamp > cutoff);
        }
    }

    /// Calculates and returns current metrics.
    pub fn get_metrics(&self) -> DetectionMetrics {
        let total_analyzed = self.total_analyzed.load(Ordering::Relaxed);
        let injections_detected = self.injections_detected.load(Ordering::Relaxed);
        let total_time = self.total_analysis_time_ms.load(Ordering::Relaxed);

        let avg_analysis_time = if total_analyzed > 0 {
            total_time as f64 / total_analyzed as f64
        } else {
            0.0
        };

        let detection_rate = if total_analyzed > 0 {
            injections_detected as f64 / total_analyzed as f64
        } else {
            0.0
        };

        // Collect risk level breakdown
        let mut risk_level_breakdown = HashMap::new();
        for entry in self.risk_level_counts.iter() {
            risk_level_breakdown.insert(entry.key().clone(), *entry.value());
        }

        // Collect threat type breakdown
        let mut threat_type_breakdown = HashMap::new();
        for entry in self.threat_type_counts.iter() {
            threat_type_breakdown.insert(entry.key().clone(), *entry.value());
        }

        // Calculate confidence statistics
        let confidence_stats = self.calculate_confidence_stats();

        // Calculate performance percentiles
        let performance_percentiles = self.calculate_performance_percentiles();

        DetectionMetrics {
            total_analyzed,
            injections_detected,
            risk_level_breakdown,
            threat_type_breakdown,
            avg_analysis_time_ms: avg_analysis_time,
            min_analysis_time_ms: self.min_analysis_time_ms.load(Ordering::Relaxed),
            max_analysis_time_ms: self.max_analysis_time_ms.load(Ordering::Relaxed),
            total_analysis_time_ms: total_time,
            detection_rate,
            confidence_stats,
            timestamp: SystemTime::now(),
            performance_percentiles,
        }
    }

    /// Calculates confidence statistics.
    fn calculate_confidence_stats(&self) -> ConfidenceStats {
        let mut all_confidences: Vec<f32> = self
            .confidence_scores
            .iter()
            .map(|entry| *entry.value())
            .collect();

        if all_confidences.is_empty() {
            return ConfidenceStats::default();
        }

        all_confidences.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let min_confidence = all_confidences[0];
        let max_confidence = all_confidences[all_confidences.len() - 1];

        // Calculate averages
        let avg_positive_confidence = if !self.positive_confidences.is_empty() {
            let sum: f32 = self
                .positive_confidences
                .iter()
                .map(|entry| *entry.value())
                .sum();
            sum as f64 / self.positive_confidences.len() as f64
        } else {
            0.0
        };

        let avg_negative_confidence = if !self.negative_confidences.is_empty() {
            let sum: f32 = self
                .negative_confidences
                .iter()
                .map(|entry| *entry.value())
                .sum();
            sum as f64 / self.negative_confidences.len() as f64
        } else {
            0.0
        };

        // Calculate standard deviation
        let mean = all_confidences.iter().sum::<f32>() / all_confidences.len() as f32;
        let variance = all_confidences
            .iter()
            .map(|&x| {
                let diff = x - mean;
                diff * diff
            })
            .sum::<f32>()
            / all_confidences.len() as f32;
        let confidence_std_dev = variance.sqrt() as f64;

        ConfidenceStats {
            avg_positive_confidence,
            avg_negative_confidence,
            min_confidence,
            max_confidence,
            confidence_std_dev,
        }
    }

    /// Calculates performance percentiles.
    fn calculate_performance_percentiles(&self) -> PerformancePercentiles {
        let mut times: Vec<u64> = self
            .analysis_times
            .iter()
            .map(|entry| *entry.value())
            .collect();

        if times.is_empty() {
            return PerformancePercentiles::default();
        }

        times.sort_unstable();

        let len = times.len();
        let p50_ms = times[len * 50 / 100];
        let p90_ms = times[len * 90 / 100];
        let p95_ms = times[len * 95 / 100];
        let p99_ms = times[len * 99 / 100];

        PerformancePercentiles {
            p50_ms,
            p90_ms,
            p95_ms,
            p99_ms,
        }
    }

    /// Resets all metrics.
    pub fn reset(&self) {
        self.total_analyzed.store(0, Ordering::Relaxed);
        self.injections_detected.store(0, Ordering::Relaxed);
        self.total_analysis_time_ms.store(0, Ordering::Relaxed);
        self.min_analysis_time_ms.store(u64::MAX, Ordering::Relaxed);
        self.max_analysis_time_ms.store(0, Ordering::Relaxed);

        self.risk_level_counts.clear();
        self.threat_type_counts.clear();
        self.analysis_times.clear();
        self.confidence_scores.clear();
        self.positive_confidences.clear();
        self.negative_confidences.clear();
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::DetectionResult;
    use crate::types::{RiskLevel, ThreatInfo, ThreatType};

    #[test]
    fn test_metrics_collector_creation() {
        let collector = MetricsCollector::new();
        let metrics = collector.get_metrics();

        assert_eq!(metrics.total_analyzed, 0);
        assert_eq!(metrics.injections_detected, 0);
        assert_eq!(metrics.detection_rate, 0.0);
    }

    #[test]
    fn test_record_safe_detection() {
        let collector = MetricsCollector::new();
        let result = DetectionResult::safe();

        collector.record_detection(&result);
        let metrics = collector.get_metrics();

        assert_eq!(metrics.total_analyzed, 1);
        assert_eq!(metrics.injections_detected, 0);
        assert_eq!(metrics.detection_rate, 0.0);
    }

    #[test]
    fn test_record_positive_detection() {
        let collector = MetricsCollector::new();

        let threat = ThreatInfo {
            threat_type: ThreatType::InstructionOverride,
            confidence: 0.9,
            span: None,
            metadata: HashMap::new(),
        };

        let result = DetectionResult::new(RiskLevel::High, 0.9, vec![threat], 100);

        collector.record_detection(&result);
        let metrics = collector.get_metrics();

        assert_eq!(metrics.total_analyzed, 1);
        assert_eq!(metrics.injections_detected, 1);
        assert_eq!(metrics.detection_rate, 1.0);
        assert_eq!(metrics.avg_analysis_time_ms, 100.0);
    }

    #[test]
    fn test_multiple_detections() {
        let collector = MetricsCollector::new();

        // Record safe detection
        collector.record_detection(&DetectionResult::safe());

        // Record positive detection
        let threat = ThreatInfo {
            threat_type: ThreatType::Jailbreak,
            confidence: 0.8,
            span: None,
            metadata: HashMap::new(),
        };
        let positive_result = DetectionResult::new(RiskLevel::Medium, 0.8, vec![threat], 150);
        collector.record_detection(&positive_result);

        let metrics = collector.get_metrics();

        assert_eq!(metrics.total_analyzed, 2);
        assert_eq!(metrics.injections_detected, 1);
        assert_eq!(metrics.detection_rate, 0.5);

        // Check risk level breakdown
        assert_eq!(metrics.risk_level_breakdown.get("None"), Some(&1));
        assert_eq!(metrics.risk_level_breakdown.get("Medium"), Some(&1));

        // Check threat type breakdown
        assert_eq!(metrics.threat_type_breakdown.get("Jailbreak"), Some(&1));
    }

    #[test]
    fn test_confidence_stats() {
        let collector = MetricsCollector::new();

        // Add some positive detections
        let threat = ThreatInfo {
            threat_type: ThreatType::InstructionOverride,
            confidence: 0.9,
            span: None,
            metadata: HashMap::new(),
        };
        let positive_result = DetectionResult::new(RiskLevel::High, 0.9, vec![threat], 100);
        collector.record_detection(&positive_result);

        // Add safe detection
        collector.record_detection(&DetectionResult::safe());

        let metrics = collector.get_metrics();

        assert!(metrics.confidence_stats.avg_positive_confidence > 0.0);
        assert!(metrics.confidence_stats.max_confidence >= metrics.confidence_stats.min_confidence);
    }

    #[test]
    fn test_performance_percentiles() {
        let collector = MetricsCollector::new();

        // Add several detections with different timings
        for time in [10, 20, 30, 50, 100, 200, 500] {
            let result = DetectionResult::new(RiskLevel::None, 1.0, vec![], time);
            collector.record_detection(&result);
        }

        let metrics = collector.get_metrics();

        assert!(metrics.performance_percentiles.p50_ms > 0);
        assert!(metrics.performance_percentiles.p90_ms >= metrics.performance_percentiles.p50_ms);
        assert!(metrics.performance_percentiles.p99_ms >= metrics.performance_percentiles.p95_ms);
    }

    #[test]
    fn test_metrics_reset() {
        let collector = MetricsCollector::new();

        // Record some data
        collector.record_detection(&DetectionResult::safe());
        assert!(collector.get_metrics().total_analyzed > 0);

        // Reset and verify
        collector.reset();
        let metrics = collector.get_metrics();

        assert_eq!(metrics.total_analyzed, 0);
        assert_eq!(metrics.injections_detected, 0);
        assert!(metrics.risk_level_breakdown.is_empty());
        assert!(metrics.threat_type_breakdown.is_empty());
    }

    #[test]
    fn test_detection_rate_percentage() {
        let metrics = DetectionMetrics {
            total_analyzed: 100,
            injections_detected: 25,
            detection_rate: 0.25,
            ..Default::default()
        };

        assert_eq!(metrics.detection_rate_percentage(), 25.0);
    }
}
