//! Metrics collection and monitoring for FluxPrompt operations.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::detection::DetectionResult;
// Note: DetectionStats, RiskLevel, ThreatType available if needed for future use

const SAMPLE_RETENTION_MS: u64 = 60 * 60 * 1000;
const CLEANUP_INTERVAL_MS: u64 = 60 * 1000;
const CLEANUP_INTERVAL_RECORDS: u64 = 1_000;
const MAX_RETAINED_SAMPLES: usize = 10_000;

#[derive(Debug, Clone, Copy)]
struct TimedSample<T> {
    recorded_at_ms: u64,
    value: T,
}

#[derive(Debug)]
struct RetentionState {
    records_since_cleanup: u64,
    next_cleanup_at_ms: u64,
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Snapshot of in-process detector outcomes and timing observations.
///
/// These values do not include ground-truth labels and therefore do not measure
/// detector accuracy or attack prevalence.
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
    /// Fraction of analyzed prompts flagged by the detector (0.0 to 1.0)
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
            min_analysis_time_ms: 0,
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
            min_confidence: 0.0,
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

    /// Returns a false-positive estimate when ground truth is available.
    ///
    /// The current collector has no ground-truth input and always returns
    /// `None`.
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
    analysis_times: DashMap<u64, TimedSample<u64>>, // sample ID -> timing sample
    confidence_scores: DashMap<u64, TimedSample<f32>>, // sample ID -> confidence sample

    // Additional stats
    min_analysis_time_ms: AtomicU64,
    max_analysis_time_ms: AtomicU64,

    // Confidence tracking
    positive_confidences: DashMap<u64, TimedSample<f32>>,
    negative_confidences: DashMap<u64, TimedSample<f32>>,

    // Sampling and cleanup state. The mutex serializes sample insertion so the
    // monotonically increasing IDs also provide a deterministic retention order.
    next_sample_id: AtomicU64,
    retention_state: Mutex<RetentionState>,
}

impl MetricsCollector {
    /// Creates a new metrics collector.
    pub fn new() -> Self {
        let now = current_timestamp_ms();

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
            next_sample_id: AtomicU64::new(0),
            retention_state: Mutex::new(RetentionState {
                records_since_cleanup: 0,
                next_cleanup_at_ms: now.saturating_add(CLEANUP_INTERVAL_MS),
            }),
        }
    }

    /// Records a detection result.
    pub fn record_detection(&self, result: &DetectionResult) {
        self.record_detection_at(result, current_timestamp_ms());
    }

    fn record_detection_at(&self, result: &DetectionResult, recorded_at_ms: u64) {
        // Serialize complete collector operations so reset and snapshot cannot
        // observe counters, breakdowns, and retained samples from different
        // logical points in time.
        let mut retention_state = self
            .retention_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let analysis_time = result.analysis_duration_ms();
        let confidence = result.confidence();

        // Update basic counters
        self.total_analyzed.fetch_add(1, Ordering::Relaxed);

        if result.is_injection_detected() {
            self.injections_detected.fetch_add(1, Ordering::Relaxed);
        }

        // Record analysis time
        self.total_analysis_time_ms
            .fetch_add(analysis_time, Ordering::Relaxed);

        // Update min/max analysis times
        self.update_min_max_time(analysis_time);

        // Record risk level
        let risk_level = format!("{:?}", result.risk_level());
        *self.risk_level_counts.entry(risk_level).or_insert(0) += 1;

        // Record threat types
        for threat in result.threats() {
            // Custom pattern names are caller-controlled and may have unbounded
            // cardinality or contain sensitive data. Aggregate them under one
            // stable label instead of retaining each name as a map key.
            let threat_type = match &threat.threat_type {
                crate::types::ThreatType::Custom(_) => "Custom".to_string(),
                threat_type => format!("{threat_type:?}"),
            };
            *self.threat_type_counts.entry(threat_type).or_insert(0) += 1;
        }

        self.record_samples(
            recorded_at_ms,
            analysis_time,
            confidence,
            result.is_injection_detected(),
            &mut retention_state,
        );
    }

    fn record_samples(
        &self,
        recorded_at_ms: u64,
        analysis_time: u64,
        confidence: f32,
        is_positive: bool,
        retention_state: &mut RetentionState,
    ) {
        let sample_id = self.next_sample_id.fetch_add(1, Ordering::Relaxed);

        self.analysis_times.insert(
            sample_id,
            TimedSample {
                recorded_at_ms,
                value: analysis_time,
            },
        );
        self.confidence_scores.insert(
            sample_id,
            TimedSample {
                recorded_at_ms,
                value: confidence,
            },
        );

        let confidence_sample = TimedSample {
            recorded_at_ms,
            value: confidence,
        };
        if is_positive {
            self.positive_confidences
                .insert(sample_id, confidence_sample);
        } else {
            self.negative_confidences
                .insert(sample_id, confidence_sample);
        }

        retention_state.records_since_cleanup =
            retention_state.records_since_cleanup.saturating_add(1);
        let count_due = retention_state.records_since_cleanup >= CLEANUP_INTERVAL_RECORDS;
        let deadline_due = recorded_at_ms >= retention_state.next_cleanup_at_ms;
        let capacity_due = self.analysis_times.len() > MAX_RETAINED_SAMPLES;

        if count_due || deadline_due || capacity_due {
            self.cleanup_old_entries(recorded_at_ms, sample_id, retention_state);
        }
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

    /// Cleans up expired and excess samples.
    fn cleanup_old_entries(
        &self,
        current_timestamp: u64,
        latest_sample_id: u64,
        retention_state: &mut RetentionState,
    ) {
        let timestamp_cutoff = current_timestamp.saturating_sub(SAMPLE_RETENTION_MS);
        let id_cutoff =
            latest_sample_id.saturating_sub((MAX_RETAINED_SAMPLES as u64).saturating_sub(1));

        self.analysis_times.retain(|&sample_id, sample| {
            sample_id >= id_cutoff && sample.recorded_at_ms >= timestamp_cutoff
        });
        self.confidence_scores.retain(|&sample_id, sample| {
            sample_id >= id_cutoff && sample.recorded_at_ms >= timestamp_cutoff
        });
        self.positive_confidences.retain(|&sample_id, sample| {
            sample_id >= id_cutoff && sample.recorded_at_ms >= timestamp_cutoff
        });
        self.negative_confidences.retain(|&sample_id, sample| {
            sample_id >= id_cutoff && sample.recorded_at_ms >= timestamp_cutoff
        });

        retention_state.records_since_cleanup = 0;
        retention_state.next_cleanup_at_ms = current_timestamp.saturating_add(CLEANUP_INTERVAL_MS);
    }

    fn cleanup_if_deadline_reached(
        &self,
        current_timestamp: u64,
        retention_state: &mut RetentionState,
    ) {
        if current_timestamp < retention_state.next_cleanup_at_ms {
            return;
        }

        let latest_sample_id = self
            .next_sample_id
            .load(Ordering::Relaxed)
            .saturating_sub(1);
        self.cleanup_old_entries(current_timestamp, latest_sample_id, retention_state);
    }

    /// Calculates and returns current metrics.
    pub fn get_metrics(&self) -> DetectionMetrics {
        let mut retention_state = self
            .retention_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.cleanup_if_deadline_reached(current_timestamp_ms(), &mut retention_state);

        let total_analyzed = self.total_analyzed.load(Ordering::Relaxed);
        let injections_detected = self.injections_detected.load(Ordering::Relaxed);
        let total_time = self.total_analysis_time_ms.load(Ordering::Relaxed);
        let min_analysis_time = self.min_analysis_time_ms.load(Ordering::Relaxed);

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
            min_analysis_time_ms: if total_analyzed == 0 || min_analysis_time == u64::MAX {
                0
            } else {
                min_analysis_time
            },
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
            .map(|entry| entry.value().value)
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
                .map(|entry| entry.value().value)
                .sum();
            sum as f64 / self.positive_confidences.len() as f64
        } else {
            0.0
        };

        let avg_negative_confidence = if !self.negative_confidences.is_empty() {
            let sum: f32 = self
                .negative_confidences
                .iter()
                .map(|entry| entry.value().value)
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
            .map(|entry| entry.value().value)
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
        let mut retention_state = self
            .retention_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

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

        retention_state.records_since_cleanup = 0;
        retention_state.next_cleanup_at_ms =
            current_timestamp_ms().saturating_add(CLEANUP_INTERVAL_MS);
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
        assert_eq!(metrics.min_analysis_time_ms, 0);
        assert_eq!(metrics.confidence_stats.min_confidence, 0.0);
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
        assert_eq!(metrics.min_analysis_time_ms, 0);
        assert_eq!(metrics.confidence_stats.min_confidence, 0.0);
    }

    #[test]
    fn test_custom_threat_metric_cardinality_is_bounded() {
        let collector = MetricsCollector::new();

        for index in 0..128 {
            let threat = ThreatInfo {
                threat_type: ThreatType::Custom(format!("tenant-pattern-{index}")),
                confidence: 0.9,
                span: None,
                metadata: HashMap::new(),
            };
            collector.record_detection(&DetectionResult::new(
                RiskLevel::High,
                0.9,
                vec![threat],
                1,
            ));
        }

        let metrics = collector.get_metrics();
        assert_eq!(metrics.threat_type_breakdown.len(), 1);
        assert_eq!(metrics.threat_type_breakdown.get("Custom"), Some(&128));
    }

    #[test]
    fn test_concurrent_record_and_reset_preserve_sample_invariants() {
        use std::sync::Arc;

        let collector = Arc::new(MetricsCollector::new());
        let recorder = Arc::clone(&collector);
        let resetter = Arc::clone(&collector);

        let record_thread = std::thread::spawn(move || {
            for _ in 0..5_000 {
                recorder.record_detection(&DetectionResult::safe());
            }
        });
        let reset_thread = std::thread::spawn(move || {
            for _ in 0..1_000 {
                resetter.reset();
            }
        });

        record_thread.join().unwrap();
        reset_thread.join().unwrap();

        let _operation = collector
            .retention_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let total = collector.total_analyzed.load(Ordering::Relaxed) as usize;
        assert!(collector.analysis_times.len() <= total);
        assert!(collector.confidence_scores.len() <= total);
        assert_eq!(
            collector
                .risk_level_counts
                .iter()
                .map(|entry| *entry.value())
                .sum::<u64>(),
            total as u64
        );
    }

    #[test]
    fn test_same_timestamp_samples_get_unique_deterministic_ids() {
        let collector = MetricsCollector::new();
        let result = DetectionResult::new(RiskLevel::None, 0.25, vec![], 7);
        let timestamp = current_timestamp_ms();

        for _ in 0..128 {
            collector.record_detection_at(&result, timestamp);
        }

        let mut sample_ids: Vec<u64> = collector
            .analysis_times
            .iter()
            .map(|entry| *entry.key())
            .collect();
        sample_ids.sort_unstable();

        assert_eq!(sample_ids, (0..128).collect::<Vec<_>>());
        assert_eq!(collector.confidence_scores.len(), 128);
        assert_eq!(collector.negative_confidences.len(), 128);
    }

    #[test]
    fn test_cleanup_runs_when_record_count_is_due() {
        let collector = MetricsCollector::new();
        let now = current_timestamp_ms();
        let expired_at = now.saturating_sub(SAMPLE_RETENTION_MS + 1);
        let result = DetectionResult::new(RiskLevel::None, 0.25, vec![], 7);

        collector.record_detection_at(&result, expired_at);
        {
            let mut retention_state = collector
                .retention_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            retention_state.records_since_cleanup = CLEANUP_INTERVAL_RECORDS - 1;
            retention_state.next_cleanup_at_ms = u64::MAX;
        }

        collector.record_detection_at(&result, now);

        assert_eq!(collector.analysis_times.len(), 1);
        assert_eq!(collector.confidence_scores.len(), 1);
    }

    #[test]
    fn test_snapshot_runs_deadline_cleanup() {
        let collector = MetricsCollector::new();
        let now = current_timestamp_ms();
        let expired_at = now.saturating_sub(SAMPLE_RETENTION_MS + 1);
        let result = DetectionResult::new(RiskLevel::None, 0.25, vec![], 7);

        collector.record_detection_at(&result, expired_at);
        collector
            .retention_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .next_cleanup_at_ms = now;

        let metrics = collector.get_metrics();

        assert_eq!(metrics.performance_percentiles.p50_ms, 0);
        assert_eq!(metrics.performance_percentiles.p99_ms, 0);
        assert!(collector.analysis_times.is_empty());
        assert!(collector.confidence_scores.is_empty());
    }

    #[test]
    fn test_sample_retention_is_bounded() {
        let collector = MetricsCollector::new();
        let result = DetectionResult::new(RiskLevel::None, 0.25, vec![], 7);
        let timestamp = current_timestamp_ms();

        for _ in 0..(MAX_RETAINED_SAMPLES + 25) {
            collector.record_detection_at(&result, timestamp);
        }

        assert_eq!(collector.analysis_times.len(), MAX_RETAINED_SAMPLES);
        assert_eq!(collector.confidence_scores.len(), MAX_RETAINED_SAMPLES);
        assert_eq!(collector.negative_confidences.len(), MAX_RETAINED_SAMPLES);
        assert!(collector.positive_confidences.is_empty());
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
