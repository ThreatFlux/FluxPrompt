//! Utility functions and helpers for FluxPrompt operations.

use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Common regex patterns used throughout the codebase.
pub static PATTERNS: Lazy<HashMap<&'static str, Regex>> = Lazy::new(|| {
    let mut patterns = HashMap::new();

    // Email pattern
    patterns.insert(
        "email",
        Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap(),
    );

    // URL pattern
    patterns.insert(
        "url",
        Regex::new(r"https?://(?:[-\w.])+(?:\:[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?").unwrap()
    );

    // IP address pattern
    patterns.insert(
        "ip_address",
        Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap(),
    );

    // Base64 pattern
    patterns.insert("base64", Regex::new(r"^[A-Za-z0-9+/]*={0,2}$").unwrap());

    // Hexadecimal pattern
    patterns.insert("hex", Regex::new(r"^[0-9a-fA-F]+$").unwrap());

    patterns
});

/// Text processing utilities.
pub mod text {
    use super::*;

    /// Normalizes text by removing excessive whitespace and control characters.
    pub fn normalize_text(text: &str) -> String {
        // Remove control characters except newlines and tabs
        let cleaned: String = text
            .chars()
            .filter(|&c| !c.is_control() || c == '\n' || c == '\t')
            .collect();

        // Normalize whitespace
        let whitespace_normalized = Regex::new(r"\s+")
            .unwrap()
            .replace_all(&cleaned, " ")
            .to_string();

        whitespace_normalized.trim().to_string()
    }

    /// Calculates the Levenshtein distance between two strings.
    pub fn levenshtein_distance(s1: &str, s2: &str) -> usize {
        let len1 = s1.chars().count();
        let len2 = s2.chars().count();

        if len1 == 0 {
            return len2;
        }
        if len2 == 0 {
            return len1;
        }

        let s1_chars: Vec<char> = s1.chars().collect();
        let s2_chars: Vec<char> = s2.chars().collect();

        let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];

        // Initialize first row and column
        for (i, row) in matrix.iter_mut().enumerate().take(len1 + 1) {
            row[0] = i;
        }
        for j in 0..=len2 {
            matrix[0][j] = j;
        }

        // Fill the matrix
        for i in 1..=len1 {
            for j in 1..=len2 {
                let cost = if s1_chars[i - 1] == s2_chars[j - 1] {
                    0
                } else {
                    1
                };

                matrix[i][j] = std::cmp::min(
                    std::cmp::min(
                        matrix[i - 1][j] + 1, // deletion
                        matrix[i][j - 1] + 1, // insertion
                    ),
                    matrix[i - 1][j - 1] + cost, // substitution
                );
            }
        }

        matrix[len1][len2]
    }

    /// Calculates text similarity based on Levenshtein distance.
    pub fn similarity(s1: &str, s2: &str) -> f32 {
        let max_len = std::cmp::max(s1.len(), s2.len());
        if max_len == 0 {
            return 1.0;
        }

        let distance = levenshtein_distance(s1, s2);
        1.0 - (distance as f32 / max_len as f32)
    }

    /// Extracts words from text, filtering out short words and punctuation.
    pub fn extract_words(text: &str, min_length: usize) -> Vec<String> {
        text.split_whitespace()
            .map(|word| {
                word.chars()
                    .filter(|c| c.is_alphanumeric())
                    .collect::<String>()
                    .to_lowercase()
            })
            .filter(|word| word.len() >= min_length)
            .collect()
    }

    /// Calculates the entropy of text (measure of randomness).
    pub fn calculate_entropy(text: &str) -> f64 {
        let mut char_counts = HashMap::new();
        let total_chars = text.chars().count() as f64;

        if total_chars == 0.0 {
            return 0.0;
        }

        // Count character frequencies
        for c in text.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }

        // Calculate entropy
        let mut entropy = 0.0;
        for &count in char_counts.values() {
            let probability = count as f64 / total_chars;
            if probability > 0.0 {
                entropy -= probability * probability.log2();
            }
        }

        entropy
    }

    /// Detects if text contains repeated patterns.
    pub fn has_repeated_patterns(text: &str, min_pattern_length: usize) -> bool {
        if text.len() < min_pattern_length * 2 {
            return false;
        }

        for pattern_len in min_pattern_length..=text.len() / 2 {
            for start in 0..=(text.len() - pattern_len * 2) {
                let pattern = &text[start..start + pattern_len];
                let remaining = &text[start + pattern_len..];

                if remaining.starts_with(pattern) {
                    return true;
                }
            }
        }

        false
    }
}

/// Encoding and decoding utilities.
pub mod encoding {
    use super::*;

    /// Detects if text is likely to be base64 encoded.
    pub fn is_likely_base64(text: &str) -> bool {
        if text.len() < 4 || text.len() % 4 != 0 {
            return false;
        }

        PATTERNS.get("base64").unwrap().is_match(text)
            && text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    }

    /// Detects if text is likely to be hexadecimal encoded.
    pub fn is_likely_hex(text: &str) -> bool {
        text.len() >= 8 && text.len() % 2 == 0 && PATTERNS.get("hex").unwrap().is_match(text)
    }

    /// Safely attempts to decode URL-encoded text.
    pub fn safe_url_decode(text: &str) -> Result<String, String> {
        let mut result = String::with_capacity(text.len());
        let chars: Vec<char> = text.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            match chars[i] {
                '%' if i + 2 < chars.len() => {
                    let hex_str: String = chars[i + 1..i + 3].iter().collect();
                    match u8::from_str_radix(&hex_str, 16) {
                        Ok(byte) => {
                            if let Some(ch) = char::from_u32(byte as u32) {
                                result.push(ch);
                            } else {
                                result.push_str(&format!("%{}", hex_str));
                            }
                        }
                        Err(_) => {
                            result.push('%');
                            result.push(chars[i + 1]);
                            result.push(chars[i + 2]);
                        }
                    }
                    i += 3;
                }
                '+' => {
                    result.push(' ');
                    i += 1;
                }
                c => {
                    result.push(c);
                    i += 1;
                }
            }
        }

        Ok(result)
    }

    /// Detects various encoding schemes in text.
    pub fn detect_encoding(text: &str) -> Vec<String> {
        let mut detected = Vec::new();

        if is_likely_base64(text) {
            detected.push("base64".to_string());
        }

        if is_likely_hex(text) {
            detected.push("hex".to_string());
        }

        if text.contains('%') && text.matches('%').count() >= 1 {
            detected.push("url".to_string());
        }

        if text.contains("\\u") {
            detected.push("unicode".to_string());
        }

        if text.contains("&#") {
            detected.push("html_entity".to_string());
        }

        detected
    }
}

/// Time and performance utilities.
pub mod time {
    use super::*;
    use std::time::Instant;

    /// Simple timer for measuring execution time.
    pub struct Timer {
        start: Instant,
        name: String,
    }

    impl Timer {
        /// Creates and starts a new timer.
        pub fn new(name: &str) -> Self {
            Self {
                start: Instant::now(),
                name: name.to_string(),
            }
        }

        /// Returns elapsed time in milliseconds.
        pub fn elapsed_ms(&self) -> u64 {
            self.start.elapsed().as_millis() as u64
        }

        /// Returns elapsed time in microseconds.
        pub fn elapsed_us(&self) -> u64 {
            self.start.elapsed().as_micros() as u64
        }

        /// Stops the timer and returns elapsed time in milliseconds.
        pub fn stop(self) -> u64 {
            let elapsed = self.elapsed_ms();
            tracing::debug!("Timer '{}' completed in {}ms", self.name, elapsed);
            elapsed
        }
    }

    /// Gets current timestamp in milliseconds since Unix epoch.
    pub fn timestamp_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Formats duration in a human-readable way.
    pub fn format_duration(duration_ms: u64) -> String {
        match duration_ms {
            0..=999 => format!("{}ms", duration_ms),
            1000..=59999 => format!("{:.1}s", duration_ms as f64 / 1000.0),
            60000..=3599999 => format!("{:.1}m", duration_ms as f64 / 60000.0),
            _ => format!("{:.1}h", duration_ms as f64 / 3600000.0),
        }
    }
}

/// Validation utilities.
pub mod validation {
    use super::*;

    /// Validates that a confidence score is within valid range (0.0 to 1.0).
    pub fn validate_confidence(confidence: f32) -> Result<(), String> {
        if !(0.0..=1.0).contains(&confidence) || confidence.is_nan() {
            Err(format!("Invalid confidence score: {}", confidence))
        } else {
            Ok(())
        }
    }

    /// Validates that text length is within specified bounds.
    pub fn validate_text_length(text: &str, min_len: usize, max_len: usize) -> Result<(), String> {
        let len = text.len();
        if len < min_len {
            Err(format!("Text too short: {} < {}", len, min_len))
        } else if len > max_len {
            Err(format!("Text too long: {} > {}", len, max_len))
        } else {
            Ok(())
        }
    }

    /// Validates that a string contains only safe characters.
    pub fn validate_safe_chars(text: &str) -> Result<(), String> {
        let unsafe_chars: Vec<char> = text
            .chars()
            .filter(|&c| c.is_control() && c != '\n' && c != '\t')
            .collect();

        if !unsafe_chars.is_empty() {
            Err(format!(
                "Text contains unsafe characters: {:?}",
                unsafe_chars
            ))
        } else {
            Ok(())
        }
    }

    /// Validates email format.
    pub fn validate_email(email: &str) -> bool {
        PATTERNS.get("email").unwrap().is_match(email)
    }

    /// Validates URL format.
    pub fn validate_url(url: &str) -> bool {
        PATTERNS.get("url").unwrap().is_match(url)
    }
}

/// Collection utilities for working with threat data.
pub mod collections {
    use std::collections::HashMap;
    use std::hash::Hash;

    /// Groups items by a key function and counts occurrences.
    pub fn group_and_count<T, K, F>(items: &[T], key_fn: F) -> HashMap<K, usize>
    where
        K: Hash + Eq,
        F: Fn(&T) -> K,
    {
        let mut counts = HashMap::new();
        for item in items {
            let key = key_fn(item);
            *counts.entry(key).or_insert(0) += 1;
        }
        counts
    }

    /// Finds the most common item in a collection.
    pub fn most_common<T>(items: &[T]) -> Option<&T>
    where
        T: Hash + Eq,
    {
        let mut counts = HashMap::new();
        for item in items {
            *counts.entry(item).or_insert(0) += 1;
        }

        counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(item, _)| item)
    }

    /// Calculates percentiles from a sorted collection.
    pub fn calculate_percentiles(
        sorted_values: &[u64],
        percentiles: &[f64],
    ) -> HashMap<String, u64> {
        let mut results = HashMap::new();

        if sorted_values.is_empty() {
            return results;
        }

        for &percentile in percentiles {
            let index = ((percentile / 100.0) * (sorted_values.len() - 1) as f64).round() as usize;
            let key = format!("p{}", percentile as u8);
            results.insert(key, sorted_values[index]);
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_text() {
        let messy_text = "  Hello\x00\x01   World  \n\t  ";
        let normalized = text::normalize_text(messy_text);
        assert_eq!(normalized, "Hello World");
    }

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(text::levenshtein_distance("cat", "bat"), 1);
        assert_eq!(text::levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(text::levenshtein_distance("", "abc"), 3);
        assert_eq!(text::levenshtein_distance("abc", "abc"), 0);
    }

    #[test]
    fn test_similarity() {
        assert!((text::similarity("hello", "hello") - 1.0).abs() < f32::EPSILON);
        assert!(text::similarity("hello", "hallo") > 0.5);
        assert!(text::similarity("abc", "xyz") < 0.5);
    }

    #[test]
    fn test_extract_words() {
        let text = "Hello, World! This is a test.";
        let words = text::extract_words(text, 2);
        assert!(words.contains(&"hello".to_string()));
        assert!(words.contains(&"world".to_string()));
        assert!(words.contains(&"this".to_string()));
        assert!(words.contains(&"test".to_string()));
        assert!(!words.contains(&"a".to_string())); // too short
    }

    #[test]
    fn test_calculate_entropy() {
        let low_entropy = "aaaaaaaaaa";
        let high_entropy = "abcdefghij";

        assert!(text::calculate_entropy(high_entropy) > text::calculate_entropy(low_entropy));
    }

    #[test]
    fn test_repeated_patterns() {
        assert!(text::has_repeated_patterns("abcabc", 3));
        assert!(text::has_repeated_patterns("testtest", 4));
        assert!(!text::has_repeated_patterns("hello world", 3));
    }

    #[test]
    fn test_base64_detection() {
        assert!(encoding::is_likely_base64("SGVsbG8="));
        assert!(encoding::is_likely_base64("SGVsbG8gV29ybGQ="));
        assert!(!encoding::is_likely_base64("Hello World"));
        assert!(!encoding::is_likely_base64("SGVsbG8")); // Invalid padding
    }

    #[test]
    fn test_hex_detection() {
        assert!(encoding::is_likely_hex("48656c6c6f"));
        assert!(encoding::is_likely_hex("deadbeef"));
        assert!(!encoding::is_likely_hex("Hello"));
        assert!(!encoding::is_likely_hex("48656c6c6")); // Odd length
    }

    #[test]
    fn test_url_decode() {
        let encoded = "Hello%20World%21";
        let decoded = encoding::safe_url_decode(encoded).unwrap();
        assert_eq!(decoded, "Hello World!");

        let with_plus = "Hello+World";
        let decoded = encoding::safe_url_decode(with_plus).unwrap();
        assert_eq!(decoded, "Hello World");
    }

    #[test]
    fn test_encoding_detection() {
        let base64_text = "SGVsbG8gV29ybGQ=";
        let detected = encoding::detect_encoding(base64_text);
        assert!(detected.contains(&"base64".to_string()));

        let url_text = "Hello%20World";
        let detected = encoding::detect_encoding(url_text);
        assert!(detected.contains(&"url".to_string()));
    }

    #[test]
    fn test_timer() {
        let timer = time::Timer::new("test");
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed = timer.elapsed_ms();
        assert!(elapsed >= 10);
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(time::format_duration(500), "500ms");
        assert_eq!(time::format_duration(1500), "1.5s");
        assert_eq!(time::format_duration(90000), "1.5m");
    }

    #[test]
    fn test_validate_confidence() {
        assert!(validation::validate_confidence(0.5).is_ok());
        assert!(validation::validate_confidence(0.0).is_ok());
        assert!(validation::validate_confidence(1.0).is_ok());
        assert!(validation::validate_confidence(-0.1).is_err());
        assert!(validation::validate_confidence(1.1).is_err());
        assert!(validation::validate_confidence(f32::NAN).is_err());
    }

    #[test]
    fn test_validate_text_length() {
        assert!(validation::validate_text_length("hello", 3, 10).is_ok());
        assert!(validation::validate_text_length("hi", 3, 10).is_err());
        assert!(validation::validate_text_length("this is too long", 3, 10).is_err());
    }

    #[test]
    fn test_validate_email() {
        assert!(validation::validate_email("test@example.com"));
        assert!(validation::validate_email("user.name+tag@domain.co.uk"));
        assert!(!validation::validate_email("invalid.email"));
        assert!(!validation::validate_email("@example.com"));
    }

    #[test]
    fn test_validate_url() {
        assert!(validation::validate_url("https://example.com"));
        assert!(validation::validate_url("http://test.org/path?query=1"));
        assert!(!validation::validate_url("not-a-url"));
        assert!(!validation::validate_url("ftp://example.com"));
    }

    #[test]
    fn test_group_and_count() {
        let numbers = vec![1, 2, 2, 3, 3, 3];
        let counts = collections::group_and_count(&numbers, |&x| x);

        assert_eq!(counts.get(&1), Some(&1));
        assert_eq!(counts.get(&2), Some(&2));
        assert_eq!(counts.get(&3), Some(&3));
    }

    #[test]
    fn test_most_common() {
        let items = vec!["a", "b", "b", "c", "c", "c"];
        let most_common = collections::most_common(&items);
        assert_eq!(most_common, Some(&"c"));
    }

    #[test]
    fn test_calculate_percentiles() {
        let values = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let percentiles = collections::calculate_percentiles(&values, &[50.0, 90.0, 95.0]);

        assert_eq!(percentiles.get("p50"), Some(&6)); // 50th percentile of 10 values is index 4.5, rounded to 5, so value 6
        assert_eq!(percentiles.get("p90"), Some(&9)); // 90th percentile of 10 values is index 8.1, rounded to 8, so value 9
        assert_eq!(percentiles.get("p95"), Some(&10)); // 95th percentile of 10 values is index 8.55, rounded to 9, so value 10
    }
}
