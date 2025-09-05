//! Error types for FluxPrompt operations.

use thiserror::Error;

/// The main error type for FluxPrompt operations.
#[derive(Error, Debug)]
pub enum FluxPromptError {
    /// Configuration validation error
    #[error("Configuration error: {message}")]
    Config {
        /// Error message
        message: String,
    },

    /// Detection engine error
    #[error("Detection error: {message}")]
    Detection {
        /// Error message
        message: String,
    },

    /// Mitigation engine error
    #[error("Mitigation error: {message}")]
    Mitigation {
        /// Error message
        message: String,
    },

    /// Pattern compilation error
    #[error("Pattern compilation error: {source}")]
    PatternCompilation {
        #[from]
        /// Regex error source
        source: regex::Error,
    },

    /// I/O error
    #[error("I/O error: {source}")]
    Io {
        #[from]
        /// I/O error source
        source: std::io::Error,
    },

    /// Serialization error
    #[error("Serialization error: {source}")]
    Serialization {
        #[from]
        /// Serialization error source
        source: serde_json::Error,
    },

    /// Async runtime error
    #[error("Async runtime error: {message}")]
    Runtime {
        /// Error message
        message: String,
    },

    /// Invalid input error
    #[error("Invalid input: {message}")]
    InvalidInput {
        /// Error message
        message: String,
    },

    /// Resource limit exceeded
    #[error("Resource limit exceeded: {resource}")]
    ResourceLimit {
        /// Resource name
        resource: String,
    },

    /// Internal error
    #[error("Internal error: {message}")]
    Internal {
        /// Error message
        message: String,
    },
}

impl FluxPromptError {
    /// Creates a new configuration error.
    pub fn config<S: Into<String>>(message: S) -> Self {
        Self::Config {
            message: message.into(),
        }
    }

    /// Creates a new detection error.
    pub fn detection<S: Into<String>>(message: S) -> Self {
        Self::Detection {
            message: message.into(),
        }
    }

    /// Creates a new mitigation error.
    pub fn mitigation<S: Into<String>>(message: S) -> Self {
        Self::Mitigation {
            message: message.into(),
        }
    }

    /// Creates a new runtime error.
    pub fn runtime<S: Into<String>>(message: S) -> Self {
        Self::Runtime {
            message: message.into(),
        }
    }

    /// Creates a new invalid input error.
    pub fn invalid_input<S: Into<String>>(message: S) -> Self {
        Self::InvalidInput {
            message: message.into(),
        }
    }

    /// Creates a new resource limit error.
    pub fn resource_limit<S: Into<String>>(resource: S) -> Self {
        Self::ResourceLimit {
            resource: resource.into(),
        }
    }

    /// Creates a new internal error.
    pub fn internal<S: Into<String>>(message: S) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }
}

/// Result type alias for FluxPrompt operations.
pub type Result<T> = std::result::Result<T, FluxPromptError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let error = FluxPromptError::config("Invalid threshold");
        assert!(matches!(error, FluxPromptError::Config { .. }));

        let error = FluxPromptError::detection("Pattern not found");
        assert!(matches!(error, FluxPromptError::Detection { .. }));
    }

    #[test]
    fn test_error_display() {
        let error = FluxPromptError::config("Test message");
        assert_eq!(error.to_string(), "Configuration error: Test message");
    }
}
