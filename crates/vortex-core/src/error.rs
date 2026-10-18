//! Structured error type with stable codes and actionable messages.
//!
//! Every error carries a machine-readable [`ErrorCode`], a human-readable
//! message, and optional `detail` and `hint` fields. The same error value is
//! rendered as JSON for machine consumption and as text for humans.

use serde::Serialize;
use std::fmt;

/// Stable machine-readable error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Input validation failed (bad arguments, empty paths, bad options).
    Validation,
    /// The requested path does not exist.
    NotFound,
    /// The path exists but is not a regular file or directory.
    NotFileOrDir,
    /// A resolved path would escape the configured inspection root.
    PathOutsideRoot,
    /// More files than the configured limit were encountered.
    TooManyFiles,
    /// A single file exceeded the per-file byte limit.
    FileTooLarge,
    /// The total bytes read exceeded the configured budget.
    TotalSizeExceeded,
    /// The operation exceeded its time budget.
    Timeout,
    /// The operation was cancelled before completing.
    Cancelled,
    /// The artifact format is recognized but not analyzable by any provider.
    UnsupportedFormat,
    /// The requested operation is not implemented by any available provider.
    UnsupportedOperation,
    /// A provider that could handle the request is not installed.
    MissingProvider,
    /// A provider failed while analyzing the artifact.
    ProviderFailure,
    /// The local evidence store could not be read or written.
    Storage,
    /// (De)serialization of structured data failed.
    Serialization,
    /// Underlying I/O failure.
    Io,
    /// Unexpected internal condition; please report a bug.
    Internal,
}

impl ErrorCode {
    /// Stable snake_case identifier used in JSON output.
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Validation => "validation",
            ErrorCode::NotFound => "not_found",
            ErrorCode::NotFileOrDir => "not_file_or_dir",
            ErrorCode::PathOutsideRoot => "path_outside_root",
            ErrorCode::TooManyFiles => "too_many_files",
            ErrorCode::FileTooLarge => "file_too_large",
            ErrorCode::TotalSizeExceeded => "total_size_exceeded",
            ErrorCode::Timeout => "timeout",
            ErrorCode::Cancelled => "cancelled",
            ErrorCode::UnsupportedFormat => "unsupported_format",
            ErrorCode::UnsupportedOperation => "unsupported_operation",
            ErrorCode::MissingProvider => "missing_provider",
            ErrorCode::ProviderFailure => "provider_failure",
            ErrorCode::Storage => "storage",
            ErrorCode::Serialization => "serialization",
            ErrorCode::Io => "io",
            ErrorCode::Internal => "internal",
        }
    }

    /// Process exit code used by the CLI for this error class.
    ///
    /// See README "Exit codes" for the full contract:
    /// 0 success, 1 failure, 2 usage (clap), 3 unsupported, 4 storage,
    /// 5 cancelled, 6 partial.
    pub const fn exit_code(self) -> i32 {
        match self {
            ErrorCode::UnsupportedFormat | ErrorCode::UnsupportedOperation => 3,
            ErrorCode::MissingProvider => 3,
            ErrorCode::Storage => 4,
            ErrorCode::Cancelled => 5,
            _ => 1,
        }
    }
}

/// The single error type used across Vortex-RE.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct VortexError {
    /// Machine-readable error code.
    pub code: ErrorCode,
    /// Short human-readable message.
    pub message: String,
    /// Optional additional context.
    pub detail: Option<String>,
    /// Optional actionable suggestion.
    pub hint: Option<String>,
}

impl VortexError {
    /// Create an error with a code and a message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            detail: None,
            hint: None,
        }
    }

    /// Attach additional detail.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Attach an actionable hint.
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Validation error for invalid input.
    pub fn validation(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Validation, message)
    }

    /// Path-not-found error.
    pub fn not_found(path: impl fmt::Display) -> Self {
        Self::new(ErrorCode::NotFound, format!("path not found: {path}"))
            .with_hint("check the path and try again; quoting helps with spaces")
    }

    /// Path escapes the inspection root.
    pub fn path_outside_root(detail: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::PathOutsideRoot,
            "resolved path escapes the inspection root",
        )
        .with_detail(detail)
    }

    /// Time budget exhausted.
    pub fn timeout(seconds: u64) -> Self {
        Self::new(
            ErrorCode::Timeout,
            format!("time budget of {seconds}s exhausted"),
        )
        .with_hint("raise --timeout-secs or narrow the target")
    }

    /// Unsupported artifact format for the requested operation.
    pub fn unsupported_format(format: impl fmt::Display, hint: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::UnsupportedFormat,
            format!("unsupported artifact format for this operation: {format}"),
        )
        .with_hint(hint)
    }

    /// Operation not implemented by any available provider.
    pub fn unsupported_operation(operation: impl fmt::Display) -> Self {
        Self::new(
            ErrorCode::UnsupportedOperation,
            format!("no available provider implements '{operation}' for this input"),
        )
        .with_hint("run 'vortex capabilities' to see supported operations")
    }

    /// Missing optional provider.
    pub fn missing_provider(provider: impl fmt::Display, hint: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::MissingProvider,
            format!("optional provider '{provider}' is not installed"),
        )
        .with_hint(hint)
    }

    /// Storage failure.
    pub fn storage(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Storage, message)
    }

    /// Internal failure.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
            .with_hint("this looks like a bug; please report it with the command you ran")
    }

    /// Render as a JSON object for machine-readable output.
    pub fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "code": self.code.as_str(),
            "message": self.message,
        });
        if let Some(detail) = &self.detail {
            obj["detail"] = serde_json::Value::String(detail.clone());
        }
        if let Some(hint) = &self.hint {
            obj["hint"] = serde_json::Value::String(hint.clone());
        }
        obj
    }
}

impl From<std::io::Error> for VortexError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::NotFound => Self::new(ErrorCode::NotFound, err.to_string())
                .with_hint("check the path and try again"),
            std::io::ErrorKind::PermissionDenied => Self::new(ErrorCode::Io, err.to_string())
                .with_hint("check file permissions for the Vortex-RE data directory and target"),
            _ => Self::new(ErrorCode::Io, err.to_string()),
        }
    }
}

impl From<serde_json::Error> for VortexError {
    fn from(err: serde_json::Error) -> Self {
        Self::new(ErrorCode::Serialization, err.to_string())
    }
}

/// Convenient result alias.
pub type VortexResult<T> = Result<T, VortexError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(ErrorCode::Validation.as_str(), "validation");
        assert_eq!(ErrorCode::UnsupportedFormat.as_str(), "unsupported_format");
        assert_eq!(ErrorCode::PathOutsideRoot.as_str(), "path_outside_root");
    }

    #[test]
    fn exit_codes_follow_contract() {
        assert_eq!(ErrorCode::Validation.exit_code(), 1);
        assert_eq!(ErrorCode::UnsupportedFormat.exit_code(), 3);
        assert_eq!(ErrorCode::MissingProvider.exit_code(), 3);
        assert_eq!(ErrorCode::Storage.exit_code(), 4);
        assert_eq!(ErrorCode::Cancelled.exit_code(), 5);
        assert_eq!(ErrorCode::Io.exit_code(), 1);
    }

    #[test]
    fn json_contains_optional_fields_only_when_set() {
        let plain = VortexError::validation("bad input");
        let json = plain.to_json();
        assert_eq!(json["code"], "validation");
        assert!(json.get("hint").is_none());

        let hinted = VortexError::validation("bad input").with_hint("try --help");
        assert_eq!(hinted.to_json()["hint"], "try --help");
    }

    #[test]
    fn io_not_found_maps_to_not_found_code() {
        let err: VortexError = std::io::Error::new(std::io::ErrorKind::NotFound, "gone").into();
        assert_eq!(err.code, ErrorCode::NotFound);
    }
}
