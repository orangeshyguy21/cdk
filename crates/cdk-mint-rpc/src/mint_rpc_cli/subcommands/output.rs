//! Output helpers shared by the federation commands.

use cdk_common::terminal::escape_control;
use clap::Args;

/// Output options for read commands.
#[derive(Debug, Args)]
pub struct OutputCommand {
    /// Print JSON instead of text
    #[arg(long, default_value_t = false)]
    pub(super) json: bool,
}

/// An escaped server string, or `none`.
pub(super) fn text(value: Option<&str>) -> String {
    value
        .map(escape_control)
        .unwrap_or_else(|| "none".to_string())
}

/// A value, or `none`.
pub(super) fn number<T>(value: Option<T>) -> String
where
    T: ToString,
{
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string())
}

/// Comma-separated values, or `none`.
pub(super) fn list<T>(values: &[T]) -> String
where
    T: ToString,
{
    match values {
        [] => "none".to_string(),
        values => values
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
    }
}
