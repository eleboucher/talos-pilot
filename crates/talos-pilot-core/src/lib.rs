//! talos-pilot-core: Core business logic for talos-pilot
//!
//! This crate contains domain types, shared utilities, and business logic
//! for the talos-pilot TUI. It is intentionally kept independent of any
//! TUI framework to enable:
//!
//! - Unit testing without UI dependencies
//! - Reuse in CLI tools or other consumers
//! - Clear separation between business logic and presentation
//!
//! # Modules
//!
//! - [`types`] - Core domain types (Cluster, Node, Service, etc.)
//! - [`indicators`] - Health and status indicators for consistent UI representation
//! - [`formatting`] - Utilities for formatting bytes, durations, percentages, etc.
//! - [`selection`] - Generic selection logic for list-based UI components

pub mod formatting;
pub mod indicators;
pub mod selection;
pub mod types;

// Re-export commonly used items at crate root
pub use formatting::*;
pub use indicators::*;
pub use selection::*;
pub use types::*;
