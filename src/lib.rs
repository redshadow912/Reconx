// Collector response structs are constructed by serde deserialization,
// not by Rust code directly. Allow dead_code for the collectors module.
#[allow(dead_code)]
pub mod collectors;

pub mod analyzers;
pub mod cli;
pub mod config;
pub mod dns;
pub mod error;
pub mod models;
pub mod output;
pub mod probe;
pub mod reports;
