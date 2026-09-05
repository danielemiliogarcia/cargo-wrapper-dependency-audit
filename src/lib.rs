//! Security analysis and transaction engine for the Dependency Audit plugin.
//! Host protocol parsing and executable dispatch remain isolated from these modules.

pub mod approvals;
pub mod archive_inspector;
pub mod candidate;
pub mod cargo_runner;
pub mod command_policy;
pub mod factory_approvals;
pub mod findings;
pub mod lockfile;
pub mod prompt;
pub mod protocol;
pub mod registry;
pub mod scanner;
pub mod security;
pub mod workspace;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, BoxError>;

pub fn error(message: impl Into<String>) -> BoxError {
    std::io::Error::other(message.into()).into()
}
