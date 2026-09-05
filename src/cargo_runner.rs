//! Provides distinct process types for isolated Cargo resolution and final downstream execution.
//! Keeping the types separate prevents candidate code from bypassing later middleware plugins.

use crate::{Result, error};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

pub trait CargoRunner {
    fn run(&self, args: &[String], cwd: &Path, cargo_home: Option<&Path>) -> Result<ExitStatus>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessRunner {
    executable: PathBuf,
}

impl ProcessRunner {
    pub fn new(executable: PathBuf) -> Self {
        Self { executable }
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    fn command(&self, args: &[String], cwd: &Path) -> Command {
        let mut command = Command::new(&self.executable);
        command.args(args).current_dir(cwd);
        command
    }

    fn run(&self, command: &mut Command) -> Result<ExitStatus> {
        command.status().map_err(|run_error| {
            error(format!(
                "dependency-audit: cannot run {}: {run_error}",
                self.executable.display()
            ))
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectCargoRunner(ProcessRunner);

impl DirectCargoRunner {
    pub fn new(executable: PathBuf) -> Self {
        Self(ProcessRunner::new(executable))
    }

    pub fn executable(&self) -> &Path {
        self.0.executable()
    }
}

impl CargoRunner for DirectCargoRunner {
    fn run(&self, args: &[String], cwd: &Path, cargo_home: Option<&Path>) -> Result<ExitStatus> {
        let mut command = self.0.command(args, cwd);
        if let Some(cargo_home) = cargo_home {
            command.env("CARGO_HOME", cargo_home);
        }
        self.0.run(&mut command)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownstreamRunner(ProcessRunner);

impl DownstreamRunner {
    pub fn new(executable: PathBuf) -> Self {
        Self(ProcessRunner::new(executable))
    }

    pub fn executable(&self) -> &Path {
        self.0.executable()
    }

    pub fn run(&self, args: &[String], cwd: &Path) -> Result<ExitStatus> {
        let mut command = self.0.command(args, cwd);
        self.0.run(&mut command)
    }
}
