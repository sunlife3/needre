//! Runtime configuration loaded from a config file.
//!
//! The config file is organized into categories and parameters:
//!
//! - A category is a name in brackets on its own line, e.g. `[processmonitor]`.
//! - A parameter is a `key value` pair (separated by whitespace) belonging to
//!   the most recently declared category, e.g. `directory /tmp`.
//! - `#` starts a comment; blank lines are ignored.
//!
//! Example:
//!
//! ```text
//! [processmonitor]
//! directory /tmp
//! directory /dev/shm
//! ```
//!
//! An execve whose binary path starts with any monitored `directory` raises a
//! detection (alert log + process-tree trace).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::{env, fs};

use anyhow::{Context, Result};
use log::{info, warn};

/// Environment variable that overrides the default config path.
const CONFIG_ENV: &str = "NEEDRE_CONFIG";
/// Default location of the config file.
const DEFAULT_CONFIG_PATH: &str = "/etc/needre/needre.conf";
/// Fallback monitored directory used when no directories are configured.
const DEFAULT_MONITOR_DIR: &str = "/tmp";

/// Category holding the process-execution monitoring settings.
const SECTION_PROCESS_MONITOR: &str = "processmonitor";
/// Parameter naming a directory prefix to monitor.
const KEY_DIRECTORY: &str = "directory";

/// A parsed config file: category name -> list of `(key, value)` parameters.
/// Parameters are kept in file order and a key may repeat (e.g. multiple
/// `directory` entries).
type Sections = HashMap<String, Vec<(String, String)>>;

/// Runtime configuration for needre.
#[derive(Debug, Clone)]
pub struct Config {
    /// Directory path prefixes to monitor. An execve whose binary path starts
    /// with any of these raises a detection.
    pub monitor_dirs: Vec<String>,
}

impl Config {
    /// Resolve the config path (`NEEDRE_CONFIG` env var, else the default),
    /// load it, and fall back to monitoring `/tmp` when no file is present.
    pub fn load() -> Result<Self> {
        let path = env::var_os(CONFIG_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));

        if !path.exists() {
            warn!(
                "config file {} not found; monitoring default directory {}",
                path.display(),
                DEFAULT_MONITOR_DIR
            );
            return Ok(Self {
                monitor_dirs: vec![DEFAULT_MONITOR_DIR.to_string()],
            });
        }

        Self::from_path(&path)
    }

    /// Parse the config file at `path`, falling back to the default directory
    /// if it monitors none.
    pub fn from_path(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let sections = parse(&text);
        let mut config = Self::from_sections(&sections);

        if config.monitor_dirs.is_empty() {
            warn!(
                "config file {} monitors no directories; monitoring default {}",
                path.display(),
                DEFAULT_MONITOR_DIR
            );
            config.monitor_dirs.push(DEFAULT_MONITOR_DIR.to_string());
        }
        info!(
            "loaded config from {}: monitoring {:?}",
            path.display(),
            config.monitor_dirs
        );
        Ok(config)
    }

    /// Interpret parsed categories into a [`Config`]. New settings should be
    /// read out of `sections` here as they are added.
    fn from_sections(sections: &Sections) -> Self {
        let monitor_dirs = sections
            .get(SECTION_PROCESS_MONITOR)
            .into_iter()
            .flatten()
            .filter(|(key, _)| key == KEY_DIRECTORY)
            .map(|(_, value)| value.clone())
            .filter(|value| !value.is_empty())
            .collect();
        Self { monitor_dirs }
    }

    /// Return the first monitored prefix that `path` starts with, if any.
    pub fn matching_prefix<'a>(&'a self, path: &str) -> Option<&'a str> {
        self.monitor_dirs
            .iter()
            .map(String::as_str)
            .find(|prefix| path.starts_with(prefix))
    }
}

/// Parse config text into categorized `(key, value)` parameters.
///
/// `[name]` opens a category; subsequent `key value` lines belong to it.
/// Parameters that appear before any category are reported and skipped.
fn parse(text: &str) -> Sections {
    let mut sections: Sections = HashMap::new();
    let mut current: Option<String> = None;

    for (idx, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }

        // Category header: [name]
        if let Some(inner) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let name = inner.trim().to_string();
            sections.entry(name.clone()).or_default();
            current = Some(name);
            continue;
        }

        // Parameter: key[space]value
        match current {
            Some(ref section) => {
                let (key, value) = match line.split_once(char::is_whitespace) {
                    Some((k, v)) => (k.trim().to_string(), v.trim().to_string()),
                    None => (line.to_string(), String::new()),
                };
                // `entry` was created when the section header was seen.
                sections.entry(section.clone()).or_default().push((key, value));
            }
            None => warn!(
                "config line {}: \"{}\" appears before any [category]; ignored",
                idx + 1,
                line
            ),
        }
    }

    sections
}

/// Remove an inline `#` comment from a line.
fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn extracts_monitored_directories() {
        let text = "\
# needre configuration
[processmonitor]
directory /tmp
  directory   /dev/shm   # in-memory tmpfs

directory /var/tmp
";
        let cfg = Config::from_sections(&super::parse(text));
        assert_eq!(cfg.monitor_dirs, ["/tmp", "/dev/shm", "/var/tmp"]);
    }

    #[test]
    fn ignores_unknown_sections_and_keys() {
        let text = "\
[processmonitor]
directory /tmp
loglevel debug

[network]
port 8080
";
        let cfg = Config::from_sections(&super::parse(text));
        assert_eq!(cfg.monitor_dirs, ["/tmp"]);
    }

    #[test]
    fn parameters_before_a_category_are_skipped() {
        let text = "\
directory /orphan
[processmonitor]
directory /tmp
";
        let cfg = Config::from_sections(&super::parse(text));
        assert_eq!(cfg.monitor_dirs, ["/tmp"]);
    }

    #[test]
    fn matches_first_prefix() {
        let cfg = Config {
            monitor_dirs: vec!["/tmp".to_string(), "/dev/shm".to_string()],
        };
        assert_eq!(cfg.matching_prefix("/tmp/evil"), Some("/tmp"));
        assert_eq!(cfg.matching_prefix("/dev/shm/x"), Some("/dev/shm"));
        assert_eq!(cfg.matching_prefix("/usr/bin/ls"), None);
    }
}
