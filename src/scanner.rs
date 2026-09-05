//! Conservatively scans Rust source text for security-relevant capabilities.
//! The scanner is heuristic and never compiles, loads, or executes inspected code.

use crate::findings::{Finding, SourceEvidence};
use std::collections::BTreeSet;

pub const SCANNER_VERSION: u32 = 1;

pub fn scan_rust_source(source: &str, context: &str) -> BTreeSet<Finding> {
    let mut findings = BTreeSet::new();
    let original_source = source;
    let source = source_without_comments(original_source);
    let compact: String = source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();

    let command_aliases = command_aliases(&source);
    let mut process_patterns = vec![
        "std::process",
        "process::Command",
        "Command::new",
        "Command::spawn",
        "Command::status",
        "Command::output",
        "libc::system",
        "::exec",
        "nix::unistd::exec",
    ];
    let alias_patterns: Vec<String> = command_aliases
        .iter()
        .flat_map(|alias| [format!("{alias}::new"), format!("{alias}::spawn")])
        .collect();
    let process_detected = process_patterns
        .iter()
        .any(|pattern| source.contains(pattern))
        || alias_patterns
            .iter()
            .any(|pattern| source.contains(pattern))
        || compact.contains("Command::new")
        || compact.contains("Command::spawn")
        || compact.contains("Command::status")
        || compact.contains("Command::output");
    if process_detected {
        findings.insert(
            Finding::new(
                "process-execution",
                format!("process API referenced in {context}"),
            )
            .with_evidence(source_evidence(
                original_source,
                &source,
                context,
                &[
                    "std::process",
                    "process::Command",
                    "Command",
                    "libc::system",
                    "::exec",
                ],
            )),
        );
    }

    process_patterns.extend(["Command :: new", "Command :: spawn"]);
    let mut literal_target_found = false;
    let mut downloader_target_found = false;
    for pattern in process_patterns
        .iter()
        .copied()
        .chain(alias_patterns.iter().map(String::as_str))
    {
        if let Some(target) = literal_call_argument(&source, pattern) {
            literal_target_found = true;
            downloader_target_found |= is_network_executable(&target);
            findings.insert(
                Finding::new(
                    "command-target",
                    format!("literal executable `{target}` in {context}"),
                )
                .with_evidence(source_evidence(
                    original_source,
                    &source,
                    context,
                    &[pattern],
                )),
            );
            if is_high_suspicion_executable(&target) {
                findings.insert(
                    Finding::new(
                        "shell-or-downloader",
                        format!("high-suspicion executable `{target}` in {context}"),
                    )
                    .with_evidence(source_evidence(
                        original_source,
                        &source,
                        context,
                        &[pattern],
                    )),
                );
            }
        }
    }
    if process_detected && !literal_target_found {
        findings.insert(
            Finding::new(
                "command-target",
                format!("unknown or dynamically constructed process target in {context}"),
            )
            .with_evidence(source_evidence(
                original_source,
                &source,
                context,
                &[
                    "std::process",
                    "process::Command",
                    "Command",
                    "libc::system",
                    "::exec",
                ],
            )),
        );
    }

    let standard_network_operation = [
        "TcpStream::connect",
        "TcpStream::connect_timeout",
        "TcpListener::bind",
        "UdpSocket::bind",
        "UdpSocket::connect",
        "UdpSocket::send_to",
        "UdpSocket::recv_from",
        "ToSocketAddrs::to_socket_addrs",
        ".to_socket_addrs(",
    ]
    .iter()
    .any(|pattern| compact.contains(pattern));
    if downloader_target_found
        || standard_network_operation
        || ["reqwest", "ureq", "hyper::", "curl::", "isahc", "attohttpc"]
            .iter()
            .any(|pattern| source.contains(pattern))
    {
        findings.insert(
            Finding::new(
                "network-access",
                format!("network API or client referenced in {context}"),
            )
            .with_evidence(source_evidence(
                original_source,
                &source,
                context,
                &[
                    "TcpStream",
                    "TcpListener",
                    "UdpSocket",
                    "ToSocketAddrs",
                    "reqwest",
                    "ureq",
                    "hyper::",
                    "curl::",
                    "isahc",
                    "attohttpc",
                    "wget",
                ],
            )),
        );
    }

    if [
        "fs::write",
        "File::create",
        "OpenOptions",
        "remove_file",
        "remove_dir",
        "remove_dir_all",
        "fs::rename",
        "fs::copy",
        "set_permissions",
        "create_dir",
        "create_dir_all",
    ]
    .iter()
    .any(|pattern| source.contains(pattern))
    {
        findings.insert(
            Finding::new(
                "filesystem-modification",
                format!("filesystem mutation API referenced in {context}"),
            )
            .with_evidence(source_evidence(
                original_source,
                &source,
                context,
                &[
                    "fs::write",
                    "File::create",
                    "OpenOptions",
                    "remove_file",
                    "remove_dir",
                    "fs::rename",
                    "fs::copy",
                    "set_permissions",
                    "create_dir",
                ],
            )),
        );
    }

    if ["env::var", "env::vars", "std::env", "option_env!", "env!"]
        .iter()
        .any(|pattern| source.contains(pattern))
        || [
            "HOME",
            "USERPROFILE",
            "SSH_AUTH_SOCK",
            "GITHUB_TOKEN",
            "AWS_",
            "TOKEN",
            "SECRET",
            "PASSWORD",
            "CREDENTIAL",
        ]
        .iter()
        .any(|pattern| source.contains(pattern))
    {
        findings.insert(Finding::new(
            "environment-access",
            format!("environment or credential-like name referenced in {context}; values are never read by the scanner"),
        ).with_evidence(source_evidence(
            original_source,
            &source,
            context,
            &[
                "env::var", "env::vars", "std::env", "option_env!", "env!", "HOME",
                "USERPROFILE", "SSH_AUTH_SOCK", "GITHUB_TOKEN", "AWS_", "TOKEN", "SECRET",
                "PASSWORD", "CREDENTIAL",
            ],
        )));
    }

    if [
        "libloading",
        "dlopen",
        "LoadLibrary",
        "extern\"C\"",
        "extern\"system\"",
        "libc::system",
    ]
    .iter()
    .any(|pattern| compact.contains(&pattern.replace(' ', "")))
    {
        findings.insert(
            Finding::new(
                "dynamic-loading-or-ffi",
                format!("dynamic loading or native-call primitive referenced in {context}"),
            )
            .with_evidence(source_evidence(
                original_source,
                &source,
                context,
                &[
                    "libloading",
                    "dlopen",
                    "LoadLibrary",
                    "extern",
                    "libc::system",
                ],
            )),
        );
    }

    let capabilities: BTreeSet<_> = findings
        .iter()
        .map(|finding| finding.capability.as_str())
        .collect();
    if capabilities.contains("network-access") && capabilities.contains("process-execution") {
        findings.insert(Finding::new(
            "high-risk-combination",
            format!("network access combined with process execution in {context}"),
        ));
    } else if capabilities.contains("network-access")
        && capabilities.contains("filesystem-modification")
    {
        findings.insert(Finding::new(
            "high-risk-combination",
            format!("network access combined with filesystem modification in {context}"),
        ));
    }
    findings
}

pub fn source_evidence(
    original_source: &str,
    scanned_source: &str,
    context: &str,
    patterns: &[&str],
) -> Option<SourceEvidence> {
    let offset = patterns
        .iter()
        .filter_map(|pattern| scanned_source.find(pattern))
        .min()?;
    let focus_line = scanned_source.as_bytes()[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1;
    let all_lines: Vec<_> = original_source.lines().collect();
    let first_line = focus_line.saturating_sub(2).max(1);
    let last_line = (focus_line + 2).min(all_lines.len());
    let lines = all_lines[first_line - 1..last_line]
        .iter()
        .map(|line| bounded_line(line))
        .collect();
    Some(SourceEvidence {
        path: context
            .strip_prefix("potential build-time helper ")
            .unwrap_or(context)
            .to_owned(),
        first_line,
        focus_line,
        lines,
    })
}

fn bounded_line(line: &str) -> String {
    const MAX_CHARS: usize = 240;
    let mut bounded: String = line.chars().take(MAX_CHARS).collect();
    if line.chars().count() > MAX_CHARS {
        bounded.push('…');
    }
    bounded
}

/// Removes Rust line and nested block comments while leaving code and string literals intact.
/// This prevents issue links and documentation examples from becoming executable-capability
/// findings. A URL literal is not itself proof that code can open a network connection.
fn source_without_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index..].starts_with(b"//") {
            output.extend_from_slice(b"  ");
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(b' ');
                index += 1;
            }
        } else if bytes[index..].starts_with(b"/*") {
            output.extend_from_slice(b"  ");
            index += 2;
            let mut depth = 1usize;
            while index < bytes.len() && depth > 0 {
                if bytes[index..].starts_with(b"/*") {
                    output.extend_from_slice(b"  ");
                    index += 2;
                    depth += 1;
                } else if bytes[index..].starts_with(b"*/") {
                    output.extend_from_slice(b"  ");
                    index += 2;
                    depth -= 1;
                } else {
                    output.push(if bytes[index] == b'\n' { b'\n' } else { b' ' });
                    index += 1;
                }
            }
        } else if let Some((prefix_length, hashes)) = raw_string_prefix(bytes, index) {
            let content_start = index + prefix_length;
            output.extend_from_slice(&bytes[index..content_start]);
            index = content_start;
            while index < bytes.len() {
                output.push(bytes[index]);
                if bytes[index] == b'"'
                    && bytes
                        .get(index + 1..index + 1 + hashes)
                        .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
                {
                    index += 1;
                    output.extend_from_slice(&bytes[index..index + hashes]);
                    index += hashes;
                    break;
                }
                index += 1;
            }
        } else if bytes[index] == b'"' {
            output.push(bytes[index]);
            index += 1;
            let mut escaped = false;
            while index < bytes.len() {
                let byte = bytes[index];
                output.push(byte);
                index += 1;
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    break;
                }
            }
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(output).expect("comment removal preserves UTF-8")
}

fn raw_string_prefix(bytes: &[u8], index: usize) -> Option<(usize, usize)> {
    let mut cursor = index;
    if bytes.get(cursor) == Some(&b'b') {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'r') {
        return None;
    }
    cursor += 1;
    let hash_start = cursor;
    while bytes.get(cursor) == Some(&b'#') {
        cursor += 1;
    }
    (bytes.get(cursor) == Some(&b'"')).then_some((cursor + 1 - index, cursor - hash_start))
}

fn command_aliases(source: &str) -> Vec<String> {
    let mut aliases = Vec::new();
    for line in source.lines() {
        let compact: String = line
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        for prefix in ["usestd::process::Commandas", "usestd::process::{Commandas"] {
            if let Some(rest) = compact.strip_prefix(prefix) {
                let alias: String = rest
                    .chars()
                    .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
                    .collect();
                if !alias.is_empty() {
                    aliases.push(alias);
                }
            }
        }
    }
    aliases
}

fn literal_call_argument(source: &str, pattern: &str) -> Option<String> {
    let start = source.find(pattern)? + pattern.len();
    let rest = source[start..].trim_start();
    let rest = rest.strip_prefix('(')?.trim_start();
    let quote = rest.chars().next()?;
    if !matches!(quote, '\'' | '"') {
        return None;
    }
    let body = &rest[quote.len_utf8()..];
    let end = body.find(quote)?;
    Some(body[..end].to_owned())
}

fn is_high_suspicion_executable(target: &str) -> bool {
    let target = target
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(target)
        .to_ascii_lowercase();
    [
        "curl",
        "wget",
        "sh",
        "bash",
        "zsh",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "python",
        "python3",
        "perl",
        "ruby",
        "wscript",
        "cscript",
        "mshta",
    ]
    .contains(&target.as_str())
}

fn is_network_executable(target: &str) -> bool {
    let target = target
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(target)
        .to_ascii_lowercase();
    ["curl", "wget"].contains(&target.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_alias_process_network_write_env_and_shell_combination() {
        let source = r#"
            use std::process::Command as C;
            use std::net::TcpStream;
            fn main() {
            let _ = std::env::var("GITHUB_TOKEN");
            std::fs::write("payload", b"x").unwrap();
            let _ = libloading::Library::new("plugin");
                C::new("sh").status().unwrap();
                TcpStream::connect("127.0.0.1:1").unwrap();
            }
        "#;
        let findings = scan_rust_source(source, "build.rs");
        let capabilities: BTreeSet<_> = findings.iter().map(|f| f.capability.as_str()).collect();
        for expected in [
            "process-execution",
            "command-target",
            "shell-or-downloader",
            "network-access",
            "filesystem-modification",
            "environment-access",
            "dynamic-loading-or-ffi",
            "high-risk-combination",
        ] {
            assert!(
                capabilities.contains(expected),
                "missing {expected}: {findings:?}"
            );
        }
    }

    #[test]
    fn issue_links_and_documentation_urls_are_not_network_capabilities() {
        let source = r##"
            // https://github.com/example/project/issues/1
            /* nested /* https://example.invalid */ comment */
            #![doc(html_root_url = "https://docs.rs/example/1.0.0")]
            fn main() {
                std::process::Command::new("rustc").status().unwrap();
            }
        "##;
        let findings = scan_rust_source(source, "build.rs");
        let capabilities: BTreeSet<_> = findings
            .iter()
            .map(|finding| finding.capability.as_str())
            .collect();
        assert!(capabilities.contains("process-execution"));
        assert!(!capabilities.contains("network-access"));
        assert!(!capabilities.contains("high-risk-combination"));
    }

    #[test]
    fn comments_cannot_manufacture_other_capabilities() {
        let source = r#"
            // Command::new("sh"); std::env::var("GITHUB_TOKEN");
            /* std::fs::write("payload", b"x"); */
            fn main() {}
        "#;
        assert!(scan_rust_source(source, "build.rs").is_empty());
    }

    #[test]
    fn a_literal_downloader_target_is_a_network_capability() {
        let findings = scan_rust_source(
            r#"fn main() { std::process::Command::new("curl").status(); }"#,
            "build.rs",
        );
        let capabilities: BTreeSet<_> = findings
            .iter()
            .map(|finding| finding.capability.as_str())
            .collect();
        assert!(capabilities.contains("network-access"));
        assert!(capabilities.contains("shell-or-downloader"));
        assert!(capabilities.contains("high-risk-combination"));
    }

    #[test]
    fn passive_network_types_are_not_network_operations() {
        let source = r#"
            use std::net::Ipv4Addr;
            pub use std::net;
            fn keep_address(address: Ipv4Addr) -> Ipv4Addr { address }
        "#;
        assert!(scan_rust_source(source, "src/lib.rs").is_empty());
    }
}
