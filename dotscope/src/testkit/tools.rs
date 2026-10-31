//! The external tools the tests drive: which ones a test may go without, and a bounded way to
//! run them.
//!
//! A test that needs a tool asks [`require_tool`] first. When the tool is missing the test is
//! skipped, unless `DOTSCOPE_REQUIRE_TOOLS=1` is set: then it fails, so a machine that is meant
//! to have the tools (the Linux CI job) never passes a test it did not run. Every tool runs
//! through [`run_with_timeout`], which drains its output while it runs and kills it when it
//! overstays.

use std::{
    fmt,
    io::Read,
    path::Path,
    process::{Child, Command, Output, Stdio},
    sync::OnceLock,
    thread,
    time::{Duration, Instant},
};

use crate::{testkit::mono::TestCapabilities, Error, Result};

/// The environment variable that turns a missing tool from a skip into a failure.
pub const REQUIRE_TOOLS: &str = "DOTSCOPE_REQUIRE_TOOLS";

/// What a test needs from the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolKind {
    /// A C# compiler and a runtime that runs what it builds.
    Toolchain,
    /// An IL disassembler (`monodis`, `ildasm` or `dotnet-ildasm`).
    Disassembler,
    /// Mono's metadata verifier, `peverify`.
    Verifier,
    /// Mono, which runs .NET Framework executables such as the packer samples.
    Mono,
    /// Mono's C# compiler, `mcs`, with Mono to run what it builds: the System.Reflection.Metadata
    /// oracle builds against Mono's framework assemblies.
    MonoCompiler,
}

impl fmt::Display for ToolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ToolKind::Toolchain => "a C# compiler and runtime",
            ToolKind::Disassembler => "an IL disassembler",
            ToolKind::Verifier => "Mono's peverify",
            ToolKind::Mono => "Mono",
            ToolKind::MonoCompiler => "Mono's C# compiler (mcs) and Mono",
        })
    }
}

/// The tools this machine has, detected once per test binary.
pub fn capabilities() -> &'static TestCapabilities {
    static CAPABILITIES: OnceLock<TestCapabilities> = OnceLock::new();
    CAPABILITIES.get_or_init(TestCapabilities::detect)
}

/// The machine's tools when it has `kind`; `None`, and the test skips, when it has not.
///
/// # Panics
///
/// When `kind` is missing and `DOTSCOPE_REQUIRE_TOOLS=1` is set.
pub fn require_tool(kind: ToolKind) -> Option<&'static TestCapabilities> {
    let capabilities = capabilities();
    if capabilities.has(kind) {
        return Some(capabilities);
    }
    skip_or_fail(
        kind,
        capabilities,
        std::env::var(REQUIRE_TOOLS).is_ok_and(|v| v == "1"),
    );
    None
}

/// A missing tool: a skip, or a failure when tools are `required`.
fn skip_or_fail(kind: ToolKind, capabilities: &TestCapabilities, required: bool) {
    assert!(
        !required,
        "{kind} is required ({REQUIRE_TOOLS}=1) but missing: {}",
        capabilities.summary()
    );
    eprintln!("skipped: no {kind} ({})", capabilities.summary());
}

/// Runs `command` to completion or for `timeout`, whichever comes first.
///
/// Stdin is closed; stdout and stderr are drained on their own threads while the tool runs, so
/// one that writes more than a pipe holds never blocks. A tool still running at `timeout` is
/// killed and reaped.
///
/// # Errors
///
/// When the tool cannot be started, or did not finish within `timeout`.
pub fn run_with_timeout(command: &mut Command, timeout: Duration) -> Result<Output> {
    let program = command.get_program().to_string_lossy().into_owned();
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Other(format!("`{program}` cannot be started: {e}")))?;
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let status = wait(&mut child, timeout);
    let stdout = stdout.join().unwrap_or_default();
    let stderr = stderr.join().unwrap_or_default();
    match status {
        Some(status) => Ok(Output {
            status,
            stdout,
            stderr,
        }),
        None => Err(Error::Other(format!(
            "`{program}` did not finish within {timeout:?} and was killed"
        ))),
    }
}

/// Reads a pipe to its end on a thread of its own.
fn drain(pipe: Option<impl Read + Send + 'static>) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut bytes);
        }
        bytes
    })
}

/// The child's exit status, or `None` when it overstayed `timeout` and was killed.
fn wait(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// What Mono's metadata verifier, `peverify`, says about an assembly: its findings, empty
/// when it found none.
///
/// Only the metadata check is used: it reads the file and runs nothing, while Mono's IL check
/// needs the assembly's references loaded into a runtime and cannot open most samples.
///
/// # Arguments
///
/// * `path` - The assembly.
/// * `references` - The directory its references are looked up in.
///
/// # Errors
///
/// When `peverify` cannot be started or does not finish within five minutes.
pub fn peverify_metadata_findings(path: &Path, references: &Path) -> Result<String> {
    let output = run_with_timeout(
        Command::new("peverify")
            .args(["--verify", "metadata,error"])
            .arg(path)
            .env("MONO_PATH", references),
        Duration::from_secs(300),
    )?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(text.trim().to_string())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    /// What the child run of this test binary does, by the test it is asked to run.
    const CHILD: &str = "DOTSCOPE_TOOLS_TEST_CHILD";

    /// This test binary, running only `test` with [`CHILD`] set.
    fn child(test: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().expect("the test binary"));
        command
            .args([test, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1");
        command
    }

    #[test]
    fn child_writes_one_mebibyte() {
        if std::env::var_os(CHILD).is_some() {
            std::io::stdout()
                .write_all(&vec![b'x'; 1 << 20])
                .expect("stdout");
        }
    }

    #[test]
    fn child_sleeps() {
        if std::env::var_os(CHILD).is_some() {
            thread::sleep(Duration::from_secs(60));
        }
    }

    #[test]
    fn a_tool_writing_more_than_a_pipe_holds_completes() {
        let output = run_with_timeout(
            &mut child("testkit::tools::tests::child_writes_one_mebibyte"),
            Duration::from_secs(60),
        )
        .expect("the child completes");
        assert!(output.status.success());
        assert!(output.stdout.len() >= 1 << 20, "{}", output.stdout.len());
    }

    #[test]
    fn a_tool_that_overstays_is_killed() {
        let started = Instant::now();
        let result = run_with_timeout(
            &mut child("testkit::tools::tests::child_sleeps"),
            Duration::from_millis(500),
        );
        assert!(
            matches!(&result, Err(Error::Other(m)) if m.contains("did not finish")),
            "{result:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(30));
    }

    #[test]
    fn a_tool_that_cannot_start_is_an_error() {
        let result = run_with_timeout(
            &mut Command::new("dotscope-no-such-tool"),
            Duration::from_secs(5),
        );
        assert!(matches!(result, Err(Error::Other(_))), "{result:?}");
    }

    #[test]
    fn a_missing_tool_is_skipped_when_not_required() {
        skip_or_fail(ToolKind::Verifier, capabilities(), false);
    }

    #[test]
    #[should_panic(expected = "is required (DOTSCOPE_REQUIRE_TOOLS=1) but missing")]
    fn a_missing_tool_fails_when_required() {
        skip_or_fail(ToolKind::Verifier, capabilities(), true);
    }
}
