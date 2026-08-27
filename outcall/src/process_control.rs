use std::io::{Read, Write};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::anyhow;

#[derive(Debug)]
pub(crate) enum ProcessRunError {
    TimedOut { timeout: Duration },
    OutputLimit { stream: &'static str, limit: usize },
    Io(anyhow::Error),
}

pub(crate) fn output_with_limits(
    command: &mut Command,
    timeout: Duration,
    output_limit: usize,
) -> Result<Output, ProcessRunError> {
    output_with_input_limits(command, None, timeout, output_limit)
}

pub(crate) fn status_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> Result<ExitStatus, ProcessRunError> {
    let child = command
        .configure_process_group()
        .spawn()
        .map_err(|error| ProcessRunError::Io(error.into()))?;
    let mut child = ChildGuard::new(child);
    let started = Instant::now();

    loop {
        match child.child_mut().try_wait() {
            Ok(Some(status)) => {
                child.disarm();
                return Ok(status);
            }
            Ok(None) if started.elapsed() >= timeout => {
                child.terminate_and_reap().map_err(ProcessRunError::Io)?;
                return Err(ProcessRunError::TimedOut { timeout });
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                let cleanup = child.terminate_and_reap();
                return Err(ProcessRunError::Io(with_cleanup_error(
                    error.into(),
                    cleanup,
                )));
            }
        }
    }
}

pub(crate) fn output_with_input_limits(
    command: &mut Command,
    input: Option<Vec<u8>>,
    timeout: Duration,
    output_limit: usize,
) -> Result<Output, ProcessRunError> {
    if output_limit == 0 {
        return Err(ProcessRunError::Io(anyhow!(
            "process output limit must be greater than zero"
        )));
    }

    let child = command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .configure_process_group()
        .spawn()
        .map_err(|error| ProcessRunError::Io(error.into()))?;
    let mut child = ChildGuard::new(child);
    let stdout = child
        .child_mut()
        .stdout
        .take()
        .ok_or_else(|| child.cleanup_error(anyhow!("child stdout pipe is unavailable")))?;
    let stderr = child
        .child_mut()
        .stderr
        .take()
        .ok_or_else(|| child.cleanup_error(anyhow!("child stderr pipe is unavailable")))?;
    let stdout_reader = spawn_bounded_reader(stdout, output_limit);
    let stderr_reader = spawn_bounded_reader(stderr, output_limit);
    let stdin_writer = match input {
        Some(input) => {
            let Some(stdin) = child.child_mut().stdin.take() else {
                let error = child.cleanup_error(anyhow!("child stdin pipe is unavailable"));
                join_after_termination(stdout_reader, stderr_reader, None);
                return Err(error);
            };
            Some(spawn_input_writer(stdin, input))
        }
        None => None,
    };
    let started = Instant::now();

    let status = loop {
        match child.child_mut().try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= timeout => {
                let cleanup = child.terminate_and_reap();
                join_after_termination(stdout_reader, stderr_reader, stdin_writer);
                if let Err(error) = cleanup {
                    return Err(ProcessRunError::Io(anyhow!(
                        "process timed out after {timeout:?}; cleanup failed: {error}"
                    )));
                }
                return Err(ProcessRunError::TimedOut { timeout });
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                let cleanup = child.terminate_and_reap();
                join_after_termination(stdout_reader, stderr_reader, stdin_writer);
                return Err(ProcessRunError::Io(with_cleanup_error(
                    error.into(),
                    cleanup,
                )));
            }
        }
    };
    child.disarm();

    let stdout = join_reader(stdout_reader).map_err(ProcessRunError::Io)?;
    let stderr = join_reader(stderr_reader).map_err(ProcessRunError::Io)?;
    let input_result = join_writer(stdin_writer);
    if stdout.exceeded {
        return Err(ProcessRunError::OutputLimit {
            stream: "stdout",
            limit: output_limit,
        });
    }
    if stderr.exceeded {
        return Err(ProcessRunError::OutputLimit {
            stream: "stderr",
            limit: output_limit,
        });
    }
    if status.success() {
        input_result.map_err(ProcessRunError::Io)?;
    }

    Ok(Output {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

struct ChildGuard {
    child: Child,
    armed: bool,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child, armed: true }
    }

    fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn terminate_and_reap(&mut self) -> anyhow::Result<()> {
        if !self.armed {
            return Ok(());
        }
        let terminate_result = terminate_process_group(&mut self.child);
        let wait_result = self.child.wait().map(|_| ()).map_err(anyhow::Error::from);
        self.armed = false;
        combine_cleanup_results(terminate_result, wait_result)
    }

    fn cleanup_error(&mut self, primary: anyhow::Error) -> ProcessRunError {
        ProcessRunError::Io(with_cleanup_error(primary, self.terminate_and_reap()))
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.armed {
            // Drop is the last-resort guard for unwinding; normal error paths
            // call `terminate_and_reap` and report any cleanup failure.
            drop(terminate_process_group(&mut self.child));
            drop(self.child.wait());
        }
    }
}

fn combine_cleanup_results(
    terminate: anyhow::Result<()>,
    wait: anyhow::Result<()>,
) -> anyhow::Result<()> {
    match (terminate, wait) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(terminate), Err(wait)) => Err(anyhow!(
            "failed to terminate child: {terminate}; failed to reap child: {wait}"
        )),
    }
}

fn with_cleanup_error(primary: anyhow::Error, cleanup: anyhow::Result<()>) -> anyhow::Error {
    match cleanup {
        Ok(()) => primary,
        Err(cleanup) => anyhow!("{primary}; process cleanup also failed: {cleanup}"),
    }
}

fn join_after_termination(
    stdout: JoinHandle<std::io::Result<BoundedOutput>>,
    stderr: JoinHandle<std::io::Result<BoundedOutput>>,
    stdin: Option<JoinHandle<std::io::Result<()>>>,
) {
    // Killing the process closes its pipes. Join all helper threads so no
    // process I/O work survives the caller; pipe errors are expected here.
    drop(join_reader(stdout));
    drop(join_reader(stderr));
    drop(join_writer(stdin));
}

fn spawn_input_writer(
    mut stdin: std::process::ChildStdin,
    input: Vec<u8>,
) -> JoinHandle<std::io::Result<()>> {
    std::thread::spawn(move || stdin.write_all(&input))
}

fn join_writer(writer: Option<JoinHandle<std::io::Result<()>>>) -> anyhow::Result<()> {
    let Some(writer) = writer else {
        return Ok(());
    };
    writer
        .join()
        .map_err(|_| anyhow!("process input writer thread panicked"))?
        .map_err(Into::into)
}

trait CommandProcessGroupExt {
    fn configure_process_group(&mut self) -> &mut Command;
}

#[cfg(unix)]
impl CommandProcessGroupExt for Command {
    fn configure_process_group(&mut self) -> &mut Command {
        use std::os::unix::process::CommandExt;

        self.process_group(0)
    }
}

#[cfg(not(unix))]
impl CommandProcessGroupExt for Command {
    fn configure_process_group(&mut self) -> &mut Command {
        self
    }
}

#[cfg(unix)]
fn terminate_process_group(child: &mut std::process::Child) -> anyhow::Result<()> {
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;

    if let Ok(pid) = i32::try_from(child.id())
        && killpg(Pid::from_raw(pid), Signal::SIGKILL).is_ok()
    {
        return Ok(());
    }
    child.kill().map_err(Into::into)
}

#[cfg(not(unix))]
fn terminate_process_group(child: &mut std::process::Child) -> anyhow::Result<()> {
    child.kill().map_err(Into::into)
}

struct BoundedOutput {
    bytes: Vec<u8>,
    exceeded: bool,
}

fn spawn_bounded_reader(
    reader: impl Read + Send + 'static,
    limit: usize,
) -> JoinHandle<std::io::Result<BoundedOutput>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::with_capacity(limit.min(8192));
        reader
            .take((limit as u64).saturating_add(1))
            .read_to_end(&mut bytes)?;
        let exceeded = bytes.len() > limit;
        if exceeded {
            bytes.truncate(limit);
        }
        Ok(BoundedOutput { bytes, exceeded })
    })
}

fn join_reader(
    reader: JoinHandle<std::io::Result<BoundedOutput>>,
) -> anyhow::Result<BoundedOutput> {
    reader
        .join()
        .map_err(|_| anyhow!("process output reader thread panicked"))?
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_stdout_and_stderr() {
        let output = output_with_limits(
            Command::new("sh").args(["-c", "printf out; printf err >&2"]),
            Duration::from_secs(1),
            1024,
        )
        .unwrap();

        assert_eq!(output.stdout, b"out");
        assert_eq!(output.stderr, b"err");
    }

    #[test]
    fn sends_bounded_process_input() {
        let output = output_with_input_limits(
            &mut Command::new("cat"),
            Some(b"request body".to_vec()),
            Duration::from_secs(1),
            1024,
        )
        .unwrap();

        assert_eq!(output.stdout, b"request body");
    }

    #[test]
    fn rejects_output_over_the_limit() {
        let error = output_with_limits(
            Command::new("sh").args(["-c", "printf 12345"]),
            Duration::from_secs(1),
            4,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ProcessRunError::OutputLimit {
                stream: "stdout",
                limit: 4
            }
        ));
    }

    #[test]
    fn terminates_process_at_timeout() {
        let started = Instant::now();
        let error = output_with_limits(
            Command::new("sh").args(["-c", "sleep 5 & wait"]),
            Duration::from_millis(50),
            1024,
        )
        .unwrap_err();

        assert!(matches!(error, ProcessRunError::TimedOut { .. }));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn status_runner_returns_status_and_enforces_timeout() {
        let status = status_with_timeout(
            Command::new("sh").args(["-c", "exit 7"]),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(status.code(), Some(7));

        let error = status_with_timeout(
            Command::new("sh").args(["-c", "sleep 5 & wait"]),
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(matches!(error, ProcessRunError::TimedOut { .. }));
    }
}
