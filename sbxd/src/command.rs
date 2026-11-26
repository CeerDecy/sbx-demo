//! Thin wrappers around the helper programs the daemon shells out to.

use std::{
    io,
    process::{Command, Output},
};

/// Runs `program` to completion and returns its captured output.
pub fn output(program: &str, args: &[&str]) -> io::Result<Output> {
    Command::new(program).args(args).output()
}

/// Runs `program` and maps a non-zero exit to an error carrying its stderr.
pub fn status(program: &str, args: &[&str]) -> io::Result<()> {
    let output = output(program, args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ))
    }
}
