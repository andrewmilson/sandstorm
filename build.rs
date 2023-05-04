use anyhow::Context;
use anyhow::Error;
use anyhow::Result;
use codegen::gen_evaluator;
use layouts::layout6;
use proc_macro2::TokenStream;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;

fn main() -> Result<()> {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let mut dst_path = File::create(Path::new(&out_dir).join("layout6.rs"))?;
    let evaluator = pretty_print(gen_evaluator::<layout6::AirConfig>())?;
    write!(dst_path, "{evaluator}")?;
    Ok(())
}

/// Use `rustfmt` to pretty-print tokens.
/// From: https://github.com/Michael-F-Bryan/scad-rs
pub fn pretty_print(tokens: TokenStream) -> Result<String, Error> {
    let tokens = tokens.to_string();

    let mut child = Command::new("rustfmt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Unable to start `rustfmt`. Is it installed?")?;

    let mut stdin = child.stdin.take().unwrap();
    write!(stdin, "{tokens}")?;
    stdin.flush()?;
    drop(stdin);

    let Output {
        status,
        stdout,
        stderr,
    } = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&stdout);
    let stderr = String::from_utf8_lossy(&stderr);

    if !status.success() {
        eprintln!("---- Stdout ----");
        eprintln!("{stdout}");
        eprintln!("---- Stderr ----");
        eprintln!("{stderr}");
        let code = status.code();
        match code {
            Some(code) => anyhow::bail!("The `rustfmt` command failed with return code {code}"),
            None => anyhow::bail!("The `rustfmt` command failed"),
        }
    }

    Ok(stdout.into())
}
