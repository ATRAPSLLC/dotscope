#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

//! The `.resources` streams the encoder writes, read by the runtime's own `ResourceManager`
//! (Mono's), which finds each name by a binary search over the hashes.

use std::{fs, path::Path, process::Command, time::Duration};

use dotscope::{
    metadata::resources::DotNetResourceEncoder,
    testkit::tools::{require_tool, run_with_timeout, ToolKind},
};

/// A string as the oracle prints it: backslash, tab and newline escaped.
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
}

#[test]
fn the_runtime_reads_what_the_encoder_writes() {
    if require_tool(ToolKind::MonoCompiler).is_none() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut mcs = Command::new("mcs");
    mcs.current_dir(dir.path())
        .arg("-out:ReadResources.exe")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracle/resources/ReadResources.cs"));
    let built = run_with_timeout(&mut mcs, Duration::from_secs(300)).unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stdout)
    );

    let mut encoder = DotNetResourceEncoder::new();
    let mut expected = Vec::new();
    // Enough names for hashes of both signs
    for index in 0..300 {
        let (name, value) = (format!("Name{index}"), format!("value {index}"));
        encoder.add_string(&name, &value).unwrap();
        expected.push((name, format!("String:{}", escape(&value))));
    }
    // A name past 63 characters and a string past 16 KiB: longer 7-bit lengths
    let (long_name, long_value) = ("N".repeat(100), "x\u{e9}\u{1F600}\t".repeat(5000));
    encoder.add_string(&long_name, &long_value).unwrap();
    expected.push((long_name, format!("String:{}", escape(&long_value))));
    // A name hashed over its UTF-16 surrogates
    encoder.add_int32("Emoji\u{1F600}", 42).unwrap();
    expected.push(("Emoji\u{1F600}".to_string(), "Int32:42".to_string()));
    encoder.add_boolean("Flag", true).unwrap();
    expected.push(("Flag".to_string(), "Boolean:True".to_string()));
    encoder.add_byte_array("Bytes", &[1, 2, 255]).unwrap();
    expected.push(("Bytes".to_string(), "Byte[]:01-02-FF".to_string()));
    encoder.add_double("Ratio", 1.5).unwrap();
    expected.push(("Ratio".to_string(), "Double:1.5".to_string()));
    fs::write(
        dir.path().join("Strings.resources"),
        encoder.encode_dotnet_format().unwrap(),
    )
    .unwrap();

    let mut mono = Command::new("mono");
    mono.current_dir(dir.path())
        .arg("ReadResources.exe")
        .arg(dir.path())
        .arg("Strings")
        .args(expected.iter().map(|(name, _)| name));
    let read = run_with_timeout(&mut mono, Duration::from_secs(300)).unwrap();
    assert!(
        read.status.success(),
        "{}",
        String::from_utf8_lossy(&read.stderr)
    );
    let found: Vec<(String, String)> = String::from_utf8(read.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            let (name, value) = line.split_once('\t').unwrap();
            (name.to_string(), value.to_string())
        })
        .collect();
    assert_eq!(found, expected);
}
