//! Security permission set (`.permissionset`) directive formatting.
//!
//! Emits ILAsm-compatible `.permissionset` directives with the security action
//! and serialized permission data as a `bytearray`.

use std::io::{self, Write};

use crate::{formatting::helpers::write_blob_hex, metadata::security::Security};

/// Write a `.permissionset` directive for a security declaration.
///
/// Emits the security action (e.g., `demand`, `assert`) followed by the
/// serialized permission set as a `bytearray (XX XX ...)`. Permission class
/// names are emitted as comments for readability.
pub(super) fn format_security(
    w: &mut dyn Write,
    security: &Security,
    indent: &str,
) -> io::Result<()> {
    // Permission class comments (before the directive)
    for perm in security.permission_set.permissions() {
        writeln!(w, "{indent}// {}", perm.class_name)?;
    }

    let raw = security.permission_set.raw_data();
    if raw.is_empty() {
        writeln!(w, "{indent}.permissionset {}", security.action)?;
    } else {
        writeln!(w, "{indent}.permissionset {} = (", security.action)?;
        write_blob_hex(w, indent, raw)?;
        writeln!(w, ")")?;
    }
    Ok(())
}
