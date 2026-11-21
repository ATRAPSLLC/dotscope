//! `System.IO.FileStream`, `System.IO.File`, `System.IO.Path`, `System.IO.FileInfo`,
//! and `System.IO.StreamReader` method hooks for .NET emulation.
//!
//! This module provides hook implementations for file I/O operations backed by
//! the emulator's [`VirtualFs`]. When obfuscated code opens files (e.g., reading
//! the assembly's own PE for anti-tamper checks), these hooks serve data from the
//! virtual filesystem instead of the real filesystem.
//!
//! # Emulated .NET Methods
//!
//! ## FileStream Constructors
//!
//! | Method | Description | Implementation |
//! |--------|-------------|----------------|
//! | `FileStream..ctor(String, FileMode)` | Open file | VirtualFs lookup → Stream |
//! | `FileStream..ctor(String, FileMode, FileAccess)` | Open file | VirtualFs lookup → Stream |
//! | `FileStream..ctor(String, FileMode, FileAccess, FileShare)` | Open file | VirtualFs lookup → Stream |
//!
//! ## File Static Methods
//!
//! | Method | Description | Implementation |
//! |--------|-------------|----------------|
//! | `File.Exists(String)` | Check file exists | VirtualFs check, default true |
//! | `File.ReadAllBytes(String)` | Read entire file | VirtualFs lookup → byte[] |
//! | `File.ReadAllText(String)` | Read file as text | VirtualFs lookup → UTF-8 string |
//! | `File.OpenRead(String)` | Open for reading | VirtualFs lookup → Stream |
//! | `File.Open(String, ...)` | Open file | VirtualFs lookup → Stream |
//! | `File.Create(String)` | Create file | Allocate empty Stream |
//! | `File.WriteAllBytes(String, Byte[])` | Write file | No-op |
//! | `File.WriteAllText(String, String)` | Write text | No-op |
//! | `File.Copy(String, String, ...)` | Copy file | No-op |
//! | `File.Delete(String)` | Delete file | No-op |
//!
//! ## Path Static Methods
//!
//! | Method | Description | Implementation |
//! |--------|-------------|----------------|
//! | `Path.GetDirectoryName(String)` | Get directory | String manipulation |
//! | `Path.Combine(...)` | Join paths | String manipulation |
//! | `Path.GetFileName(String)` | Get filename | String manipulation |
//! | `Path.GetFileNameWithoutExtension(String)` | Filename sans ext | String manipulation |
//! | `Path.GetExtension(String)` | Get extension | String manipulation |
//! | `Path.GetFullPath(String)` | Full path | Returns input as-is |
//! | `Path.GetTempPath()` | Temp directory | Config-based |
//! | `Path.HasExtension(String)` | Check extension | String manipulation |
//! | `Path.ChangeExtension(String, String)` | Replace extension | String manipulation |
//! | `Path.GetPathRoot(String)` | Get root | String manipulation |
//! | `Path.IsPathRooted(String)` | Check if rooted | String manipulation |
//!
//! ## FileInfo Methods
//!
//! | Method | Description | Implementation |
//! |--------|-------------|----------------|
//! | `FileInfo..ctor(String)` | Create FileInfo | Store path in synthetic field |
//! | `FileInfo.get_Exists` | Check existence | VirtualFs check |
//! | `FileInfo.get_Length` | Get file size | VirtualFs lookup → data length |
//! | `FileInfo.get_FullName` | Get full path | Return stored path |
//! | `FileInfo.get_Name` | Get filename | Extract from path |
//! | `FileInfo.get_Extension` | Get extension | Extract from path |
//! | `FileInfo.get_DirectoryName` | Get directory | Extract from path |
//! | `FileInfo.OpenRead()` | Open for reading | VirtualFs → Stream |
//!
//! ## StreamReader Methods
//!
//! | Method | Description | Implementation |
//! |--------|-------------|----------------|
//! | `StreamReader..ctor(Stream)` | Wrap stream | Store ref in synthetic field |
//! | `StreamReader..ctor(String)` | Open file | VirtualFs → Stream → store |
//! | `StreamReader.ReadToEnd()` | Read all text | Remaining bytes → UTF-8 |
//! | `StreamReader.ReadLine()` | Read one line | Read until newline |
//! | `StreamReader.Read()` | Read char | Single char as i32 |
//! | `StreamReader.Peek()` | Peek char | Peek without advancing |
//! | `StreamReader.get_EndOfStream` | Check EOF | Position >= length |
//! | `StreamReader.Close/Dispose` | Cleanup | No-op |
//!
//! [`VirtualFs`]: crate::emulation::filesystem::VirtualFs

use log::debug;

use crate::{
    emulation::{
        runtime::{
            bcl::crypto::transform_stream_data,
            hook::{Hook, HookContext, HookManager, PreHookResult},
        },
        thread::EmulationThread,
        tokens::io_fields,
        EmValue, HeapRef,
    },
    Result,
};

/// Registers all `System.IO.FileStream`, `System.IO.File`, `System.IO.Path`,
/// `System.IO.FileInfo`, and `System.IO.StreamReader` hooks.
pub fn register(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("System.IO.FileStream..ctor")
            .match_name("System.IO", "FileStream", ".ctor")
            .pre(filestream_ctor_pre),
    )?;
    manager.register(
        Hook::new("System.IO.File.Exists")
            .match_name("System.IO", "File", "Exists")
            .pre(file_exists_pre),
    )?;
    manager.register(
        Hook::new("System.IO.File.ReadAllBytes")
            .match_name("System.IO", "File", "ReadAllBytes")
            .pre(file_read_all_bytes_pre),
    )?;
    manager.register(
        Hook::new("System.IO.File.ReadAllText")
            .match_name("System.IO", "File", "ReadAllText")
            .pre(file_read_all_text_pre),
    )?;
    manager.register(
        Hook::new("System.IO.File.OpenRead")
            .match_name("System.IO", "File", "OpenRead")
            .pre(file_open_read_pre),
    )?;
    manager.register(
        Hook::new("System.IO.File.Open")
            .match_name("System.IO", "File", "Open")
            .pre(file_open_pre),
    )?;
    manager.register(
        Hook::new("System.IO.File.Create")
            .match_name("System.IO", "File", "Create")
            .pre(file_create_pre),
    )?;
    manager.register(
        Hook::new("System.IO.File.WriteAllBytes")
            .match_name("System.IO", "File", "WriteAllBytes")
            .pre(file_noop_pre),
    )?;
    manager.register(
        Hook::new("System.IO.File.WriteAllText")
            .match_name("System.IO", "File", "WriteAllText")
            .pre(file_noop_pre),
    )?;
    manager.register(
        Hook::new("System.IO.File.Copy")
            .match_name("System.IO", "File", "Copy")
            .pre(file_noop_pre),
    )?;
    manager.register(
        Hook::new("System.IO.File.Delete")
            .match_name("System.IO", "File", "Delete")
            .pre(file_noop_pre),
    )?;
    manager.register(
        Hook::new("System.IO.Path.GetDirectoryName")
            .match_name("System.IO", "Path", "GetDirectoryName")
            .pre(path_get_directory_name_pre),
    )?;
    manager.register(
        Hook::new("System.IO.Path.Combine")
            .match_name("System.IO", "Path", "Combine")
            .pre(path_combine_pre),
    )?;
    manager.register(
        Hook::new("System.IO.Path.GetFileName")
            .match_name("System.IO", "Path", "GetFileName")
            .pre(path_get_file_name_pre),
    )?;
    manager.register(
        Hook::new("System.IO.Path.GetFileNameWithoutExtension")
            .match_name("System.IO", "Path", "GetFileNameWithoutExtension")
            .pre(path_get_file_name_without_extension_pre),
    )?;
    manager.register(
        Hook::new("System.IO.Path.GetExtension")
            .match_name("System.IO", "Path", "GetExtension")
            .pre(path_get_extension_pre),
    )?;
    manager.register(
        Hook::new("System.IO.Path.GetFullPath")
            .match_name("System.IO", "Path", "GetFullPath")
            .pre(path_get_full_path_pre),
    )?;
    manager.register(
        Hook::new("System.IO.Path.GetTempPath")
            .match_name("System.IO", "Path", "GetTempPath")
            .pre(path_get_temp_path_pre),
    )?;
    manager.register(
        Hook::new("System.IO.Path.HasExtension")
            .match_name("System.IO", "Path", "HasExtension")
            .pre(path_has_extension_pre),
    )?;
    manager.register(
        Hook::new("System.IO.Path.ChangeExtension")
            .match_name("System.IO", "Path", "ChangeExtension")
            .pre(path_change_extension_pre),
    )?;
    manager.register(
        Hook::new("System.IO.Path.GetPathRoot")
            .match_name("System.IO", "Path", "GetPathRoot")
            .pre(path_get_path_root_pre),
    )?;
    manager.register(
        Hook::new("System.IO.Path.IsPathRooted")
            .match_name("System.IO", "Path", "IsPathRooted")
            .pre(path_is_path_rooted_pre),
    )?;
    manager.register(
        Hook::new("System.IO.FileInfo..ctor")
            .match_name("System.IO", "FileInfo", ".ctor")
            .pre(fileinfo_ctor_pre),
    )?;
    manager.register(
        Hook::new("System.IO.FileInfo.get_Exists")
            .match_name("System.IO", "FileInfo", "get_Exists")
            .pre(fileinfo_get_exists_pre),
    )?;
    manager.register(
        Hook::new("System.IO.FileInfo.get_Length")
            .match_name("System.IO", "FileInfo", "get_Length")
            .pre(fileinfo_get_length_pre),
    )?;
    manager.register(
        Hook::new("System.IO.FileInfo.get_FullName")
            .match_name("System.IO", "FileInfo", "get_FullName")
            .pre(fileinfo_get_fullname_pre),
    )?;
    manager.register(
        Hook::new("System.IO.FileInfo.get_Name")
            .match_name("System.IO", "FileInfo", "get_Name")
            .pre(fileinfo_get_name_pre),
    )?;
    manager.register(
        Hook::new("System.IO.FileInfo.get_Extension")
            .match_name("System.IO", "FileInfo", "get_Extension")
            .pre(fileinfo_get_extension_pre),
    )?;
    manager.register(
        Hook::new("System.IO.FileInfo.get_DirectoryName")
            .match_name("System.IO", "FileInfo", "get_DirectoryName")
            .pre(fileinfo_get_directory_name_pre),
    )?;
    manager.register(
        Hook::new("System.IO.FileInfo.OpenRead")
            .match_name("System.IO", "FileInfo", "OpenRead")
            .pre(fileinfo_open_read_pre),
    )?;
    manager.register(
        Hook::new("System.IO.StreamReader..ctor")
            .match_name("System.IO", "StreamReader", ".ctor")
            .pre(streamreader_ctor_pre),
    )?;
    manager.register(
        Hook::new("System.IO.StreamReader.ReadToEnd")
            .match_name("System.IO", "StreamReader", "ReadToEnd")
            .pre(streamreader_read_to_end_pre),
    )?;
    manager.register(
        Hook::new("System.IO.StreamReader.ReadLine")
            .match_name("System.IO", "StreamReader", "ReadLine")
            .pre(streamreader_read_line_pre),
    )?;
    manager.register(
        Hook::new("System.IO.StreamReader.Read")
            .match_name("System.IO", "StreamReader", "Read")
            .pre(streamreader_read_pre),
    )?;
    manager.register(
        Hook::new("System.IO.StreamReader.Peek")
            .match_name("System.IO", "StreamReader", "Peek")
            .pre(streamreader_peek_pre),
    )?;
    manager.register(
        Hook::new("System.IO.StreamReader.get_EndOfStream")
            .match_name("System.IO", "StreamReader", "get_EndOfStream")
            .pre(streamreader_get_end_of_stream_pre),
    )?;
    manager.register(
        Hook::new("System.IO.StreamReader.Close")
            .match_name("System.IO", "StreamReader", "Close")
            .pre(streamreader_noop_pre),
    )?;
    manager.register(
        Hook::new("System.IO.StreamReader.Dispose")
            .match_name("System.IO", "StreamReader", "Dispose")
            .pre(streamreader_noop_pre),
    )?;

    Ok(())
}

/// Extracts a string path from the first argument of a hook context.
fn extract_path_arg(ctx: &HookContext<'_>, thread: &EmulationThread) -> Option<String> {
    match ctx.args.first() {
        Some(EmValue::ObjectRef(r)) => thread.heap().get_string(*r).ok().map(|s| s.to_string()),
        _ => None,
    }
}

/// Extracts a string from the Nth argument (0-indexed).
fn extract_nth_string_arg(
    ctx: &HookContext<'_>,
    thread: &EmulationThread,
    n: usize,
) -> Option<String> {
    match ctx.args.get(n) {
        Some(EmValue::ObjectRef(r)) => thread.heap().get_string(*r).ok().map(|s| s.to_string()),
        _ => None,
    }
}

/// Extracts the filename portion from a path (after last `\` or `/`).
fn path_filename(path: &str) -> &str {
    match path.rfind(['\\', '/']) {
        Some(pos) => path.get(pos.saturating_add(1)..).unwrap_or(path),
        None => path,
    }
}

/// Returns true if a path is rooted (starts with drive letter like `C:` or `\` or `/`).
fn is_rooted(path: &str) -> bool {
    let bytes = path.as_bytes();
    let Some(&first) = bytes.first() else {
        return false;
    };
    first == b'\\' || first == b'/' || bytes.get(1).is_some_and(|&b| b == b':')
}

/// Allocates a string on the heap and returns a bypass result, or Null on error.
fn alloc_string_result(thread: &mut EmulationThread, s: &str) -> PreHookResult {
    match thread.heap_mut().alloc_string(s) {
        Ok(r) => PreHookResult::Bypass(Some(EmValue::ObjectRef(r))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Retrieves the stored path string from a FileInfo's synthetic field.
fn get_fileinfo_path(this: Option<&EmValue>, thread: &EmulationThread) -> Option<String> {
    let this_ref = match this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return None,
    };
    let field_value = thread
        .heap()
        .get_field(this_ref, io_fields::FILEINFO_PATH)
        .ok()?;
    match field_value {
        EmValue::ObjectRef(str_ref) => thread
            .heap()
            .get_string(str_ref)
            .ok()
            .map(|s| s.to_string()),
        _ => None,
    }
}

/// Retrieves the stream HeapRef stored in a StreamReader's synthetic field.
fn get_streamreader_stream(this: Option<&EmValue>, thread: &EmulationThread) -> Option<HeapRef> {
    let this_ref = match this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return None,
    };
    let field_value = thread
        .heap()
        .get_field(this_ref, io_fields::STREAMREADER_STREAM)
        .ok()?;
    match field_value {
        EmValue::ObjectRef(stream_ref) => Some(stream_ref),
        _ => None,
    }
}

/// Hook for `System.IO.FileStream..ctor` constructors.
///
/// Looks up the path in the [`VirtualFs`]. If found, replaces the `this`
/// object with a [`HeapObject::Stream`] containing the file data. If not
/// found, throws `FileNotFoundException`.
///
/// [`VirtualFs`]: crate::emulation::filesystem::VirtualFs
/// [`HeapObject::Stream`]: crate::emulation::memory::HeapObject::Stream
fn filestream_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let path = match extract_path_arg(ctx, thread) {
        Some(p) => p,
        None => return PreHookResult::throw_file_not_found("<null>"),
    };

    let data = match thread.virtual_fs().get(&path) {
        Some(cow) => cow.data().to_vec(),
        None => {
            debug!("FileStream: file not found in VirtualFs: {}", path);
            return PreHookResult::throw_file_not_found(&path);
        }
    };

    debug!(
        "FileStream: opened {} from VirtualFs ({} bytes)",
        path,
        data.len()
    );

    match ctx.this {
        Some(EmValue::ObjectRef(stream_ref)) => {
            try_hook!(thread.heap_mut().replace_with_stream(*stream_ref, data));
            PreHookResult::Bypass(None)
        }
        _ => {
            let type_token = thread.resolve_type_token("System.IO", "FileStream");
            match thread.heap_mut().alloc_stream(data, type_token) {
                Ok(stream_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(stream_ref))),
                Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
}

/// Hook for `System.IO.File.Exists(String) -> Boolean`.
///
/// Checks VirtualFs; defaults to true for compatibility with anti-tamper checks.
fn file_exists_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(r)) = ctx.args.first() {
        if let Ok(path) = thread.heap().get_string(*r) {
            if thread.virtual_fs().exists(&path) {
                return PreHookResult::Bypass(Some(EmValue::I32(1)));
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(1)))
}

/// Hook for `System.IO.File.ReadAllBytes(String) -> Byte[]`.
fn file_read_all_bytes_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let path = match extract_path_arg(ctx, thread) {
        Some(p) => p,
        None => return PreHookResult::throw_file_not_found("<null>"),
    };

    let data = match thread.virtual_fs().get(&path) {
        Some(cow) => cow.data().to_vec(),
        None => {
            debug!("File.ReadAllBytes: file not found in VirtualFs: {}", path);
            return PreHookResult::throw_file_not_found(&path);
        }
    };

    debug!(
        "File.ReadAllBytes: read {} from VirtualFs ({} bytes)",
        path,
        data.len()
    );

    match thread.heap_mut().alloc_byte_array(&data) {
        Ok(array_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.IO.File.ReadAllText(String, [Encoding]) -> String`.
///
/// Reads file from VirtualFs and decodes as UTF-8. Encoding argument is ignored.
fn file_read_all_text_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let path = match extract_path_arg(ctx, thread) {
        Some(p) => p,
        None => return PreHookResult::throw_file_not_found("<null>"),
    };

    let data = match thread.virtual_fs().get(&path) {
        Some(cow) => cow.data().to_vec(),
        None => {
            debug!("File.ReadAllText: file not found in VirtualFs: {}", path);
            return PreHookResult::throw_file_not_found(&path);
        }
    };

    debug!(
        "File.ReadAllText: read {} from VirtualFs ({} bytes)",
        path,
        data.len()
    );

    let text = String::from_utf8_lossy(&data);
    alloc_string_result(thread, &text)
}

/// Hook for `System.IO.File.OpenRead(String) -> FileStream`.
fn file_open_read_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let path = match extract_path_arg(ctx, thread) {
        Some(p) => p,
        None => return PreHookResult::throw_file_not_found("<null>"),
    };

    let data = match thread.virtual_fs().get(&path) {
        Some(cow) => cow.data().to_vec(),
        None => {
            debug!("File.OpenRead: file not found in VirtualFs: {}", path);
            return PreHookResult::throw_file_not_found(&path);
        }
    };

    debug!(
        "File.OpenRead: opened {} from VirtualFs ({} bytes)",
        path,
        data.len()
    );

    let type_token = thread.resolve_type_token("System.IO", "FileStream");
    match thread.heap_mut().alloc_stream(data, type_token) {
        Ok(stream_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(stream_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.IO.File.Open(String, FileMode, ...) -> FileStream`.
///
/// Same behavior as OpenRead — VirtualFs lookup, ignore mode/access args.
fn file_open_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    file_open_read_pre(ctx, thread)
}

/// Hook for `System.IO.File.Create(String) -> FileStream`.
///
/// Creates an empty stream (emulator doesn't persist writes).
fn file_create_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let type_token = thread.resolve_type_token("System.IO", "FileStream");
    match thread.heap_mut().alloc_stream(Vec::new(), type_token) {
        Ok(stream_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(stream_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// No-op hook for write/copy/delete operations that don't produce meaningful output.
fn file_noop_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.Path.GetDirectoryName(String) -> String`.
fn path_get_directory_name_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let path = match extract_path_arg(ctx, thread) {
        Some(p) => p,
        None => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    let dir = path
        .rsplit_once(['\\', '/'])
        .map_or("", |(parent, _)| parent);

    alloc_string_result(thread, dir)
}

/// Hook for `System.IO.Path.Combine(String, String, ...) -> String`.
///
/// Joins path arguments with `\`. If any argument is rooted, it resets the
/// accumulated path (matching .NET behavior).
fn path_combine_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let mut parts = Vec::new();
    for arg in ctx.args.iter() {
        if let EmValue::ObjectRef(r) = arg {
            if let Ok(s) = thread.heap().get_string(*r) {
                parts.push(s.to_string());
            }
        }
    }

    let result = parts.iter().fold(String::new(), |acc, part| {
        if is_rooted(part) || acc.is_empty() {
            part.clone()
        } else if acc.ends_with('\\') || acc.ends_with('/') {
            format!("{acc}{part}")
        } else {
            format!("{acc}\\{part}")
        }
    });

    alloc_string_result(thread, &result)
}

/// Hook for `System.IO.Path.GetFileName(String) -> String`.
fn path_get_file_name_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let path = match extract_path_arg(ctx, thread) {
        Some(p) => p,
        None => return PreHookResult::Bypass(Some(EmValue::Null)),
    };
    alloc_string_result(thread, path_filename(&path))
}

/// Hook for `System.IO.Path.GetFileNameWithoutExtension(String) -> String`.
fn path_get_file_name_without_extension_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let path = match extract_path_arg(ctx, thread) {
        Some(p) => p,
        None => return PreHookResult::Bypass(Some(EmValue::Null)),
    };
    let filename = path_filename(&path);
    let without_ext = filename.rsplit_once('.').map_or(filename, |(stem, _)| stem);
    alloc_string_result(thread, without_ext)
}

/// Hook for `System.IO.Path.GetExtension(String) -> String`.
fn path_get_extension_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let path = match extract_path_arg(ctx, thread) {
        Some(p) => p,
        None => return PreHookResult::Bypass(Some(EmValue::Null)),
    };
    let filename = path_filename(&path);
    // `split_at` rather than `&filename[pos..]`: `rfind` always returns a character boundary, so
    // both are sound, but this keeps the crate free of `str` range indexing (`clippy::string_slice`).
    // The extension keeps its leading dot, which `rsplit_once` would consume.
    let ext = filename
        .rfind('.')
        .map_or("", |pos| filename.split_at(pos).1);
    alloc_string_result(thread, ext)
}

/// Hook for `System.IO.Path.GetFullPath(String) -> String`.
///
/// In emulation, paths are already "full" so we return the input unchanged.
fn path_get_full_path_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let path = match extract_path_arg(ctx, thread) {
        Some(p) => p,
        None => return PreHookResult::Bypass(Some(EmValue::Null)),
    };
    alloc_string_result(thread, &path)
}

/// Hook for `System.IO.Path.GetTempPath() -> String`.
///
/// Returns `assembly_location_base` + `\` from config.
fn path_get_temp_path_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let base = &thread.config().environment.assembly_location_base;
    let temp = format!("{base}\\");
    alloc_string_result(thread, &temp)
}

/// Hook for `System.IO.Path.HasExtension(String) -> Boolean`.
fn path_has_extension_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let path = match extract_path_arg(ctx, thread) {
        Some(p) => p,
        None => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };
    let filename = path_filename(&path);
    let has = filename.contains('.');
    PreHookResult::Bypass(Some(EmValue::I32(has as i32)))
}

/// Hook for `System.IO.Path.ChangeExtension(String, String) -> String`.
fn path_change_extension_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let path = match extract_path_arg(ctx, thread) {
        Some(p) => p,
        None => return PreHookResult::Bypass(Some(EmValue::Null)),
    };
    let new_ext = extract_nth_string_arg(ctx, thread, 1).unwrap_or_default();

    // Strip existing extension
    let base = match path.rfind('.') {
        // Only strip if the dot is in the filename portion, not in a parent directory name.
        Some(pos) if pos > path.rfind(['\\', '/']).unwrap_or(0) => path.split_at(pos).0,
        _ => &path,
    };

    // Append new extension (ensure it starts with '.')
    let result = if new_ext.is_empty() {
        base.to_string()
    } else if new_ext.starts_with('.') {
        format!("{base}{new_ext}")
    } else {
        format!("{base}.{new_ext}")
    };

    alloc_string_result(thread, &result)
}

/// Hook for `System.IO.Path.GetPathRoot(String) -> String`.
fn path_get_path_root_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let path = match extract_path_arg(ctx, thread) {
        Some(p) => p,
        None => return PreHookResult::Bypass(Some(EmValue::Null)),
    };
    let bytes = path.as_bytes();
    let root = if bytes.get(1) == Some(&b':') && matches!(bytes.get(2), Some(&b'\\') | Some(&b'/'))
    {
        // Drive letter root: "C:\"
        path.get(..3).unwrap_or("")
    } else if bytes.get(1) == Some(&b':') {
        // Drive letter without trailing sep: "C:"
        path.get(..2).unwrap_or("")
    } else if matches!(bytes.first(), Some(&b'\\') | Some(&b'/')) {
        path.get(..1).unwrap_or("")
    } else {
        ""
    };
    alloc_string_result(thread, root)
}

/// Hook for `System.IO.Path.IsPathRooted(String) -> Boolean`.
fn path_is_path_rooted_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let path = match extract_path_arg(ctx, thread) {
        Some(p) => p,
        None => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };
    PreHookResult::Bypass(Some(EmValue::I32(is_rooted(&path) as i32)))
}

/// Hook for `System.IO.FileInfo..ctor(String)`.
///
/// Stores the path string ref in a synthetic field on `this`.
fn fileinfo_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let path_ref = match ctx.args.first() {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    if let Some(EmValue::ObjectRef(this_ref)) = ctx.this {
        try_hook!(thread.heap_mut().set_field(
            *this_ref,
            io_fields::FILEINFO_PATH,
            EmValue::ObjectRef(path_ref),
        ));
    }

    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.FileInfo.get_Exists -> Boolean`.
fn fileinfo_get_exists_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let path = match get_fileinfo_path(ctx.this, thread) {
        Some(p) => p,
        None => return PreHookResult::Bypass(Some(EmValue::I32(1))),
    };
    let _exists = thread.virtual_fs().exists(&path);
    // Default to true for compatibility — virtual FS always reports existence
    PreHookResult::Bypass(Some(EmValue::I32(1)))
}

/// Hook for `System.IO.FileInfo.get_Length -> Int64`.
fn fileinfo_get_length_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let path = match get_fileinfo_path(ctx.this, thread) {
        Some(p) => p,
        None => return PreHookResult::Bypass(Some(EmValue::I64(0))),
    };
    let len = thread
        .virtual_fs()
        .get(&path)
        .map_or(0i64, |cow| cow.data().len() as i64);
    PreHookResult::Bypass(Some(EmValue::I64(len)))
}

/// Hook for `System.IO.FileInfo.get_FullName -> String`.
fn fileinfo_get_fullname_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Return the stored path ObjectRef directly from the synthetic field
    if let Some(EmValue::ObjectRef(this_ref)) = ctx.this {
        if let Ok(field) = thread.heap().get_field(*this_ref, io_fields::FILEINFO_PATH) {
            return PreHookResult::Bypass(Some(field));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.IO.FileInfo.get_Name -> String`.
fn fileinfo_get_name_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let path = match get_fileinfo_path(ctx.this, thread) {
        Some(p) => p,
        None => return PreHookResult::Bypass(Some(EmValue::Null)),
    };
    alloc_string_result(thread, path_filename(&path))
}

/// Hook for `System.IO.FileInfo.get_Extension -> String`.
fn fileinfo_get_extension_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let path = match get_fileinfo_path(ctx.this, thread) {
        Some(p) => p,
        None => return PreHookResult::Bypass(Some(EmValue::Null)),
    };
    let filename = path_filename(&path);
    // Extension keeps its leading dot; see the note in `path_get_extension_pre`.
    let ext = filename
        .rfind('.')
        .map_or("", |pos| filename.split_at(pos).1);
    alloc_string_result(thread, ext)
}

/// Hook for `System.IO.FileInfo.get_DirectoryName -> String`.
fn fileinfo_get_directory_name_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let path = match get_fileinfo_path(ctx.this, thread) {
        Some(p) => p,
        None => return PreHookResult::Bypass(Some(EmValue::Null)),
    };
    let dir = path
        .rsplit_once(['\\', '/'])
        .map_or("", |(parent, _)| parent);
    alloc_string_result(thread, dir)
}

/// Hook for `System.IO.FileInfo.OpenRead() -> FileStream`.
fn fileinfo_open_read_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let path = match get_fileinfo_path(ctx.this, thread) {
        Some(p) => p,
        None => return PreHookResult::throw_file_not_found("<FileInfo>"),
    };

    let data = match thread.virtual_fs().get(&path) {
        Some(cow) => cow.data().to_vec(),
        None => {
            debug!("FileInfo.OpenRead: file not found in VirtualFs: {}", path);
            return PreHookResult::throw_file_not_found(&path);
        }
    };

    let type_token = thread.resolve_type_token("System.IO", "FileStream");
    match thread.heap_mut().alloc_stream(data, type_token) {
        Ok(stream_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(stream_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.IO.StreamReader..ctor(Stream)` and `..ctor(String, [Encoding])`.
///
/// If the first argument is a string (ObjectRef that resolves as string), opens
/// the file from VirtualFs. Otherwise treats the argument as a Stream reference.
fn streamreader_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let this_ref = match ctx.this {
        Some(EmValue::ObjectRef(r)) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let stream_ref = match ctx.args.first() {
        Some(EmValue::ObjectRef(r)) => {
            // Try to interpret as a string path first (StreamReader..ctor(String))
            if let Ok(path) = thread.heap().get_string(*r) {
                let path = path.to_string();
                let data = match thread.virtual_fs().get(&path) {
                    Some(cow) => cow.data().to_vec(),
                    None => {
                        debug!("StreamReader: file not found in VirtualFs: {}", path);
                        return PreHookResult::throw_file_not_found(&path);
                    }
                };
                // Allocate a new stream from the file data
                let type_token = thread.resolve_type_token("System.IO", "FileStream");
                match thread.heap_mut().alloc_stream(data, type_token) {
                    Ok(sr) => sr,
                    Err(_) => return PreHookResult::Bypass(None),
                }
            } else {
                // Not a string — treat as Stream reference
                *r
            }
        }
        _ => return PreHookResult::Bypass(None),
    };

    try_hook!(thread.heap_mut().set_field(
        this_ref,
        io_fields::STREAMREADER_STREAM,
        EmValue::ObjectRef(stream_ref),
    ));

    PreHookResult::Bypass(None)
}

/// Hook for `System.IO.StreamReader.ReadToEnd() -> String`.
///
/// Reads remaining bytes from the underlying stream and decodes as UTF-8.
fn streamreader_read_to_end_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let stream_ref = match get_streamreader_stream(ctx.this, thread) {
        Some(r) => r,
        None => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    // Try plain Stream first (most common path)
    if let Some(text) = try_hook!(thread.heap().with_stream(stream_ref, |data, position| {
        let remaining: &[u8] = data.get(*position..).unwrap_or(&[]);
        let text = String::from_utf8_lossy(remaining).into_owned();
        *position = data.len(); // Advance to end
        text
    })) {
        return alloc_string_result(thread, &text);
    }

    // Handle CryptoStream: the StreamReader wraps a CryptoStream which needs
    // decryption/encryption before reading. Perform the full transform inline.
    if let Some((underlying_stream, transform_ref, mode)) =
        try_hook!(thread.heap().get_crypto_stream_info(stream_ref))
    {
        // Only handle Read mode (0)
        if mode != 0 {
            return PreHookResult::Bypass(Some(EmValue::Null));
        }

        // Check if we already have cached transformed data
        let decrypted = if let Some((data, pos)) =
            try_hook!(thread.heap().get_crypto_stream_transformed(stream_ref))
        {
            data.get(pos..).map(<[u8]>::to_vec).unwrap_or_default()
        } else {
            // No cached data — perform the crypto transform now
            let Some((stream_data, underlying_pos)) =
                try_hook!(thread.heap().get_stream_data(underlying_stream))
            else {
                return PreHookResult::Bypass(Some(EmValue::Null));
            };

            let effective_data: &[u8] = stream_data.get(underlying_pos..).unwrap_or(&[]);

            let effective_data = effective_data.to_vec();
            let transformed = match transform_stream_data(thread, transform_ref, &effective_data) {
                Ok(transformed) => transformed,
                Err(result) => return result,
            };

            // Cache the transformed data for potential future reads
            let _ = thread
                .heap()
                .set_crypto_stream_transformed(stream_ref, transformed.clone());

            transformed
        };

        let text = String::from_utf8_lossy(&decrypted).into_owned();
        return alloc_string_result(thread, &text);
    }

    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `System.IO.StreamReader.ReadLine() -> String`.
///
/// Reads bytes until `\n` (handling `\r\n`), decodes as UTF-8.
/// Returns null at end of stream.
fn streamreader_read_line_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let stream_ref = match get_streamreader_stream(ctx.this, thread) {
        Some(r) => r,
        None => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    // Zero-copy: scan for newline in-place and advance position
    let line_text = match try_hook!(thread.heap().with_stream(stream_ref, |data, position| {
        if *position >= data.len() {
            return None; // EOF
        }

        let remaining: &[u8] = data.get(*position..)?;
        let (line_bytes, advance) = if let Some(nl_pos) = remaining.iter().position(|&b| b == b'\n')
        {
            let line_end =
                if nl_pos > 0 && remaining.get(nl_pos.saturating_sub(1)).copied() == Some(b'\r') {
                    nl_pos.saturating_sub(1) // Strip \r from \r\n
                } else {
                    nl_pos
                };
            (
                remaining.get(..line_end).unwrap_or(&[]),
                nl_pos.saturating_add(1),
            ) // Skip past the \n
        } else {
            // No newline found — return rest of stream
            (remaining, remaining.len())
        };

        *position = position.saturating_add(advance);
        Some(String::from_utf8_lossy(line_bytes).into_owned())
    })) {
        Some(opt) => opt,
        None => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    match line_text {
        Some(text) => alloc_string_result(thread, &text),
        None => PreHookResult::Bypass(Some(EmValue::Null)), // EOF
    }
}

/// Hook for `System.IO.StreamReader.Read() -> Int32`.
///
/// Reads a single character. Returns -1 at EOF.
fn streamreader_read_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let stream_ref = match get_streamreader_stream(ctx.this, thread) {
        Some(r) => r,
        None => return PreHookResult::Bypass(Some(EmValue::I32(-1))),
    };

    // Zero-copy single-byte read — advances position internally
    match try_hook!(thread.heap().stream_read_byte(stream_ref)) {
        Some(byte) => PreHookResult::Bypass(Some(EmValue::I32(byte as i32))),
        None => PreHookResult::Bypass(Some(EmValue::I32(-1))),
    }
}

/// Hook for `System.IO.StreamReader.Peek() -> Int32`.
///
/// Returns the next character without advancing. Returns -1 at EOF.
fn streamreader_peek_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let stream_ref = match get_streamreader_stream(ctx.this, thread) {
        Some(r) => r,
        None => return PreHookResult::Bypass(Some(EmValue::I32(-1))),
    };

    // Zero-copy peek — read byte at current position without advancing
    let value = try_hook!(thread.heap().with_stream(stream_ref, |data, position| {
        data.get(*position).map_or(-1, |&b| b as i32)
    }));

    PreHookResult::Bypass(Some(EmValue::I32(value.unwrap_or(-1))))
}

/// Hook for `System.IO.StreamReader.get_EndOfStream -> Boolean`.
fn streamreader_get_end_of_stream_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let stream_ref = match get_streamreader_stream(ctx.this, thread) {
        Some(r) => r,
        None => return PreHookResult::Bypass(Some(EmValue::I32(1))),
    };

    // Zero-copy length/position check — no buffer clone needed
    let len = match try_hook!(thread.heap().stream_len(stream_ref)) {
        Some(l) => l,
        None => return PreHookResult::Bypass(Some(EmValue::I32(1))),
    };
    let pos = match try_hook!(thread.heap().stream_position(stream_ref)) {
        Some(p) => p,
        None => return PreHookResult::Bypass(Some(EmValue::I32(1))),
    };

    PreHookResult::Bypass(Some(EmValue::I32((pos >= len) as i32)))
}

/// No-op hook for StreamReader.Close/Dispose.
fn streamreader_noop_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use super::*;
    use crate::{
        emulation::{
            filesystem::VirtualFs,
            runtime::{
                hook::{HookContext, HookManager, PreHookResult},
                RuntimeState,
            },
            AddressSpace, CaptureContext, EmValue, EmulationThread, SharedFakeObjects,
            ThreadContext, ThreadId,
        },
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::{create_test_thread, emulation_config},
    };

    /// Creates a test thread with a virtual filesystem containing "test.exe".
    fn create_thread_with_vfs() -> EmulationThread {
        let mut vfs = VirtualFs::new();
        vfs.map_data("test.exe", vec![0x4D, 0x5A, 0x90, 0x00]);

        let address_space = Arc::new(AddressSpace::new());
        let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
        let ctx = Arc::new(ThreadContext::new(
            address_space,
            Arc::new(RwLock::new(RuntimeState::new())),
            Arc::new(CaptureContext::new()),
            Arc::new(emulation_config()),
            None,
            fake_objects,
            Arc::new(vfs),
        ));
        EmulationThread::new(ThreadId::MAIN, ctx)
    }

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        register(&manager).unwrap();
        // 1 FileStream + 10 File + 11 Path + 8 FileInfo + 8 StreamReader = 38
        assert_eq!(manager.len(), 38);
    }

    #[test]
    fn test_filestream_ctor_found() {
        let mut thread = create_thread_with_vfs();
        let path_ref = thread.heap_mut().alloc_string("test.exe").unwrap();
        let this_ref = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();

        let args = [EmValue::ObjectRef(path_ref), EmValue::I32(3)]; // FileMode.Open = 3
        let this = EmValue::ObjectRef(this_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "FileStream",
            ".ctor",
            PointerSize::Bit64,
        )
        .with_args(&args)
        .with_this(Some(&this));

        let result = filestream_ctor_pre(&ctx, &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));

        // Verify the object was replaced with a stream containing the VFS data
        let (data, _pos) = thread.heap().get_stream_data(this_ref).unwrap().unwrap();
        assert_eq!(data, vec![0x4D, 0x5A, 0x90, 0x00]);
    }

    #[test]
    fn test_filestream_ctor_not_found() {
        let mut thread = create_thread_with_vfs();
        let path_ref = thread.heap_mut().alloc_string("nonexistent.dll").unwrap();

        let args = [EmValue::ObjectRef(path_ref), EmValue::I32(3)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "FileStream",
            ".ctor",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = filestream_ctor_pre(&ctx, &mut thread);
        assert!(matches!(result, PreHookResult::Throw { .. }));
    }

    #[test]
    fn test_file_read_all_bytes() {
        let mut thread = create_thread_with_vfs();
        let path_ref = thread.heap_mut().alloc_string("test.exe").unwrap();

        let args = [EmValue::ObjectRef(path_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "File",
            "ReadAllBytes",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = file_read_all_bytes_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref))) = result {
            let bytes = thread.heap().get_byte_array(array_ref).unwrap().unwrap();
            assert_eq!(bytes, vec![0x4D, 0x5A, 0x90, 0x00]);
        } else {
            panic!("Expected byte array result");
        }
    }

    #[test]
    fn test_file_read_all_text() {
        let mut vfs = VirtualFs::new();
        vfs.map_data("hello.txt", b"Hello, World!".to_vec());

        let address_space = Arc::new(AddressSpace::new());
        let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
        let ctx = Arc::new(ThreadContext::new(
            address_space,
            Arc::new(RwLock::new(RuntimeState::new())),
            Arc::new(CaptureContext::new()),
            Arc::new(emulation_config()),
            None,
            fake_objects,
            Arc::new(vfs),
        ));
        let mut thread = EmulationThread::new(ThreadId::MAIN, ctx);

        let path_ref = thread.heap_mut().alloc_string("hello.txt").unwrap();
        let args = [EmValue::ObjectRef(path_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "File",
            "ReadAllText",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = file_read_all_text_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))) = result {
            let text = thread.heap().get_string(str_ref).unwrap();
            assert_eq!(text.as_ref(), "Hello, World!");
        } else {
            panic!("Expected string result");
        }
    }

    #[test]
    fn test_file_open_read() {
        let mut thread = create_thread_with_vfs();
        let path_ref = thread.heap_mut().alloc_string("test.exe").unwrap();

        let args = [EmValue::ObjectRef(path_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "File",
            "OpenRead",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = file_open_read_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(stream_ref))) = result {
            let (data, _) = thread.heap().get_stream_data(stream_ref).unwrap().unwrap();
            assert_eq!(data, vec![0x4D, 0x5A, 0x90, 0x00]);
        } else {
            panic!("Expected stream result");
        }
    }

    #[test]
    fn test_file_exists() {
        let mut thread = create_thread_with_vfs();
        let path_ref = thread.heap_mut().alloc_string("test.exe").unwrap();

        let args = [EmValue::ObjectRef(path_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "File",
            "Exists",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = file_exists_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_file_create_returns_empty_stream() {
        let mut thread = create_test_thread();
        let path_ref = thread.heap_mut().alloc_string("new.txt").unwrap();

        let args = [EmValue::ObjectRef(path_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "File",
            "Create",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = file_create_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(stream_ref))) = result {
            let (data, pos) = thread.heap().get_stream_data(stream_ref).unwrap().unwrap();
            assert!(data.is_empty());
            assert_eq!(pos, 0);
        } else {
            panic!("Expected stream result");
        }
    }

    #[test]
    fn test_file_noop_methods() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "File",
            "Delete",
            PointerSize::Bit64,
        );
        let result = file_noop_pre(&ctx, &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
    }

    #[test]
    fn test_path_get_directory_name() {
        let mut thread = create_test_thread();
        let path_ref = thread
            .heap_mut()
            .alloc_string(r"C:\Users\test\file.exe")
            .unwrap();

        let args = [EmValue::ObjectRef(path_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Path",
            "GetDirectoryName",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = path_get_directory_name_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))) = result {
            let dir = thread.heap().get_string(str_ref).unwrap();
            assert_eq!(dir.as_ref(), r"C:\Users\test");
        } else {
            panic!("Expected string result");
        }
    }

    #[test]
    fn test_path_combine() {
        let mut thread = create_test_thread();
        let a = thread.heap_mut().alloc_string(r"C:\Users").unwrap();
        let b = thread.heap_mut().alloc_string("test").unwrap();

        let args = [EmValue::ObjectRef(a), EmValue::ObjectRef(b)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Path",
            "Combine",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = path_combine_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            let s = thread.heap().get_string(r).unwrap();
            assert_eq!(s.as_ref(), r"C:\Users\test");
        } else {
            panic!("Expected string result");
        }
    }

    #[test]
    fn test_path_combine_rooted_resets() {
        let mut thread = create_test_thread();
        let a = thread.heap_mut().alloc_string(r"C:\Users").unwrap();
        let b = thread.heap_mut().alloc_string(r"D:\Other").unwrap();

        let args = [EmValue::ObjectRef(a), EmValue::ObjectRef(b)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Path",
            "Combine",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = path_combine_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            let s = thread.heap().get_string(r).unwrap();
            assert_eq!(s.as_ref(), r"D:\Other");
        } else {
            panic!("Expected string result");
        }
    }

    #[test]
    fn test_path_get_file_name() {
        let mut thread = create_test_thread();
        let path_ref = thread
            .heap_mut()
            .alloc_string(r"C:\Users\test\file.exe")
            .unwrap();

        let args = [EmValue::ObjectRef(path_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Path",
            "GetFileName",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = path_get_file_name_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            let s = thread.heap().get_string(r).unwrap();
            assert_eq!(s.as_ref(), "file.exe");
        } else {
            panic!("Expected string result");
        }
    }

    #[test]
    fn test_path_get_extension() {
        let mut thread = create_test_thread();
        let path_ref = thread.heap_mut().alloc_string("file.exe").unwrap();

        let args = [EmValue::ObjectRef(path_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Path",
            "GetExtension",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = path_get_extension_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            let s = thread.heap().get_string(r).unwrap();
            assert_eq!(s.as_ref(), ".exe");
        } else {
            panic!("Expected string result");
        }
    }

    #[test]
    fn test_path_get_file_name_without_extension() {
        let mut thread = create_test_thread();
        let path_ref = thread.heap_mut().alloc_string(r"C:\dir\mylib.dll").unwrap();

        let args = [EmValue::ObjectRef(path_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Path",
            "GetFileNameWithoutExtension",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = path_get_file_name_without_extension_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            let s = thread.heap().get_string(r).unwrap();
            assert_eq!(s.as_ref(), "mylib");
        } else {
            panic!("Expected string result");
        }
    }

    #[test]
    fn test_path_is_path_rooted() {
        let mut thread = create_test_thread();

        // Rooted path
        let rooted_ref = thread.heap_mut().alloc_string(r"C:\test").unwrap();
        let args = [EmValue::ObjectRef(rooted_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Path",
            "IsPathRooted",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = path_is_path_rooted_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));

        // Relative path
        let rel_ref = thread.heap_mut().alloc_string("relative/path").unwrap();
        let args2 = [EmValue::ObjectRef(rel_ref)];
        let ctx2 = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Path",
            "IsPathRooted",
            PointerSize::Bit64,
        )
        .with_args(&args2);
        let result2 = path_is_path_rooted_pre(&ctx2, &mut thread);
        assert!(matches!(
            result2,
            PreHookResult::Bypass(Some(EmValue::I32(0)))
        ));
    }

    #[test]
    fn test_path_get_temp_path() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Path",
            "GetTempPath",
            PointerSize::Bit64,
        );

        let result = path_get_temp_path_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            let s = thread.heap().get_string(r).unwrap();
            assert!(s.ends_with('\\'));
        } else {
            panic!("Expected string result");
        }
    }

    #[test]
    fn test_path_change_extension() {
        let mut thread = create_test_thread();
        let path_ref = thread.heap_mut().alloc_string("file.txt").unwrap();
        let ext_ref = thread.heap_mut().alloc_string(".log").unwrap();

        let args = [EmValue::ObjectRef(path_ref), EmValue::ObjectRef(ext_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Path",
            "ChangeExtension",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = path_change_extension_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            let s = thread.heap().get_string(r).unwrap();
            assert_eq!(s.as_ref(), "file.log");
        } else {
            panic!("Expected string result");
        }
    }

    #[test]
    fn test_path_get_path_root() {
        let mut thread = create_test_thread();
        let path_ref = thread
            .heap_mut()
            .alloc_string(r"C:\Users\test\file.exe")
            .unwrap();

        let args = [EmValue::ObjectRef(path_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "Path",
            "GetPathRoot",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = path_get_path_root_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            let s = thread.heap().get_string(r).unwrap();
            assert_eq!(s.as_ref(), r"C:\");
        } else {
            panic!("Expected string result");
        }
    }

    #[test]
    fn test_filestream_ctor_case_insensitive() {
        let mut thread = create_thread_with_vfs();
        let path_ref = thread.heap_mut().alloc_string("TEST.EXE").unwrap();
        let this_ref = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();

        let args = [EmValue::ObjectRef(path_ref), EmValue::I32(3)];
        let this = EmValue::ObjectRef(this_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "FileStream",
            ".ctor",
            PointerSize::Bit64,
        )
        .with_args(&args)
        .with_this(Some(&this));

        let result = filestream_ctor_pre(&ctx, &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
    }

    #[test]
    fn test_filestream_ctor_full_path_match() {
        let mut thread = create_thread_with_vfs();
        let path_ref = thread
            .heap_mut()
            .alloc_string(r"C:\Program Files\test.exe")
            .unwrap();
        let this_ref = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();

        let args = [EmValue::ObjectRef(path_ref), EmValue::I32(3)];
        let this = EmValue::ObjectRef(this_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "FileStream",
            ".ctor",
            PointerSize::Bit64,
        )
        .with_args(&args)
        .with_this(Some(&this));

        let result = filestream_ctor_pre(&ctx, &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
    }

    #[test]
    fn test_fileinfo_ctor_and_properties() {
        let mut thread = create_thread_with_vfs();
        let path_ref = thread.heap_mut().alloc_string(r"C:\temp\test.exe").unwrap();
        let this_ref = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();

        // .ctor
        let args = [EmValue::ObjectRef(path_ref)];
        let this = EmValue::ObjectRef(this_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "FileInfo",
            ".ctor",
            PointerSize::Bit64,
        )
        .with_args(&args)
        .with_this(Some(&this));
        let result = fileinfo_ctor_pre(&ctx, &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));

        // get_Name
        let ctx_name = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "FileInfo",
            "get_Name",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = fileinfo_get_name_pre(&ctx_name, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            let s = thread.heap().get_string(r).unwrap();
            assert_eq!(s.as_ref(), "test.exe");
        } else {
            panic!("Expected name string");
        }

        // get_Extension
        let ctx_ext = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "FileInfo",
            "get_Extension",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = fileinfo_get_extension_pre(&ctx_ext, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            let s = thread.heap().get_string(r).unwrap();
            assert_eq!(s.as_ref(), ".exe");
        } else {
            panic!("Expected extension string");
        }

        // get_DirectoryName
        let ctx_dir = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "FileInfo",
            "get_DirectoryName",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = fileinfo_get_directory_name_pre(&ctx_dir, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            let s = thread.heap().get_string(r).unwrap();
            assert_eq!(s.as_ref(), r"C:\temp");
        } else {
            panic!("Expected directory string");
        }

        // get_Length (test.exe has 4 bytes)
        let ctx_len = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "FileInfo",
            "get_Length",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = fileinfo_get_length_pre(&ctx_len, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(4)))
        ));
    }

    #[test]
    fn test_streamreader_read_to_end() {
        let mut thread = create_test_thread();
        let stream_ref = thread
            .heap_mut()
            .alloc_stream(b"Hello, World!".to_vec(), None)
            .unwrap();
        let this_ref = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        thread
            .heap_mut()
            .set_field(
                this_ref,
                io_fields::STREAMREADER_STREAM,
                EmValue::ObjectRef(stream_ref),
            )
            .unwrap();

        let this = EmValue::ObjectRef(this_ref);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "StreamReader",
            "ReadToEnd",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result = streamreader_read_to_end_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            let s = thread.heap().get_string(r).unwrap();
            assert_eq!(s.as_ref(), "Hello, World!");
        } else {
            panic!("Expected string result");
        }

        // After ReadToEnd, EndOfStream should be true
        let ctx_eof = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "StreamReader",
            "get_EndOfStream",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = streamreader_get_end_of_stream_pre(&ctx_eof, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_streamreader_read_line() {
        let mut thread = create_test_thread();
        let stream_ref = thread
            .heap_mut()
            .alloc_stream(b"line1\r\nline2\nline3".to_vec(), None)
            .unwrap();
        let this_ref = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        thread
            .heap_mut()
            .set_field(
                this_ref,
                io_fields::STREAMREADER_STREAM,
                EmValue::ObjectRef(stream_ref),
            )
            .unwrap();

        let this = EmValue::ObjectRef(this_ref);

        // Line 1 (with \r\n)
        let ctx1 = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "StreamReader",
            "ReadLine",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = streamreader_read_line_pre(&ctx1, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(thread.heap().get_string(r).unwrap().as_ref(), "line1");
        } else {
            panic!("Expected line1");
        }

        // Line 2 (with \n)
        let ctx2 = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "StreamReader",
            "ReadLine",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = streamreader_read_line_pre(&ctx2, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(thread.heap().get_string(r).unwrap().as_ref(), "line2");
        } else {
            panic!("Expected line2");
        }

        // Line 3 (no trailing newline)
        let ctx3 = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "StreamReader",
            "ReadLine",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = streamreader_read_line_pre(&ctx3, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            assert_eq!(thread.heap().get_string(r).unwrap().as_ref(), "line3");
        } else {
            panic!("Expected line3");
        }

        // EOF — returns Null
        let ctx4 = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "StreamReader",
            "ReadLine",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = streamreader_read_line_pre(&ctx4, &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(Some(EmValue::Null))));
    }

    #[test]
    fn test_streamreader_read_and_peek() {
        let mut thread = create_test_thread();
        let stream_ref = thread
            .heap_mut()
            .alloc_stream(b"AB".to_vec(), None)
            .unwrap();
        let this_ref = thread
            .heap_mut()
            .alloc_object(Token::new(0x02000001))
            .unwrap();
        thread
            .heap_mut()
            .set_field(
                this_ref,
                io_fields::STREAMREADER_STREAM,
                EmValue::ObjectRef(stream_ref),
            )
            .unwrap();

        let this = EmValue::ObjectRef(this_ref);

        // Peek — should return 'A' without advancing
        let ctx_peek = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "StreamReader",
            "Peek",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = streamreader_peek_pre(&ctx_peek, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(65))) // 'A'
        ));

        // Read — should return 'A' and advance
        let ctx_read = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "StreamReader",
            "Read",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = streamreader_read_pre(&ctx_read, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(65)))
        ));

        // Read — should return 'B'
        let ctx_read2 = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "StreamReader",
            "Read",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = streamreader_read_pre(&ctx_read2, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(66))) // 'B'
        ));

        // Read at EOF — should return -1
        let ctx_read3 = HookContext::new(
            Token::new(0x0A000001),
            "System.IO",
            "StreamReader",
            "Read",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = streamreader_read_pre(&ctx_read3, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(-1)))
        ));
    }
}
