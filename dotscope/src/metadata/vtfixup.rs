//! VTableFixup directory parsing for mixed-mode and COM interop assemblies.
//!
//! This module parses the CLR VTableFixup directory from the PE file's CLR header,
//! producing structured data about vtable fixup entries, method-to-slot mappings,
//! and native PE export correlations. The parsed data is consumed by the formatting
//! module to emit ILAsm-compatible `.vtfixup`, `.vtentry`, and `.export` directives.
//!
//! # Architecture
//!
//! The VTableFixup directory is an optional CLR metadata structure that appears in
//! mixed-mode assemblies (containing both managed and unmanaged code) and assemblies
//! that export managed methods as native PE exports for COM interop. The directory
//! consists of an array of 8-byte entries, each pointing to a slot array of method
//! tokens in the PE file's data sections.
//!
//! # Key Components
//!
//! - [`VtFixupEntry`](crate::metadata::vtfixup::VtFixupEntry) - A single parsed VTableFixup directory entry with RVA, flags, and tokens
//! - [`VtFixupContext`](crate::metadata::vtfixup::VtFixupContext) - Pre-computed context containing all entries plus method-to-slot and export maps
//! - [`parse`](crate::metadata::vtfixup::parse) - Entry point that reads and correlates the VTableFixup directory
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::CilObject;
//! use dotscope::metadata::vtfixup;
//!
//! let assembly = CilObject::from_path("mixed_mode.dll")?;
//! if let Some(ctx) = vtfixup::parse(&assembly) {
//!     println!("{} vtfixup entries", ctx.entries.len());
//!     for (token, positions) in &ctx.vtentry_map {
//!         for (entry, slot) in positions {
//!             println!("  token 0x{token:08X} -> entry {entry} : slot {slot}");
//!         }
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`]. The parsed
//! [`VtFixupContext`](crate::metadata::vtfixup::VtFixupContext) is immutable after
//! construction and safe to share across threads.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::cor20header`] - Source of the VTableFixup directory RVA and size
//! - [`crate::metadata::exports`] - Native PE export table for correlating exports with vtable slots
//! - [`crate::formatting::IlFormatter`] - Rendering of parsed data as ILAsm directives
//!   (the actual `formatting::vtfixup` helper module is private; reach it via `IlFormatter`).

use std::collections::HashMap;

use crate::CilObject;

/// COR_VTABLE flag: slots are 32-bit tokens.
pub const COR_VTABLE_32BIT: u16 = 0x01;
/// COR_VTABLE flag: slots are 64-bit (padded) tokens.
pub const COR_VTABLE_64BIT: u16 = 0x02;
/// COR_VTABLE flag: vtable receives unmanaged-to-managed transition thunks.
pub const COR_VTABLE_FROM_UNMANAGED: u16 = 0x04;
/// COR_VTABLE flag: retain AppDomain across unmanaged calls.
pub const COR_VTABLE_RETAIN_APPDOMAIN: u16 = 0x08;
/// COR_VTABLE flag: call most-derived method on virtual dispatch.
pub const COR_VTABLE_CALL_MOST_DERIVED: u16 = 0x10;

/// A single parsed VTableFixup directory entry.
///
/// Each entry describes a contiguous array of method token slots at a given RVA
/// in the PE file. The `flags` field controls slot width (32-bit vs 64-bit) and
/// transition thunk behavior.
pub struct VtFixupEntry {
    /// Relative virtual address of the token slot array in the PE file.
    pub rva: u32,
    /// Number of token slots in this entry.
    pub count: u16,
    /// Bitmask of `COR_VTABLE_*` flags controlling slot behavior.
    pub flags: u16,
    /// Parsed method tokens from the slot array (one per slot).
    pub tokens: Vec<u32>,
}

/// Pre-computed VTableFixup context for one assembly.
///
/// Contains parsed VTableFixup entries, a mapping from method tokens to their
/// vtable entry/slot positions, and a mapping from method tokens to their
/// native PE export ordinal and name.
pub struct VtFixupContext {
    /// All parsed VTableFixup directory entries.
    pub entries: Vec<VtFixupEntry>,
    /// Method token to vtable positions: `token -> Vec<(entry_1based, slot_1based)>`.
    pub vtentry_map: HashMap<u32, Vec<(usize, usize)>>,
    /// Method token to native PE export: `token -> (ordinal, Option<name>)`.
    pub export_map: HashMap<u32, (u16, Option<String>)>,
}

/// Parse the VTableFixup directory from the assembly's CLR header.
///
/// Returns `None` if the assembly has no VTableFixup entries (pure managed).
pub fn parse(asm: &CilObject) -> Option<VtFixupContext> {
    let header = asm.cor20header();
    let rva = header.vtable_fixups_rva;
    let size = header.vtable_fixups_size;

    if rva == 0 || size == 0 {
        return None;
    }

    let file = asm.file();
    let data = file.rva_slice(rva as usize, size as usize).ok()?;

    // Each VTableFixup directory entry is 8 bytes: rva(u32) + count(u16) + flags(u16)
    let num_entries = (size as usize) / 8;
    let mut entries = Vec::with_capacity(num_entries);

    for i in 0..num_entries {
        let base = i.checked_mul(8)?;
        let end = base.checked_add(8)?;
        let chunk = data.get(base..end)?;
        let entry_rva = u32::from_le_bytes(chunk.get(0..4)?.try_into().ok()?);
        let count = u16::from_le_bytes(chunk.get(4..6)?.try_into().ok()?);
        let flags = u16::from_le_bytes(chunk.get(6..8)?.try_into().ok()?);

        let slot_size: usize = if flags & COR_VTABLE_64BIT != 0 { 8 } else { 4 };

        // Read method tokens at the entry's RVA
        let mut tokens = Vec::with_capacity(count as usize);
        let tok_data_len = (count as usize).saturating_mul(slot_size);
        if let Ok(tok_data) = file.rva_slice(entry_rva as usize, tok_data_len) {
            for j in 0..count as usize {
                let Some(slot_base) = j.checked_mul(slot_size) else {
                    break;
                };
                let token = if slot_size == 8 {
                    // 64-bit slot: read u64, truncate to u32 (high 32 bits are padding)
                    slot_base
                        .checked_add(8)
                        .and_then(|end| tok_data.get(slot_base..end))
                        .and_then(|s| <[u8; 8]>::try_from(s).ok())
                        .map_or(0u32, |b| u64::from_le_bytes(b) as u32)
                } else {
                    slot_base
                        .checked_add(4)
                        .and_then(|end| tok_data.get(slot_base..end))
                        .and_then(|s| <[u8; 4]>::try_from(s).ok())
                        .map_or(0u32, u32::from_le_bytes)
                };
                tokens.push(token);
            }
        }

        entries.push(VtFixupEntry {
            rva: entry_rva,
            count,
            flags,
            tokens,
        });
    }

    // Build vtentry_map: token -> Vec<(entry_1based, slot_1based)>
    let mut vtentry_map: HashMap<u32, Vec<(usize, usize)>> = HashMap::new();
    for (i, entry) in entries.iter().enumerate() {
        for (j, &token) in entry.tokens.iter().enumerate() {
            if token != 0 {
                let entry_idx = i.checked_add(1)?;
                let slot_idx = j.checked_add(1)?;
                vtentry_map
                    .entry(token)
                    .or_default()
                    .push((entry_idx, slot_idx));
            }
        }
    }

    // Build export_map from native PE exports correlated with VTableFixup slots.
    // Each native export's address RVA may point into a VTableFixup entry's token
    // array; if so, we map the method token at that slot to the export's ordinal/name.
    let mut export_map: HashMap<u32, (u16, Option<String>)> = HashMap::new();
    for func in asm.exports().native().functions() {
        if func.is_forwarder || func.address == 0 {
            continue;
        }
        let addr = func.address;

        for entry in &entries {
            let slot_size: u32 = if entry.flags & COR_VTABLE_64BIT != 0 {
                8
            } else {
                4
            };
            let range_end = entry
                .rva
                .saturating_add(u32::from(entry.count).saturating_mul(slot_size));
            if addr >= entry.rva && addr < range_end {
                let Some(slot_offset) = addr.checked_sub(entry.rva) else {
                    break;
                };
                let Some(rem) = slot_offset.checked_rem(slot_size) else {
                    break;
                };
                if rem == 0 {
                    if let Some(slot_div) = slot_offset.checked_div(slot_size) {
                        let slot_idx = slot_div as usize;
                        if let Some(&token) = entry.tokens.get(slot_idx) {
                            if token != 0 {
                                export_map.insert(token, (func.ordinal, func.name.clone()));
                            }
                        }
                    }
                }
                break;
            }
        }
    }

    Some(VtFixupContext {
        entries,
        vtentry_map,
        export_map,
    })
}
