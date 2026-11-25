//! Working assembly for byte-level techniques.
//!
//! [`WorkingAssembly`] wraps a [`CilObject`] and queues byte-level mutations
//! through the underlying [`crate::file::File`]'s interior-mutable pending-write
//! log. After mutations, `commit()` applies the pending writes in-place and
//! rebuilds the metadata index — with **zero** full-file byte copies.
//!
//! For techniques that need full assembly replacement (anti-tamper decryption,
//! native method conversion, resource insertion), [`WorkingAssembly::replace_assembly`]
//! discards pending byte patches and replaces the entire assembly.

use crate::{
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{FieldRvaRaw, TableDataOwned, TableId},
        validation::ValidationConfig,
    },
    CilObject, Error, Result,
};

/// A mutable assembly wrapper for byte-level deobfuscation techniques.
///
/// Provides two mutation modes:
///
/// 1. **Byte patching** — `write()` / `write_le()` for surgical byte-level
///    edits (token operands, immediate values). Patches queue in the
///    underlying `File`'s copy-on-write buffer and are applied in-place on
///    `commit()` — no full-file copies at any point.
///
/// 2. **Assembly replacement** — `replace_assembly()` for techniques that
///    need full PE regeneration (anti-tamper decryption, native method
///    conversion). This discards any pending byte patches and replaces the
///    entire assembly with a freshly built `CilObject`.
pub struct WorkingAssembly {
    /// The current assembly. `Option` is used solely for in-place ownership
    /// juggling during `commit()`; it is always `Some` outside that method.
    cilobject: Option<CilObject>,
}

impl WorkingAssembly {
    /// Creates a new working assembly from a `CilObject`.
    ///
    /// No byte data is copied — the `CilObject` is moved directly in.
    #[must_use]
    pub fn new(assembly: CilObject) -> Self {
        Self {
            cilobject: Some(assembly),
        }
    }

    /// Returns a reference to the inner `CilObject`, or an error if the
    /// assembly has been moved out (only possible mid-`commit()`).
    fn assembly(&self) -> Result<&CilObject> {
        self.cilobject
            .as_ref()
            .ok_or_else(|| Error::Other("WorkingAssembly: assembly unavailable".to_string()))
    }

    /// Queues a raw byte patch at the given file offset.
    ///
    /// The patch is not visible via `cilobject()` until `commit()` is called.
    ///
    /// # Errors
    ///
    /// Returns an error if the offset + data length exceeds the file size.
    pub fn write(&self, offset: usize, data: &[u8]) -> Result<()> {
        self.assembly()?.file().write(offset, data)
    }

    /// Queues a little-endian primitive patch at the given file offset.
    ///
    /// # Errors
    ///
    /// Returns an error if the offset is out of bounds.
    pub fn write_le<T: cowfile::Primitive>(&self, offset: usize, value: T) -> Result<()> {
        self.assembly()?.file().write_le(offset, value)
    }

    /// Reads a little-endian primitive from the committed file data.
    ///
    /// # Errors
    ///
    /// Returns an error if the offset is out of bounds.
    pub fn read_le<T: cowfile::Primitive>(&self, offset: usize) -> Result<T> {
        self.assembly()?.file().read_le(offset)
    }

    /// Returns `true` if there are uncommitted byte mutations.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.cilobject
            .as_ref()
            .is_some_and(|co| co.file().has_pending())
    }

    /// Commits pending byte mutations and rebuilds the `CilObject`.
    ///
    /// Patches are applied in-place to the underlying `File` — an O(patches)
    /// operation with no full-file copies. The `CilObject` is consumed and its
    /// `Arc<File>` is unwrapped to obtain exclusive ownership, the file is
    /// patched, and a fresh `CilObject` is built from it.
    ///
    /// After commit, `cilobject()` reflects the patched bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if committing or re-parsing fails.
    pub fn commit(&mut self) -> Result<()> {
        if !self.has_pending() {
            return Ok(());
        }

        // Consume the CilObject through the chain:
        let co = self
            .cilobject
            .take()
            .ok_or_else(|| Error::Other("WorkingAssembly: assembly unavailable".to_string()))?;
        let mut file = co.into_assembly().into_view().into_file()?;

        // Apply pending patches in-place (O(patches), not O(file_size)).
        file.commit_pending()?;

        // Rebuild CilObject from the patched file — no byte copies.
        let view = CilAssemblyView::from_file_with_validation(file, ValidationConfig::analysis())?;
        self.cilobject = Some(CilObject::from_view_with_validation(
            view,
            ValidationConfig::analysis(),
        )?);
        Ok(())
    }

    /// Replaces the entire assembly with a new `CilObject`.
    ///
    /// This discards any pending byte patches and replaces the current assembly.
    /// Use this for techniques that need full PE regeneration (anti-tamper
    /// decryption, native method conversion, resource insertion) where
    /// byte-level patching is insufficient.
    pub fn replace_assembly(&mut self, assembly: CilObject) {
        self.cilobject = Some(assembly);
    }

    /// Stores decrypted FieldRVA data through the assembly changes system.
    ///
    /// This is the correct way to persist decrypted field data across PE
    /// regeneration iterations. Unlike `file.write()` (which is transient),
    /// this stores the data in `AssemblyChanges` and updates the FieldRVA
    /// table row with a placeholder RVA. The PE writer then uses the stored
    /// data instead of the original encrypted bytes.
    ///
    /// Temporarily takes ownership of the `CilObject`, converts to
    /// `CilAssembly` for mutation, then rebuilds the `CilObject`.
    pub fn store_field_data(&mut self, entries: Vec<(u32, Vec<u8>)>) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        let co = self
            .cilobject
            .take()
            .ok_or_else(|| Error::Other("WorkingAssembly: assembly unavailable".into()))?;
        let mut cil = co.into_assembly();

        for (fieldrva_rid, data) in entries {
            let placeholder_rva = cil.store_field_data(data);

            let existing_row = cil
                .view()
                .tables()
                .and_then(|t| t.table::<FieldRvaRaw>())
                .and_then(|table| table.get(fieldrva_rid).ok().flatten())
                .ok_or_else(|| Error::Other(format!("FieldRVA row {fieldrva_rid} not found")))?;

            let updated_row = FieldRvaRaw {
                rid: existing_row.rid,
                token: existing_row.token,
                offset: existing_row.offset,
                rva: placeholder_rva,
                field: existing_row.field,
            };

            cil.table_row_update(
                TableId::FieldRVA,
                fieldrva_rid,
                TableDataOwned::FieldRVA(updated_row),
            )?;
        }

        // Regenerate the PE to persist the changes. into_view() would
        // discard changes, so we must go through full PE regeneration.
        let new_co = cil.into_cilobject_with(ValidationConfig::analysis(), Default::default())?;
        self.cilobject = Some(new_co);

        Ok(())
    }

    /// Returns a reference to the current metadata view.
    ///
    /// Pending byte patches are **not** visible through this reference; they
    /// are only reflected after a call to `commit()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the assembly is temporarily unavailable (only
    /// possible if called re-entrantly during `commit()`).
    pub fn cilobject(&self) -> Result<&CilObject> {
        self.assembly()
    }

    /// Consumes the working assembly, committing any pending changes,
    /// and returns the final `CilObject`.
    ///
    /// # Errors
    ///
    /// Returns an error if committing or re-parsing fails.
    pub fn into_cilobject(mut self) -> Result<CilObject> {
        self.commit()?;
        self.cilobject
            .ok_or_else(|| Error::Other("WorkingAssembly: assembly unavailable".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::WorkingAssembly, metadata::validation::ValidationConfig,
        testkit::fixture, CilObject,
    };

    fn load_sample() -> CilObject {
        let p = fixture("packers/confuserex/1.6.0/original.exe");
        CilObject::from_path_with_validation(&p, ValidationConfig::analysis())
            .unwrap_or_else(|e| panic!("Failed to load test sample: {e}"))
    }

    #[test]
    fn test_new_no_pending() {
        let wa = WorkingAssembly::new(load_sample());
        assert!(!wa.has_pending());
    }

    #[test]
    fn test_cilobject_accessible() {
        let wa = WorkingAssembly::new(load_sample());
        assert!(wa.cilobject().is_ok());
        assert!(wa.cilobject().unwrap().module().is_some());
    }

    #[test]
    fn test_write_creates_pending() {
        let wa = WorkingAssembly::new(load_sample());
        // Write a single byte at offset 0 (the MZ header)
        wa.write(0, &[0x4D]).unwrap();
        assert!(wa.has_pending());
    }

    #[test]
    fn test_commit_clears_pending() {
        let mut wa = WorkingAssembly::new(load_sample());
        wa.write(0, &[0x4D]).unwrap();
        assert!(wa.has_pending());

        wa.commit().unwrap();
        assert!(!wa.has_pending());
    }

    #[test]
    fn test_commit_noop_without_pending() {
        let mut wa = WorkingAssembly::new(load_sample());
        // commit with no pending should be a no-op
        wa.commit().unwrap();
        assert!(!wa.has_pending());
    }

    #[test]
    fn test_replace_assembly() {
        let mut wa = WorkingAssembly::new(load_sample());
        wa.write(0, &[0x4D]).unwrap();
        assert!(wa.has_pending());

        wa.replace_assembly(load_sample());
        // replace_assembly discards pending patches
        assert!(!wa.has_pending());
        assert!(wa.cilobject().is_ok());
    }

    #[test]
    fn test_into_cilobject() {
        let co = WorkingAssembly::new(load_sample())
            .into_cilobject()
            .unwrap();
        assert!(co.module().is_some());
    }
}
