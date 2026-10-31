//! Renumbering what blobs name: the type tokens inside signatures, and the rows and blobs a
//! Portable PDB's blobs name.
//!
//! Some blobs name other metadata inside their bytes:
//!
//! - **Signatures** name types by token (`TypeDefOrRefOrSpecEncoded`, ECMA-335 II.23.2.8).
//! - **Portable PDB blobs** name rows: sequence points name Document rows and the local
//!   signature's StandAloneSig row, a local constant names its enum or general type and its
//!   modifiers' types, an imports blob names AssemblyRef rows and types, and the
//!   TypeDefinitionDocuments and AsyncMethodSteppingInformation custom debug information name
//!   Document and MethodDef rows.
//! - **Document names and imports** also name blobs: a DocumentNameBlob stores its parts as
//!   `#Blob` offsets, and an imports blob its aliases and namespaces.
//!
//! When a write deletes rows, the rows after them shift and every row a blob names must
//! follow, a row the write deletes being a dangling reference like any other. When it rebuilds
//! the `#Blob` heap (deduplication, edits, removals), blobs move and every blob offset a blob
//! names must follow. Both are renumbered here, through the same [`TokenRemap`] the
//! instruction operands use and the offsets the heap writer gives each blob.
//!
//! What a blob holds is known only from the column that references it: the heap itself is
//! untyped, and a custom attribute value or a constant can read as a signature. So only the
//! blobs such a column references are renumbered, each parsed as that column's kind
//! ([`signature_blobs`], [`debug_blobs`]). A blob that does not parse as its kind is kept as it
//! is.
//!
//! The blobs that name rows are renumbered in place, as the heap writer meets them. The blobs
//! that name blobs cannot be: the offsets they name are only known once those blobs are
//! placed. The heap writer holds them back, places every other blob, and then writes them
//! encoded with the offsets their parts were given ([`BlobRemap::encode_deferred`]). A blob a
//! change adds with parts that are themselves additions is a [`BlobComposite`], encoded the
//! same way from the offsets its parts resolved to.
//!
//! A row a change adds is named by its placeholder (`0x0080_0000 | id`) in a blob a builder
//! wrote; the placeholder is resolved to the row's final number before it is renumbered.
//!
//! A blob that two columns of different kinds reference would need two renderings; compilers
//! share a blob only between identical contents, and a signature with type tokens is not
//! byte-identical to an attribute value or a constant in practice, so this case is not
//! handled.

use std::collections::HashMap;

use uguid::Guid;

use crate::{
    cilassembly::{
        changes::{AssemblyChanges, BlobComposite, ChangeRef, ChangeRefRc},
        modifications::TableModifications,
        operation::Operation,
        writer::remapper::TokenRemap,
        CilAssembly,
    },
    metadata::{
        customdebuginformation::{
            encode_custom_debug_blob, parse_custom_debug_blob, CustomDebugInfo, CustomDebugKind,
        },
        importscope::{encode_import_records, parse_import_records, ImportRecord},
        pdb::{DocumentNameBlob, LocalConstantSig, LocalConstantValue},
        sequencepoints::parse_sequence_points,
        signatures::{
            encode_field_signature, encode_local_var_signature, encode_method_signature,
            encode_method_spec_signature, encode_property_signature, encode_typespec_signature,
            parse_field_signature, parse_local_var_signature, parse_method_signature,
            parse_method_spec_signature, parse_property_signature, parse_type_spec_signature,
            SIGNATURE_HEADER,
        },
        tables::{
            skip_unreadable, CustomDebugInformationRaw, DocumentRaw, FieldRaw, ImportScopeRaw,
            LocalConstantRaw, MemberRefRaw, MethodDebugInformationRaw, MethodDefRaw, MethodSpecRaw,
            PropertyRaw, StandAloneSigRaw, TableDataOwned, TableId, TypeSpecRaw,
        },
        token::Token,
    },
    Error, Referrer, Result,
};

/// What a blob holds, by the column that references it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobKind {
    /// `MethodDef.Signature`: a method signature.
    Method,
    /// `Field.Signature`: a field signature.
    Field,
    /// `MemberRef.Signature`: a field signature (`FIELD` header) or a method signature.
    MemberRef,
    /// `StandAloneSig.Signature`: a local variable list (`LOCAL_SIG` header) or, for a `calli`,
    /// a method signature.
    StandAlone,
    /// `Property.Type`: a property signature.
    Property,
    /// `TypeSpec.Signature`: a type specification.
    TypeSpec,
    /// `MethodSpec.Instantiation`: the type arguments of a generic method instantiation.
    MethodSpec,
    /// `Document.Name`: a DocumentNameBlob, whose parts are `#Blob` offsets.
    DocumentName,
    /// `MethodDebugInformation.SequencePoints`: sequence points, which name Document rows and
    /// a StandAloneSig row; `document` is the row's Document column, 0 when the blob names
    /// its first document.
    SequencePoints {
        /// The row's Document column, as the input or the change gives it
        document: u32,
    },
    /// `LocalConstant.Signature`: a constant's type and value, which name types.
    LocalConstant,
    /// `ImportScope.Imports`: declarations naming `#Blob` offsets, AssemblyRef rows and types.
    Imports,
    /// `CustomDebugInformation.Value` of kind TypeDefinitionDocuments: Document rows.
    TypeDefinitionDocuments,
    /// `CustomDebugInformation.Value` of kind AsyncMethodSteppingInformation: MethodDef rows.
    AsyncMethodStepping,
}

impl BlobKind {
    /// Whether the blob names other blobs, so that it is written after them.
    #[must_use]
    pub fn names_blobs(self) -> bool {
        matches!(self, BlobKind::DocumentName | BlobKind::Imports)
    }

    /// Whether the blob is a signature.
    #[must_use]
    pub fn is_signature(self) -> bool {
        matches!(
            self,
            BlobKind::Method
                | BlobKind::Field
                | BlobKind::MemberRef
                | BlobKind::StandAlone
                | BlobKind::Property
                | BlobKind::TypeSpec
                | BlobKind::MethodSpec
        )
    }
}

/// A blob whose content names rows or blobs: its kind, and a column that references it, for
/// the error naming a dangling reference in it.
#[derive(Debug, Clone, Copy)]
pub struct TypedBlob {
    /// What the blob holds.
    pub kind: BlobKind,
    /// A column referencing the blob.
    pub referrer: Referrer,
}

/// The blobs the signature columns of `assembly` reference, keyed as the blob heap writer
/// meets them: by heap offset for the input's blobs, by placeholder for appended ones.
///
/// Covers the input's surviving rows and every surviving row the pending changes insert or
/// update.
#[must_use]
pub fn signature_blobs(assembly: &CilAssembly) -> HashMap<u32, TypedBlob> {
    let mut blobs = HashMap::new();
    let mut record = |index: u32, kind: BlobKind, row: Token, column: &'static str| {
        if index != 0 {
            blobs.insert(
                index,
                TypedBlob {
                    kind,
                    referrer: Referrer::Column { row, column },
                },
            );
        }
    };

    let view = assembly.view();
    if let Some(tables) = view.tables() {
        let live = |table: TableId, rid: u32| !assembly.changes().is_row_deleted(table, rid);
        if let Some(table) = tables.table::<MethodDefRaw>() {
            for row in table.iter().filter_map(skip_unreadable) {
                if live(TableId::MethodDef, row.rid) {
                    record(row.signature, BlobKind::Method, row.token, "Signature");
                }
            }
        }
        if let Some(table) = tables.table::<FieldRaw>() {
            for row in table.iter().filter_map(skip_unreadable) {
                if live(TableId::Field, row.rid) {
                    record(row.signature, BlobKind::Field, row.token, "Signature");
                }
            }
        }
        if let Some(table) = tables.table::<MemberRefRaw>() {
            for row in table.iter().filter_map(skip_unreadable) {
                if live(TableId::MemberRef, row.rid) {
                    record(row.signature, BlobKind::MemberRef, row.token, "Signature");
                }
            }
        }
        if let Some(table) = tables.table::<StandAloneSigRaw>() {
            for row in table.iter().filter_map(skip_unreadable) {
                if live(TableId::StandAloneSig, row.rid) {
                    record(row.signature, BlobKind::StandAlone, row.token, "Signature");
                }
            }
        }
        if let Some(table) = tables.table::<PropertyRaw>() {
            for row in table.iter().filter_map(skip_unreadable) {
                if live(TableId::Property, row.rid) {
                    record(row.signature, BlobKind::Property, row.token, "Type");
                }
            }
        }
        if let Some(table) = tables.table::<TypeSpecRaw>() {
            for row in table.iter().filter_map(skip_unreadable) {
                if live(TableId::TypeSpec, row.rid) {
                    record(row.signature, BlobKind::TypeSpec, row.token, "Signature");
                }
            }
        }
        if let Some(table) = tables.table::<MethodSpecRaw>() {
            for row in table.iter().filter_map(skip_unreadable) {
                if live(TableId::MethodSpec, row.rid) {
                    record(
                        row.instantiation,
                        BlobKind::MethodSpec,
                        row.token,
                        "Instantiation",
                    );
                }
            }
        }
    }

    for table_id in [
        TableId::MethodDef,
        TableId::Field,
        TableId::MemberRef,
        TableId::StandAloneSig,
        TableId::Property,
        TableId::TypeSpec,
        TableId::MethodSpec,
    ] {
        let rows: Vec<(u32, &TableDataOwned)> =
            match assembly.changes().get_table_modifications(table_id) {
                Some(TableModifications::Sparse { operations, .. }) => operations
                    .iter()
                    .filter_map(|op| match &op.operation {
                        // A row a later operation deletes references nothing.
                        Operation::Insert(rid, data) | Operation::Update(rid, data)
                            if !assembly.changes().is_row_deleted(table_id, *rid) =>
                        {
                            Some((*rid, data))
                        }
                        _ => None,
                    })
                    .collect(),
                Some(TableModifications::Replaced(rows)) => (1u32..).zip(rows).collect(),
                None => Vec::new(),
            };
        for (rid, data) in rows {
            let row = Token::from_parts(table_id, rid);
            match data {
                TableDataOwned::MethodDef(r) => {
                    record(r.signature, BlobKind::Method, row, "Signature");
                }
                TableDataOwned::Field(r) => {
                    record(r.signature, BlobKind::Field, row, "Signature");
                }
                TableDataOwned::MemberRef(r) => {
                    record(r.signature, BlobKind::MemberRef, row, "Signature");
                }
                TableDataOwned::StandAloneSig(r) => {
                    record(r.signature, BlobKind::StandAlone, row, "Signature");
                }
                TableDataOwned::Property(r) => {
                    record(r.signature, BlobKind::Property, row, "Type");
                }
                TableDataOwned::TypeSpec(r) => {
                    record(r.signature, BlobKind::TypeSpec, row, "Signature");
                }
                TableDataOwned::MethodSpec(r) => {
                    record(r.instantiation, BlobKind::MethodSpec, row, "Instantiation");
                }
                _ => {}
            }
        }
    }

    blobs
}

/// The blobs the Portable PDB columns of `assembly` reference whose content names rows or
/// blobs, keyed as the blob heap writer meets them: by heap offset for the input's blobs, by
/// placeholder for appended ones.
///
/// Covers the debug tables in the input's own metadata (their surviving rows) and every
/// surviving row the pending changes insert or update: each Document's name, each
/// MethodDebugInformation's sequence points, each LocalConstant's signature, each
/// ImportScope's imports, and the value of each CustomDebugInformation row of kind
/// TypeDefinitionDocuments or AsyncMethodSteppingInformation.
#[must_use]
pub fn debug_blobs(assembly: &CilAssembly) -> HashMap<u32, TypedBlob> {
    let mut blobs = HashMap::new();
    let mut record = |index: u32, kind: BlobKind, row: Token, column: &'static str| {
        if index != 0 {
            blobs.insert(
                index,
                TypedBlob {
                    kind,
                    referrer: Referrer::Column { row, column },
                },
            );
        }
    };
    let changes = assembly.changes();
    let view = assembly.view();
    // The kind of a custom debug information row whose blob names rows, from its GUID
    let cdi_kind = |kind: u32| -> Option<BlobKind> {
        let guid = if ChangeRef::is_heap_placeholder(kind) {
            changes
                .guid_heap_changes
                .appended_iter()
                .find(|(_, change_ref)| change_ref.placeholder() == kind)
                .map(|(bytes, _)| Guid::from_bytes(*bytes))
        } else if let Some(bytes) = changes.guid_heap_changes.get_modification(kind) {
            Some(Guid::from_bytes(*bytes))
        } else {
            view.guids().and_then(|heap| heap.get(kind as usize).ok())
        }?;
        match CustomDebugKind::from_guid(guid) {
            CustomDebugKind::TypeDefinitionDocuments => Some(BlobKind::TypeDefinitionDocuments),
            CustomDebugKind::AsyncMethodSteppingInformation => Some(BlobKind::AsyncMethodStepping),
            _ => None,
        }
    };
    let mut row = |data: &TableDataOwned, token: Token| match data {
        TableDataOwned::Document(r) => record(r.name, BlobKind::DocumentName, token, "Name"),
        TableDataOwned::MethodDebugInformation(r) => record(
            r.sequence_points,
            BlobKind::SequencePoints {
                document: r.document,
            },
            token,
            "SequencePoints",
        ),
        TableDataOwned::LocalConstant(r) => {
            record(r.signature, BlobKind::LocalConstant, token, "Signature");
        }
        TableDataOwned::ImportScope(r) => record(r.imports, BlobKind::Imports, token, "Imports"),
        TableDataOwned::CustomDebugInformation(r) => {
            if let Some(kind) = cdi_kind(r.kind) {
                record(r.value, kind, token, "Value");
            }
        }
        _ => {}
    };

    if let Some(tables) = view.tables() {
        let live = |table: TableId, rid: u32| !changes.is_row_deleted(table, rid);
        macro_rules! input_rows {
            ($($raw:ident => $variant:ident),* $(,)?) => {
                $(
                    if let Some(table) = tables.table::<$raw>() {
                        for input in table.iter().filter_map(skip_unreadable) {
                            if live(TableId::$variant, input.rid) {
                                let token = input.token;
                                row(&TableDataOwned::$variant(input), token);
                            }
                        }
                    }
                )*
            };
        }
        input_rows!(
            DocumentRaw => Document,
            MethodDebugInformationRaw => MethodDebugInformation,
            LocalConstantRaw => LocalConstant,
            ImportScopeRaw => ImportScope,
            CustomDebugInformationRaw => CustomDebugInformation,
        );
    }

    for table_id in [
        TableId::Document,
        TableId::MethodDebugInformation,
        TableId::LocalConstant,
        TableId::ImportScope,
        TableId::CustomDebugInformation,
    ] {
        match changes.get_table_modifications(table_id) {
            Some(TableModifications::Sparse { operations, .. }) => {
                for op in operations {
                    // A row a later operation deletes references nothing.
                    if let Operation::Insert(rid, data) | Operation::Update(rid, data) =
                        &op.operation
                    {
                        if !changes.is_row_deleted(table_id, *rid) {
                            row(data, Token::from_parts(table_id, *rid));
                        }
                    }
                }
            }
            Some(TableModifications::Replaced(rows)) => {
                for (rid, data) in (1u32..).zip(rows) {
                    row(data, Token::from_parts(table_id, rid));
                }
            }
            None => {}
        }
    }

    blobs
}

/// What the blob heap writer needs to renumber what blobs name: which blobs name rows or
/// blobs, how the write renumbers tokens, and the changes, for the rows and blobs they add.
pub struct BlobRemap<'a> {
    /// The blobs whose content names rows or blobs, from [`signature_blobs`] and
    /// [`debug_blobs`].
    pub blobs: &'a HashMap<u32, TypedBlob>,
    /// How the write renumbers tokens.
    pub tokens: &'a TokenRemap,
    /// The assembly's changes: the rows a placeholder names, and the composite blobs.
    pub changes: &'a AssemblyChanges,
}

impl BlobRemap<'_> {
    /// The blob at `index` with the rows it names renumbered, or `None` when it names no rows,
    /// names blobs (and is written by [`BlobRemap::encode_deferred`]), or nothing in it
    /// changes. A blob that does not parse as its kind is kept as it is.
    ///
    /// # Errors
    ///
    /// [`crate::Error::DanglingReference`] when the blob names a deleted row, under
    /// [`DanglingPolicy::Error`](crate::cilassembly::writer::DanglingPolicy::Error), and an
    /// encoding error for a blob that cannot be written back.
    pub fn remap(&self, index: u32, blob: &[u8]) -> Result<Option<Vec<u8>>> {
        let Some(typed) = self.blobs.get(&index) else {
            return Ok(None);
        };
        // An input blob names input rows, which change only when rows are deleted; an
        // appended one may name rows a change adds, by placeholder
        if self.tokens.is_empty() && !ChangeRef::is_heap_placeholder(index) {
            return Ok(None);
        }
        if typed.kind.is_signature() {
            if self.tokens.is_empty() {
                return Ok(None);
            }
            return remap_signature_tokens(blob, typed.kind, self.tokens, typed.referrer);
        }
        if typed.kind.names_blobs() {
            return Ok(None);
        }
        remap_debug_tokens(blob, typed.kind, &mut |token| {
            self.token(typed.referrer, token)
        })
    }

    /// Whether the blob at `index` (with the change id `change_id`, for an appended one) names
    /// blobs: the heap writer writes it after every other blob, with
    /// [`BlobRemap::encode_deferred`].
    #[must_use]
    pub fn defers(&self, index: u32, change_id: Option<u64>) -> bool {
        change_id.is_some_and(|id| self.changes.blob_composites.contains_key(&id))
            || self
                .blobs
                .get(&index)
                .is_some_and(|typed| typed.kind.names_blobs())
    }

    /// The bytes of a blob that names blobs, with every blob it names at the offset
    /// `blob_offset` gives it and every row renumbered.
    ///
    /// A composite blob (`change_id` names one) is encoded from the offsets its parts
    /// resolved to; any other is decoded from `blob` and encoded again. A blob that does not
    /// parse as its kind is returned as it is.
    ///
    /// # Arguments
    ///
    /// * `index` - The blob's input offset, or its placeholder for an appended blob
    /// * `change_id` - The change id of an appended blob
    /// * `blob` - The blob's bytes, as the input or the change gives them
    /// * `blob_offset` - The offset the written heap gives the blob at an input offset
    ///
    /// # Errors
    ///
    /// When a blob or row it names is gone ([`crate::Error::DanglingReference`] for a row,
    /// under [`DanglingPolicy::Error`](crate::cilassembly::writer::DanglingPolicy::Error)), a
    /// part of a composite has no offset, or the blob cannot be written back.
    pub fn encode_deferred(
        &self,
        index: u32,
        change_id: Option<u64>,
        blob: &[u8],
        blob_offset: &mut dyn FnMut(u32) -> Result<u32>,
    ) -> Result<Vec<u8>> {
        let typed = self.blobs.get(&index).copied();
        if let Some(composite) = change_id.and_then(|id| self.changes.blob_composites.get(&id)) {
            let referrer = typed.map_or_else(
                || match composite {
                    BlobComposite::DocumentName { .. } => Referrer::Column {
                        row: Token::from_parts(TableId::Document, 0),
                        column: "Name",
                    },
                    BlobComposite::Imports(_) => Referrer::Column {
                        row: Token::from_parts(TableId::ImportScope, 0),
                        column: "Imports",
                    },
                },
                |typed| typed.referrer,
            );
            let resolved = |part: &Option<ChangeRefRc>| -> Result<u32> {
                match part {
                    None => Ok(0),
                    Some(change_ref) => change_ref.offset().ok_or_else(|| {
                        Error::LayoutFailed(format!(
                            "{referrer} names a blob the write has not placed"
                        ))
                    }),
                }
            };
            return match composite {
                BlobComposite::DocumentName { separator, parts } => DocumentNameBlob {
                    separator: *separator,
                    parts: parts.iter().map(resolved).collect::<Result<_>>()?,
                }
                .encode(),
                BlobComposite::Imports(imports) => {
                    let records = imports
                        .iter()
                        .map(|import| {
                            Ok(ImportRecord {
                                kind: import.kind,
                                alias: resolved(&import.alias)?,
                                assembly: self.row(
                                    referrer,
                                    TableId::AssemblyRef,
                                    import.assembly,
                                )?,
                                namespace: resolved(&import.namespace)?,
                                target: import
                                    .target
                                    .map(|target| {
                                        self.token(referrer, target.value()).map(Token::new)
                                    })
                                    .transpose()?,
                            })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    encode_import_records(&records)
                }
            };
        }
        let Some(typed) = typed else {
            return Ok(blob.to_vec());
        };
        let referrer = typed.referrer;
        match typed.kind {
            BlobKind::DocumentName => {
                let Ok(mut name) = DocumentNameBlob::parse(blob) else {
                    return Ok(blob.to_vec());
                };
                for part in &mut name.parts {
                    *part = blob_offset(*part)?;
                }
                name.encode()
            }
            BlobKind::Imports => {
                let Ok(mut records) = parse_import_records(blob) else {
                    return Ok(blob.to_vec());
                };
                for record in &mut records {
                    record.alias = blob_offset(record.alias)?;
                    record.namespace = blob_offset(record.namespace)?;
                    record.assembly = self.row(referrer, TableId::AssemblyRef, record.assembly)?;
                    if let Some(target) = &mut record.target {
                        *target = Token::new(self.token(referrer, target.value())?);
                    }
                }
                encode_import_records(&records)
            }
            _ => Ok(blob.to_vec()),
        }
    }

    /// The token `token` is written as: a row a change adds, named by its placeholder,
    /// resolved to its row, then renumbered as the write renumbers rows.
    fn token(&self, referrer: Referrer, token: u32) -> Result<u32> {
        let row = token & 0x00FF_FFFF;
        let token = if ChangeRef::is_placeholder(row) {
            self.changes
                .lookup_by_placeholder(row)
                .and_then(|change_ref| change_ref.token())
                .map_or(token, |resolved| resolved.value())
        } else {
            token
        };
        self.tokens.remap(referrer, token)
    }

    /// The row `row` of `table` is written as; 0 (no row) stays 0.
    fn row(&self, referrer: Referrer, table: TableId, row: u32) -> Result<u32> {
        if row == 0 {
            return Ok(0);
        }
        Ok(self.token(referrer, Token::from_parts(table, row).value())? & 0x00FF_FFFF)
    }
}

/// `blob`, read as the Portable PDB blob `kind`, with every row it names renumbered by
/// `token` (a function of whole tokens); `None` when it does not parse as `kind` or nothing
/// in it changes.
///
/// # Errors
///
/// As `token`, and an encoding error for a blob that cannot be written back.
fn remap_debug_tokens(
    blob: &[u8],
    kind: BlobKind,
    token: &mut dyn FnMut(u32) -> Result<u32>,
) -> Result<Option<Vec<u8>>> {
    let mut changed = false;
    let mut renumber = |target: &mut Token| -> Result<()> {
        if target.row() == 0 {
            return Ok(());
        }
        let new = Token::new(token(target.value())?);
        if new != *target {
            *target = new;
            changed = true;
        }
        Ok(())
    };
    let encoded = match kind {
        BlobKind::SequencePoints { document } => {
            let Ok(mut points) = parse_sequence_points(blob, document) else {
                return Ok(None);
            };
            renumber_row(
                &mut renumber,
                TableId::StandAloneSig,
                &mut points.local_signature,
            )?;
            for point in &mut points.points {
                renumber_row(&mut renumber, TableId::Document, &mut point.document)?;
            }
            let mut column = document;
            renumber_row(&mut renumber, TableId::Document, &mut column)?;
            points.to_bytes(column)
        }
        BlobKind::LocalConstant => {
            let Ok(mut constant) = LocalConstantSig::parse(blob) else {
                return Ok(None);
            };
            for modifier in &mut constant.modifiers {
                renumber(&mut modifier.modifier_type)?;
            }
            match &mut constant.value {
                LocalConstantValue::Enum { enum_type, .. } => renumber(enum_type)?,
                LocalConstantValue::General { type_token, .. } => renumber(type_token)?,
                LocalConstantValue::Primitive(_) | LocalConstantValue::NullObject => {}
            }
            constant.encode()
        }
        BlobKind::TypeDefinitionDocuments => {
            let Ok(CustomDebugInfo::TypeDefinitionDocuments(mut documents)) =
                parse_custom_debug_blob(blob, CustomDebugKind::TypeDefinitionDocuments)
            else {
                return Ok(None);
            };
            for document in &mut documents {
                renumber_row(&mut renumber, TableId::Document, document)?;
            }
            encode_custom_debug_blob(&CustomDebugInfo::TypeDefinitionDocuments(documents))
        }
        BlobKind::AsyncMethodStepping => {
            let Ok(CustomDebugInfo::AsyncMethodSteppingInformation {
                catch_handler,
                mut awaits,
            }) = parse_custom_debug_blob(blob, CustomDebugKind::AsyncMethodSteppingInformation)
            else {
                return Ok(None);
            };
            for await_point in &mut awaits {
                renumber_row(&mut renumber, TableId::MethodDef, &mut await_point.method)?;
            }
            encode_custom_debug_blob(&CustomDebugInfo::AsyncMethodSteppingInformation {
                catch_handler,
                awaits,
            })
        }
        _ => return Ok(None),
    };
    if changed {
        Ok(Some(encoded?))
    } else {
        Ok(None)
    }
}

/// Renumbers the row `row` of `table` with `renumber`, which renumbers whole tokens.
fn renumber_row(
    renumber: &mut dyn FnMut(&mut Token) -> Result<()>,
    table: TableId,
    row: &mut u32,
) -> Result<()> {
    let mut token = Token::from_parts(table, *row);
    renumber(&mut token)?;
    *row = token.row();
    Ok(())
}

/// `signature`, read as `kind`, with every type token renumbered by `tokens`; `None` when it
/// does not parse as `kind` or nothing in it changes.
///
/// # Errors
///
/// [`crate::Error::DanglingReference`] naming `referrer` when a token names a deleted row,
/// under [`DanglingPolicy::Error`](crate::cilassembly::writer::DanglingPolicy::Error), and an
/// encoding error for a signature that cannot be written back.
pub fn remap_signature_tokens(
    signature: &[u8],
    kind: BlobKind,
    tokens: &TokenRemap,
    referrer: Referrer,
) -> Result<Option<Vec<u8>>> {
    let mut changed = false;
    let mut renumber = |token: &mut Token| -> Result<()> {
        let new = tokens.remap(referrer, token.value())?;
        if new != token.value() {
            *token = Token::new(new);
            changed = true;
        }
        Ok(())
    };
    let header = signature.first().copied();
    // A signature that does not parse as its kind is kept as it is.
    let encoded = match (kind, header) {
        (BlobKind::Field, _) | (BlobKind::MemberRef, Some(SIGNATURE_HEADER::FIELD)) => {
            let Ok(mut parsed) = parse_field_signature(signature) else {
                return Ok(None);
            };
            parsed.for_each_type_token_mut(&mut renumber)?;
            encode_field_signature(&parsed)
        }
        (BlobKind::StandAlone, Some(SIGNATURE_HEADER::LOCAL_SIG)) => {
            let Ok(mut parsed) = parse_local_var_signature(signature) else {
                return Ok(None);
            };
            parsed.for_each_type_token_mut(&mut renumber)?;
            encode_local_var_signature(&parsed)
        }
        (BlobKind::Method | BlobKind::MemberRef | BlobKind::StandAlone, _) => {
            let Ok(mut parsed) = parse_method_signature(signature) else {
                return Ok(None);
            };
            parsed.for_each_type_token_mut(&mut renumber)?;
            encode_method_signature(&parsed)
        }
        (BlobKind::Property, _) => {
            let Ok(mut parsed) = parse_property_signature(signature) else {
                return Ok(None);
            };
            parsed.for_each_type_token_mut(&mut renumber)?;
            encode_property_signature(&parsed)
        }
        (BlobKind::TypeSpec, _) => {
            let Ok(mut parsed) = parse_type_spec_signature(signature) else {
                return Ok(None);
            };
            parsed.for_each_type_token_mut(&mut renumber)?;
            encode_typespec_signature(&parsed)
        }
        (BlobKind::MethodSpec, _) => {
            let Ok(mut parsed) = parse_method_spec_signature(signature) else {
                return Ok(None);
            };
            parsed.for_each_type_token_mut(&mut renumber)?;
            encode_method_spec_signature(&parsed)
        }
        // Not a signature
        _ => return Ok(None),
    };
    if changed {
        Ok(Some(encoded?))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::{writer::DanglingPolicy, ChangeIds, HeapChanges},
        metadata::{
            customdebuginformation::AsyncAwait,
            importscope::ImportKind,
            pdb::PrimitiveConstant,
            sequencepoints::{SequencePoint, SequencePoints},
            signatures::CustomModifier,
        },
        Error,
    };

    const REFERRER: Referrer = Referrer::Column {
        row: Token::new(0x0600_0001),
        column: "Signature",
    };

    /// TypeRef 5 becomes 3, TypeDef 4 becomes 2, TypeSpec 2 becomes 1; TypeRef 9 is deleted.
    fn tokens(dangling: DanglingPolicy) -> TokenRemap {
        TokenRemap::for_tests(
            &[
                (0x0100_0005, 0x0100_0003),
                (0x0200_0004, 0x0200_0002),
                (0x1B00_0002, 0x1B00_0001),
            ],
            &[0x0100_0009],
            dangling,
        )
    }

    fn remapped(signature: &[u8], kind: BlobKind) -> Option<Vec<u8>> {
        remap_signature_tokens(signature, kind, &tokens(DanglingPolicy::Error), REFERRER).unwrap()
    }

    /// Each kind of signature has its tokens renumbered, read as its column says.
    #[test]
    fn every_kind_of_signature_is_renumbered() {
        // CLASS TypeRef 5 is 0x12 0x15; TypeRef 3 is 0x12 0x0D.
        assert_eq!(
            remapped(&[0x00, 0x00, 0x12, 0x15], BlobKind::Method),
            Some(vec![0x00, 0x00, 0x12, 0x0D])
        );
        assert_eq!(
            remapped(&[0x06, 0x12, 0x15], BlobKind::Field),
            Some(vec![0x06, 0x12, 0x0D])
        );
        assert_eq!(
            remapped(&[0x06, 0x12, 0x15], BlobKind::MemberRef),
            Some(vec![0x06, 0x12, 0x0D])
        );
        assert_eq!(
            remapped(&[0x20, 0x00, 0x12, 0x15], BlobKind::MemberRef),
            Some(vec![0x20, 0x00, 0x12, 0x0D])
        );
        assert_eq!(
            remapped(&[0x07, 0x01, 0x12, 0x15], BlobKind::StandAlone),
            Some(vec![0x07, 0x01, 0x12, 0x0D])
        );
        // A calli signature: DEFAULT, no parameters, returning CLASS TypeRef 5.
        assert_eq!(
            remapped(&[0x00, 0x00, 0x12, 0x15], BlobKind::StandAlone),
            Some(vec![0x00, 0x00, 0x12, 0x0D])
        );
        assert_eq!(
            remapped(&[0x28, 0x00, 0x12, 0x15], BlobKind::Property),
            Some(vec![0x28, 0x00, 0x12, 0x0D])
        );
        // GENERICINST CLASS TypeDef 4 <CLASS TypeSpec 2>; TypeDef 4 is 0x10, TypeSpec 2 is 0x0A.
        assert_eq!(
            remapped(&[0x15, 0x12, 0x10, 0x01, 0x12, 0x0A], BlobKind::TypeSpec),
            Some(vec![0x15, 0x12, 0x08, 0x01, 0x12, 0x06])
        );
        assert_eq!(
            remapped(&[0x0A, 0x01, 0x12, 0x15], BlobKind::MethodSpec),
            Some(vec![0x0A, 0x01, 0x12, 0x0D])
        );
    }

    /// The extra arguments of a vararg call site and a TypeSpec's custom modifiers are
    /// signature tokens too.
    #[test]
    fn varargs_and_type_spec_modifiers_are_renumbered() {
        // VARARG, one fixed and one extra parameter: void (I4, SENTINEL, CLASS TypeRef 5)
        assert_eq!(
            remapped(
                &[0x05, 0x02, 0x01, 0x08, 0x41, 0x12, 0x15],
                BlobKind::MemberRef
            ),
            Some(vec![0x05, 0x02, 0x01, 0x08, 0x41, 0x12, 0x0D])
        );
        // CMOD_OPT TypeRef 5, then I4
        assert_eq!(
            remapped(&[0x20, 0x15, 0x08], BlobKind::TypeSpec),
            Some(vec![0x20, 0x0D, 0x08])
        );
    }

    /// A signature naming a deleted row is a dangling reference naming its column; under the
    /// null policy the token becomes the null token of its table.
    #[test]
    fn a_deleted_type_in_a_signature_is_a_dangling_reference() {
        // CLASS TypeRef 9 is 0x12 0x25.
        let signature = [0x06, 0x12, 0x25];
        let error = remap_signature_tokens(
            &signature,
            BlobKind::Field,
            &tokens(DanglingPolicy::Error),
            REFERRER,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                Error::DanglingReference { referrer, target }
                    if referrer == REFERRER && target == Token::new(0x0100_0009)
            ),
            "{error}"
        );
        assert_eq!(
            remap_signature_tokens(
                &signature,
                BlobKind::Field,
                &tokens(DanglingPolicy::Null),
                REFERRER
            )
            .unwrap(),
            Some(vec![0x06, 0x12, 0x01])
        );
    }

    /// Nothing to renumber, or bytes that are not the kind their column says, leave the blob
    /// as it is.
    #[test]
    fn an_unchanged_or_unreadable_signature_is_kept() {
        assert_eq!(remapped(&[0x06, 0x08], BlobKind::Field), None);
        assert_eq!(remapped(&[0x06, 0x12, 0x11], BlobKind::Field), None);
        assert_eq!(remapped(&[0xFF, 0xFF], BlobKind::Method), None);
    }

    /// Only blobs a signature column references are touched: an attribute value that reads
    /// as a method signature (`01 00 11 4D...`: C calling convention, no parameters, returning
    /// VALUETYPE TypeRef 19) is not one.
    #[test]
    fn a_blob_no_signature_column_references_is_untouched() {
        let tokens =
            TokenRemap::for_tests(&[(0x0100_0013, 0x0100_0010)], &[], DanglingPolicy::Error);
        let mut blobs = HashMap::new();
        blobs.insert(
            0x40,
            TypedBlob {
                kind: BlobKind::Field,
                referrer: REFERRER,
            },
        );
        let changes = AssemblyChanges::new();
        let remap = BlobRemap {
            blobs: &blobs,
            tokens: &tokens,
            changes: &changes,
        };
        let attribute_value = [0x01, 0x00, 0x11, 0x4D, 0x65, 0x74, 0x61, 0x00, 0x00];
        assert_eq!(remap.remap(0x10, &attribute_value).unwrap(), None);
        assert_eq!(
            remap.remap(0x40, &[0x06, 0x11, 0x4D]).unwrap(),
            Some(vec![0x06, 0x11, 0x41])
        );
    }

    /// Document 3 becomes 2, MethodDef 5 becomes 4, StandAloneSig 2 becomes 1, TypeRef 5
    /// becomes 3 and AssemblyRef 2 becomes 1; Document 9 is deleted.
    fn debug_tokens(dangling: DanglingPolicy) -> TokenRemap {
        TokenRemap::for_tests(
            &[
                (0x3000_0003, 0x3000_0002),
                (0x0600_0005, 0x0600_0004),
                (0x1100_0002, 0x1100_0001),
                (0x0100_0005, 0x0100_0003),
                (0x2300_0002, 0x2300_0001),
            ],
            &[0x3000_0009],
            dangling,
        )
    }

    fn debug_remapped(blob: &[u8], kind: BlobKind) -> Result<Option<Vec<u8>>> {
        let tokens = debug_tokens(DanglingPolicy::Error);
        remap_debug_tokens(blob, kind, &mut |token| tokens.remap(REFERRER, token))
    }

    fn point(il_offset: u32, line: u32, document: u32) -> SequencePoint {
        let mut point = SequencePoint::new(il_offset, line, 1, line, 9).unwrap();
        point.document = document;
        point
    }

    /// Sequence points follow the Document and StandAloneSig rows they name: in the blob's
    /// header and document records for a method spanning documents, and in the local
    /// signature for one with its own document.
    #[test]
    fn sequence_points_follow_their_rows() {
        let spanning = SequencePoints {
            local_signature: 2,
            points: vec![point(0, 10, 3), point(4, 11, 4), point(8, 12, 3)],
        };
        let blob = spanning.to_bytes(0).unwrap();
        let written = debug_remapped(&blob, BlobKind::SequencePoints { document: 0 })
            .unwrap()
            .unwrap();
        let read = parse_sequence_points(&written, 0).unwrap();
        assert_eq!(read.local_signature, 1);
        let documents: Vec<u32> = read.points.iter().map(|point| point.document).collect();
        assert_eq!(documents, [2, 4, 2]);

        let own = SequencePoints {
            local_signature: 2,
            points: vec![point(0, 10, 3), point(4, 11, 3)],
        };
        let blob = own.to_bytes(3).unwrap();
        let written = debug_remapped(&blob, BlobKind::SequencePoints { document: 3 })
            .unwrap()
            .unwrap();
        let read = parse_sequence_points(&written, 2).unwrap();
        assert_eq!(read.local_signature, 1);
        assert!(read.points.iter().all(|point| point.document == 2));
    }

    /// A local constant follows the types it names: its enum type and its modifiers' types.
    #[test]
    fn a_local_constant_follows_its_types() {
        let constant = LocalConstantSig {
            modifiers: vec![CustomModifier {
                is_required: false,
                modifier_type: Token::new(0x0100_0005),
            }],
            value: LocalConstantValue::Enum {
                value: PrimitiveConstant::I2(7),
                enum_type: Token::new(0x0100_0005),
            },
        };
        let written = debug_remapped(&constant.encode().unwrap(), BlobKind::LocalConstant)
            .unwrap()
            .unwrap();
        let read = LocalConstantSig::parse(&written).unwrap();
        assert_eq!(read.modifiers[0].modifier_type, Token::new(0x0100_0003));
        assert_eq!(
            read.value,
            LocalConstantValue::Enum {
                value: PrimitiveConstant::I2(7),
                enum_type: Token::new(0x0100_0003),
            }
        );
    }

    /// The custom debug information that names rows follows them: a type's documents, and the
    /// method each await of an async method is in. One naming a deleted document is a
    /// dangling reference.
    #[test]
    fn custom_debug_information_follows_its_rows() {
        let documents =
            encode_custom_debug_blob(&CustomDebugInfo::TypeDefinitionDocuments(vec![3, 1]))
                .unwrap();
        let written = debug_remapped(&documents, BlobKind::TypeDefinitionDocuments)
            .unwrap()
            .unwrap();
        assert_eq!(
            parse_custom_debug_blob(&written, CustomDebugKind::TypeDefinitionDocuments).unwrap(),
            CustomDebugInfo::TypeDefinitionDocuments(vec![2, 1])
        );

        let stepping = CustomDebugInfo::AsyncMethodSteppingInformation {
            catch_handler: Some(0x40),
            awaits: vec![AsyncAwait {
                yield_offset: 0x10,
                resume_offset: 0x20,
                method: 5,
            }],
        };
        let written = debug_remapped(
            &encode_custom_debug_blob(&stepping).unwrap(),
            BlobKind::AsyncMethodStepping,
        )
        .unwrap()
        .unwrap();
        let CustomDebugInfo::AsyncMethodSteppingInformation {
            awaits,
            catch_handler,
        } = parse_custom_debug_blob(&written, CustomDebugKind::AsyncMethodSteppingInformation)
            .unwrap()
        else {
            panic!("stepping information");
        };
        assert_eq!((catch_handler, awaits[0].method), (Some(0x40), 4));

        let deleted =
            encode_custom_debug_blob(&CustomDebugInfo::TypeDefinitionDocuments(vec![9])).unwrap();
        let error = debug_remapped(&deleted, BlobKind::TypeDefinitionDocuments).unwrap_err();
        assert!(
            matches!(error, Error::DanglingReference { target, .. } if target == Token::new(0x3000_0009)),
            "{error}"
        );
        // Nothing to renumber leaves the blob as it is
        let untouched =
            encode_custom_debug_blob(&CustomDebugInfo::TypeDefinitionDocuments(vec![1])).unwrap();
        assert_eq!(
            debug_remapped(&untouched, BlobKind::TypeDefinitionDocuments).unwrap(),
            None
        );
    }

    /// A document name and an imports blob are written with the offsets the rebuilt heap gives
    /// the blobs they name, and an imports blob with its rows renumbered.
    #[test]
    fn blobs_that_name_blobs_follow_them() {
        let tokens = debug_tokens(DanglingPolicy::Error);
        let changes = AssemblyChanges::new();
        let mut blobs = HashMap::new();
        for (index, kind) in [(0x40, BlobKind::DocumentName), (0x50, BlobKind::Imports)] {
            blobs.insert(
                index,
                TypedBlob {
                    kind,
                    referrer: REFERRER,
                },
            );
        }
        let remap = BlobRemap {
            blobs: &blobs,
            tokens: &tokens,
            changes: &changes,
        };
        assert!(remap.defers(0x40, None) && remap.defers(0x50, None) && !remap.defers(0x60, None));
        let mut moved = |offset: u32| -> Result<u32> {
            Ok(match offset {
                5 => 7,
                9 => 2,
                other => other,
            })
        };

        let name = DocumentNameBlob {
            separator: b'/',
            parts: vec![0, 5, 9],
        };
        let written = remap
            .encode_deferred(0x40, None, &name.encode().unwrap(), &mut moved)
            .unwrap();
        assert_eq!(DocumentNameBlob::parse(&written).unwrap().parts, [0, 7, 2]);

        let imports = [
            ImportRecord {
                kind: ImportKind::DefineAssemblyNamespaceAlias,
                alias: 5,
                assembly: 2,
                namespace: 9,
                target: None,
            },
            ImportRecord {
                kind: ImportKind::ImportType,
                alias: 0,
                assembly: 0,
                namespace: 0,
                target: Some(Token::new(0x0100_0005)),
            },
        ];
        let written = remap
            .encode_deferred(
                0x50,
                None,
                &encode_import_records(&imports).unwrap(),
                &mut moved,
            )
            .unwrap();
        let read = parse_import_records(&written).unwrap();
        assert_eq!(
            (read[0].alias, read[0].assembly, read[0].namespace),
            (7, 1, 2)
        );
        assert_eq!(read[1].target, Some(Token::new(0x0100_0003)));
    }

    /// A composite blob is encoded from the offsets its parts resolved to; an empty part is
    /// index 0.
    #[test]
    fn a_composite_is_encoded_from_its_parts() {
        let tokens = TokenRemap::default();
        let mut changes = AssemblyChanges::new();
        let mut heap = HeapChanges::<Vec<u8>>::new_blobs(ChangeIds::new());
        let src = heap.append(b"src".to_vec());
        let file = heap.append(b"a.cs".to_vec());
        src.resolve_to_offset(0x21);
        file.resolve_to_offset(0x25);
        let name = changes.blob_heap_changes.append(Vec::new());
        changes.blob_composites.insert(
            name.id(),
            BlobComposite::DocumentName {
                separator: b'/',
                parts: vec![None, Some(src), Some(file)],
            },
        );
        let blobs = HashMap::new();
        let remap = BlobRemap {
            blobs: &blobs,
            tokens: &tokens,
            changes: &changes,
        };
        assert!(remap.defers(name.placeholder(), Some(name.id())));
        let written = remap
            .encode_deferred(name.placeholder(), Some(name.id()), &[], &mut |offset| {
                Ok(offset)
            })
            .unwrap();
        assert_eq!(written, [b'/', 0x00, 0x21, 0x25]);
    }
}
