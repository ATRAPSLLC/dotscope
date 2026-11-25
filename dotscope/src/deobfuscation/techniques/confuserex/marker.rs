//! ConfuserEx marker attribute detection and removal.
//!
//! ConfuserEx stamps protected assemblies with custom attributes —
//! `ConfusedByAttribute` and `ConfuserVersionAttribute` — that identify the
//! obfuscator. This technique detects those marker attributes by scanning
//! the CustomAttribute table for entries whose constructor resolves to a
//! type (TypeDef or TypeRef) with a known ConfuserEx name, then marks them
//! for removal during the cleanup phase.
//!
//! # Detection
//!
//! For each CustomAttribute entry, resolves the constructor to find the
//! declaring type:
//! - **MethodDef constructor**: walks the TypeDef table to find the owning type
//! - **MemberRef constructor**: resolves the class (TypeDef or TypeRef)
//!
//! Matches type names containing `ConfusedByAttribute`, `ConfuserVersion`,
//! or `ConfuserEx`. Also extracts the embedded version string when present.
//!
//! # Transform
//!
//! Records the marker attribute tokens for removal. Actual deletion happens
//! during assembly regeneration since removing table rows requires a full
//! PE rebuild.

use std::any::Any;

use crate::{
    compiler::{EventKind, EventLog},
    deobfuscation::{
        techniques::{
            Detection, Evidence, Technique, TechniqueCapability, TechniqueCategory, WorkingAssembly,
        },
        utils::resolve_custom_attr_type,
    },
    metadata::{
        tables::{CustomAttributeRaw, TableId},
        token::Token,
    },
    utils::read_packed_len,
    CilObject, Result,
};

/// Findings from ConfuserEx marker attribute detection.
#[derive(Debug)]
pub struct MarkerFindings {
    /// Tokens of detected marker custom attributes.
    pub tokens: Vec<Token>,
    /// Tokens of locally-defined marker TypeDefs (for cleanup).
    pub typedef_tokens: Vec<Token>,
    /// ConfuserEx version string extracted from attribute data, if present.
    pub version: Option<String>,
}

/// Detects and removes ConfuserEx marker attributes.
///
/// Scans for `ConfusedByAttribute` and `ConfuserVersionAttribute` custom
/// attributes that ConfuserEx injects to mark protected assemblies. These
/// serve no runtime purpose and are removed for clean output.
pub struct ConfuserExMarker;

impl Technique for ConfuserExMarker {
    fn id(&self) -> &'static str {
        "confuserex.marker"
    }

    fn name(&self) -> &'static str {
        "ConfuserEx Marker Attribute Removal"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Metadata
    }

    fn capabilities(&self) -> Vec<TechniqueCapability> {
        vec![TechniqueCapability::ByteTransform]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let Some(tables) = assembly.tables() else {
            return Detection::new_empty();
        };
        let Some(ca_table) = tables.table::<CustomAttributeRaw>() else {
            return Detection::new_empty();
        };

        let mut marker_tokens = Vec::new();
        let mut typedef_tokens = Vec::new();
        let mut version = None;

        for attr in ca_table {
            let attr = match attr {
                Ok(row) => row,
                Err(e) => {
                    log::warn!("skipping unreadable metadata row: {e}");
                    continue;
                }
            };
            // Resolve the constructor to find the declaring type name.
            // ConfuserEx defines marker attributes locally, so the constructor
            // is typically a MethodDef pointing to a local TypeDef.
            let Some(resolved) = resolve_custom_attr_type(assembly, &attr) else {
                continue;
            };

            let name = resolved.name;

            if name.contains("ConfuserVersion") || name.contains("ConfusedByAttribute") {
                let attr_token = Token::new((TableId::CustomAttribute as u32) << 24 | attr.rid);
                marker_tokens.push(attr_token);

                // Track the local TypeDef for cleanup removal
                if let Some(token) = resolved.typedef_token {
                    if !typedef_tokens.contains(&token) {
                        typedef_tokens.push(token);
                    }
                }

                // Extract version from ConfuserVersion attribute blob
                if name.contains("ConfuserVersion") && version.is_none() {
                    version = extract_version_from_blob(assembly, &attr);
                }
            }
        }

        if marker_tokens.is_empty() {
            return Detection::new_empty();
        }

        let count = marker_tokens.len();
        let mut evidence = vec![Evidence::Attribute(format!(
            "{count} ConfuserEx marker attributes"
        ))];

        if let Some(ref ver) = version {
            evidence.push(Evidence::Attribute(format!("ConfuserEx version: {ver}")));
        }

        let attr_tokens_for_cleanup: Vec<Token> = marker_tokens.clone();

        let findings = MarkerFindings {
            tokens: marker_tokens,
            typedef_tokens: typedef_tokens.clone(),
            version,
        };

        let mut detection = Detection::new_detected(
            evidence,
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        );

        // Register marker attribute tokens and typedef tokens for cleanup
        detection
            .cleanup_mut()
            .add_attributes(attr_tokens_for_cleanup);
        detection.cleanup_mut().add_types(typedef_tokens);

        detection
    }

    fn byte_transform(
        &self,
        _assembly: &mut WorkingAssembly,
        detection: &mut Detection,
    ) -> Option<Result<EventLog>> {
        let events = EventLog::new();

        let Some(findings) = detection.findings::<MarkerFindings>() else {
            return Some(Ok(events));
        };

        // Marker attribute removal is handled during assembly regeneration.
        // We log the intent here; the actual table row removal happens in
        // the cleanup phase when requires_regeneration() triggers a full rebuild.
        if !findings.tokens.is_empty() {
            let version_info = findings
                .version
                .as_deref()
                .map(|v| format!(" (version: {v})"))
                .unwrap_or_default();
            events.record(EventKind::ArtifactRemoved).message(format!(
                "Marked {} ConfuserEx attributes for removal{}",
                findings.tokens.len(),
                version_info,
            ));
        }

        Some(Ok(events))
    }

    fn requires_regeneration(&self) -> bool {
        true
    }
}

/// Attempts to extract a ConfuserEx version string from an attribute blob.
///
/// ConfuserEx embeds version information as a string argument in the
/// `ConfusedByAttribute` constructor. The blob format is:
/// `[prolog: 0x0001] [packed-len] [utf8-string]`.
fn extract_version_from_blob(assembly: &CilObject, row: &CustomAttributeRaw) -> Option<String> {
    let blob = assembly.blob()?;
    let data = blob.get(row.value as usize).ok()?;

    // Minimum: 2-byte prolog + 1-byte length + 1 char
    if data.len() < 4 {
        return None;
    }

    // Check prolog 0x0001
    if *data.first()? != 0x01 || *data.get(1)? != 0x00 {
        return None;
    }

    // Read packed string length
    let (str_len, offset) = read_packed_len(data.get(2..)?)?;
    let start = 2usize.checked_add(offset)?;
    let end = start.checked_add(str_len)?;
    if end > data.len() {
        return None;
    }

    let s = std::str::from_utf8(data.get(start..end)?).ok()?;
    if s.is_empty() {
        return None;
    }
    Some(s.to_string())
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{
            confuserex::marker::{ConfuserExMarker, MarkerFindings},
            Evidence, Technique,
        },
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("packers/confuserex/1.6.0/mkaring_normal.exe");

        let technique = ConfuserExMarker;
        let detection = technique.detect(&assembly);

        assert!(
            detection.is_detected(),
            "ConfuserExMarker should detect markers in mkaring_normal.exe"
        );
        assert!(
            !detection.evidence().is_empty(),
            "Detection should have evidence"
        );
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let technique = ConfuserExMarker;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "ConfuserExMarker should not detect markers in original.exe"
        );
    }

    #[test]
    fn test_detect_findings_have_tokens_and_typedefs() {
        let assembly = load_sample("packers/confuserex/1.6.0/mkaring_normal.exe");

        let technique = ConfuserExMarker;
        let detection = technique.detect(&assembly);

        assert!(detection.is_detected());

        let findings = detection
            .findings::<MarkerFindings>()
            .expect("Should have MarkerFindings");

        assert!(
            !findings.tokens.is_empty(),
            "Should have marker attribute tokens"
        );

        // ConfuserEx marker attributes are locally defined TypeDefs
        assert!(
            !findings.typedef_tokens.is_empty(),
            "Should have typedef tokens for locally-defined marker types"
        );

        // If a version was extracted, evidence should mention it
        if findings.version.is_some() {
            let has_version_evidence = detection.evidence().iter().any(|e| {
                if let Evidence::Attribute(s) = e {
                    s.contains("version")
                } else {
                    false
                }
            });
            assert!(
                has_version_evidence,
                "Evidence should mention the ConfuserEx version when version is extracted"
            );
        }
    }
}
