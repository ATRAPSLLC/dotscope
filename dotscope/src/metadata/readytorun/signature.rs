//! Type signatures as a ReadyToRun image encodes them: ECMA-335's, with the
//! runtime's own element types (`ELEMENT_TYPE_*_ZAPSIG`, `CorConstants.cs`).
//!
//! A signature nests as deep as its bytes allow, and every byte of a ReadyToRun
//! image is the image author's: a type is read into its elements in signature
//! order and spelled into one buffer, with explicit stacks, so neither the
//! reading nor the spelling recurses and both take time linear in the
//! signature.

use crate::{Error, Result};

/// `READYTORUN_METHOD_SIG_SlotInsteadOfToken`.
const METHOD_SIG_SLOT: u32 = 0x08;

/// `READYTORUN_METHOD_SIG_MemberRefToken` (and
/// `READYTORUN_FIELD_SIG_MemberRefToken`, the same bit).
const SIG_MEMBER_REF: u32 = 0x10;

/// `READYTORUN_METHOD_SIG_OwnerType` (and `READYTORUN_FIELD_SIG_OwnerType`).
const SIG_OWNER_TYPE: u32 = 0x40;

/// `READYTORUN_METHOD_SIG_UpdateContext`: the module index the method's
/// tokens are read in follows the flags.
const METHOD_SIG_UPDATE_CONTEXT: u32 = 0x80;

/// The metadata table of a `MethodDef` token.
pub(crate) const METHOD_DEF_TABLE: u32 = 0x06;

/// The metadata table of a `MemberRef` token.
pub(crate) const MEMBER_REF_TABLE: u32 = 0x0a;

/// The metadata table of a `Field` token.
const FIELD_TABLE: u32 = 0x04;

/// A metadata token, and the module whose metadata it is read in when that
/// is not the image's own (an index the signature states).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleToken {
    /// The token: its table in the high byte, its row below.
    pub token: u32,
    /// The module the token is read in, when the signature overrides it.
    pub module: Option<u32>,
}

impl ModuleToken {
    /// The token of row `rid` of `table`, read in `module`.
    pub(crate) fn new(table: u32, rid: u32, module: Option<u32>) -> Self {
        Self {
            token: (table << 24) | (rid & 0x00ff_ffff),
            module,
        }
    }
}

/// A type signature, as the runtime encodes it: ECMA-335's, with the
/// runtime's own element types (`ELEMENT_TYPE_*_ZAPSIG`). Held as its
/// elements in signature order, each followed by the elements of the types it
/// is built of, so neither reading nor spelling it recurses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureType(pub Vec<SignatureElement>);

/// One element of a [`SignatureType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureElement {
    /// A primitive, by its `ELEMENT_TYPE` (`VOID` to `STRING`, `TYPEDBYREF`,
    /// `I`, `U`, `OBJECT`).
    Primitive(u8),
    /// A class or value type, by its `TypeDefOrRef` coded index; with the
    /// count of type arguments that follow when it is a generic
    /// instantiation.
    Named {
        /// The `TypeDefOrRef` coded index: the row above two tag bits.
        coded: u32,
        /// The module its token is read in, when not the image's own.
        module: Option<u32>,
        /// The type arguments of a `GENERICINST`, which follow it.
        arguments: Option<u32>,
    },
    /// A pointer to the type that follows.
    Pointer,
    /// A managed reference to the type that follows.
    ByRef,
    /// A one-dimensional zero-based array of the type that follows.
    SzArray,
    /// An array of the type that follows, of this rank.
    Array(u32),
    /// The type that follows, modified (`CMOD_REQD`, `CMOD_OPT`), pinned, or
    /// as a native value type: spelled as that type.
    Wrapped,
    /// A type's generic parameter, by number.
    TypeVariable(u32),
    /// A method's generic parameter, by number.
    MethodVariable(u32),
    /// A generic parameter, by its `GenericParam` row.
    GenericParameter(u32),
    /// `System.__Canon`, the shared instantiation's stand-in.
    Canon,
    /// A function pointer: its return type and this many parameters follow.
    FunctionPointer(u32),
}

impl SignatureElement {
    /// The count of types that follow this element and belong to it.
    fn children(self) -> u32 {
        match self {
            Self::Named { arguments, .. } => arguments.unwrap_or(0),
            Self::Pointer | Self::ByRef | Self::SzArray | Self::Array(_) | Self::Wrapped => 1,
            Self::FunctionPointer(parameters) => parameters.saturating_add(1),
            Self::Primitive(_)
            | Self::TypeVariable(_)
            | Self::MethodVariable(_)
            | Self::GenericParameter(_)
            | Self::Canon => 0,
        }
    }
}

impl SignatureType {
    /// Reads the type at the reader's position, its tokens read in `module`.
    pub(crate) fn read(reader: &mut SignatureReader<'_>, module: Option<u32>) -> Result<Self> {
        let mut elements = Vec::new();
        let mut frames = vec![Frame {
            types: 1,
            module,
            array: None,
        }];
        while let Some(frame) = frames.last_mut() {
            if frame.types == 0 {
                // An array's shape follows its element type.
                if let Some(at) = frame.array {
                    let rank = reader.unsigned()?;
                    for _ in 0..reader.unsigned()? {
                        reader.unsigned()?;
                    }
                    for _ in 0..reader.unsigned()? {
                        reader.unsigned()?;
                    }
                    if let Some(element) = elements.get_mut(at) {
                        *element = SignatureElement::Array(rank);
                    }
                }
                frames.pop();
                continue;
            }
            frame.types = frame.types.saturating_sub(1);
            let outer = frame.module;
            // `ReadElementType` masks the high bit.
            let element = reader.byte()? & 0x7f;
            let read = match element {
                // MODULE_ZAPSIG: the type that follows is read in another
                // module.
                0x3f => {
                    let module = Some(reader.unsigned()?);
                    frames.push(Frame {
                        types: 1,
                        module,
                        array: None,
                    });
                    continue;
                }
                // SENTINEL: the varargs after it are counted with the
                // parameters before it; the marker is no type.
                0x41 => {
                    frame.types = frame.types.saturating_add(1);
                    continue;
                }
                0x01..=0x0e | 0x16 | 0x18 | 0x19 | 0x1c => SignatureElement::Primitive(element),
                0x0f => SignatureElement::Pointer,
                0x10 => SignatureElement::ByRef,
                0x11 | 0x12 => SignatureElement::Named {
                    coded: reader.unsigned()?,
                    module: outer,
                    arguments: None,
                },
                0x13 => SignatureElement::TypeVariable(reader.unsigned()?),
                // ARRAY: the element type, then the shape, read when the
                // element's frame ends.
                0x14 => {
                    frames.push(Frame {
                        types: 1,
                        module: outer,
                        array: Some(elements.len()),
                    });
                    elements.push(SignatureElement::Array(0));
                    continue;
                }
                // GENERICINST: the generic type, read in another module when
                // a MODULE_ZAPSIG precedes it, then its arguments, read in
                // this one.
                0x15 => {
                    let mut generic = reader.byte()? & 0x7f;
                    let mut module = outer;
                    if generic == 0x3f {
                        module = Some(reader.unsigned()?);
                        generic = reader.byte()? & 0x7f;
                    }
                    if !matches!(generic, 0x11 | 0x12) {
                        return Err(reader.malformed("a generic instantiation of no named type"));
                    }
                    let coded = reader.unsigned()?;
                    SignatureElement::Named {
                        coded,
                        module,
                        arguments: Some(reader.unsigned()?),
                    }
                }
                // FNPTR: a method signature's convention, generic parameter
                // count, and parameter count; its types follow.
                0x1b => {
                    let convention = reader.unsigned()?;
                    if convention & 0x10 != 0 {
                        reader.unsigned()?;
                    }
                    SignatureElement::FunctionPointer(reader.unsigned()?)
                }
                0x1d => SignatureElement::SzArray,
                0x1e => SignatureElement::MethodVariable(reader.unsigned()?),
                // CMOD_REQD, CMOD_OPT: the modifier's token, then the type.
                0x1f | 0x20 => {
                    reader.unsigned()?;
                    SignatureElement::Wrapped
                }
                // PINNED, NATIVE_VALUETYPE_ZAPSIG.
                0x45 | 0x3d => SignatureElement::Wrapped,
                // VAR_ZAPSIG.
                0x3b => SignatureElement::GenericParameter(reader.unsigned()?),
                // CANON_ZAPSIG.
                0x3e => SignatureElement::Canon,
                other => {
                    return Err(reader.malformed(&format!("element type {other:#04x}")));
                }
            };
            let children = read.children();
            elements.push(read);
            if children > 0 {
                frames.push(Frame {
                    types: children,
                    module: outer,
                    array: None,
                });
            }
        }
        Ok(Self(elements))
    }

    /// Spells the type, a named type by `name` given its `TypeDefOrRef` coded
    /// index; `None` when `name` names one of its types nothing, or a token
    /// is read in another module, whose metadata this image does not hold.
    ///
    /// Written into one buffer in signature order, each element's closing
    /// text held until the types it is built of are written, so the cost is
    /// the spelling's length however deep the type nests.
    pub fn spell(&self, name: impl Fn(u32) -> Option<String>) -> Option<String> {
        let mut out = String::new();
        // The elements still open: the types each has left to write, and
        // the text between and after them.
        let mut open: Vec<Opened> = Vec::new();
        for &element in &self.0 {
            if let Some(parent) = open.last_mut() {
                out.push_str(parent.before_next());
            }
            match element {
                SignatureElement::Primitive(primitive) => out.push_str(primitive_name(primitive)?),
                SignatureElement::Named {
                    coded,
                    module,
                    arguments,
                } => {
                    if module.is_some() {
                        return None;
                    }
                    out.push_str(&name(coded)?);
                    if arguments.is_some_and(|count| count > 0) {
                        out.push('<');
                    }
                }
                SignatureElement::FunctionPointer(_) => out.push_str("method "),
                SignatureElement::TypeVariable(number) => out.push_str(&format!("!{number}")),
                SignatureElement::MethodVariable(number) => out.push_str(&format!("!!{number}")),
                SignatureElement::GenericParameter(row) => {
                    out.push_str(&format!("!GenericParam{row}"));
                }
                SignatureElement::Canon => out.push_str("System.__Canon"),
                SignatureElement::Pointer
                | SignatureElement::ByRef
                | SignatureElement::SzArray
                | SignatureElement::Array(_)
                | SignatureElement::Wrapped => {}
            }
            let children = element.children();
            if children > 0 {
                open.push(Opened {
                    element,
                    left: children,
                    written: 0,
                });
                continue;
            }
            // A complete type closes every element it was the last of.
            while open.last().is_some_and(|opened| opened.left == 0) {
                let closed = open.pop()?;
                out.push_str(&closed.close());
            }
        }
        open.is_empty().then_some(out)
    }
}

/// An element of a [`SignatureType`] being spelled, whose types are not all
/// written yet.
struct Opened {
    /// The element.
    element: SignatureElement,
    /// Its types still to write.
    left: u32,
    /// Its types written or being written.
    written: u32,
}

impl Opened {
    /// The text before the element's next type, which it counts as begun.
    fn before_next(&mut self) -> &'static str {
        self.left = self.left.saturating_sub(1);
        self.written = self.written.saturating_add(1);
        match (self.element, self.written) {
            (SignatureElement::Named { .. }, 2..) => ", ",
            // A function pointer's return type comes first.
            (SignatureElement::FunctionPointer(_), 2) => " *(",
            (SignatureElement::FunctionPointer(_), 3..) => ", ",
            _ => "",
        }
    }

    /// The text after the element's last type.
    fn close(&self) -> String {
        match self.element {
            SignatureElement::Named { .. } => ">".to_owned(),
            SignatureElement::Pointer => "*".to_owned(),
            SignatureElement::ByRef => "&".to_owned(),
            SignatureElement::SzArray => "[]".to_owned(),
            SignatureElement::Array(rank) => {
                format!("[{}]", ",".repeat((rank as usize).saturating_sub(1)))
            }
            SignatureElement::FunctionPointer(0) => " *()".to_owned(),
            SignatureElement::FunctionPointer(_) => ")".to_owned(),
            _ => String::new(),
        }
    }
}

/// Types still to read of one element of a [`SignatureType`].
struct Frame {
    /// How many.
    types: u32,
    /// The module their tokens are read in, when not the image's own.
    module: Option<u32>,
    /// The array element whose shape follows them, by its index.
    array: Option<usize>,
}

/// The name of primitive `ELEMENT_TYPE` `element`.
fn primitive_name(element: u8) -> Option<&'static str> {
    Some(match element {
        0x01 => "System.Void",
        0x02 => "System.Boolean",
        0x03 => "System.Char",
        0x04 => "System.SByte",
        0x05 => "System.Byte",
        0x06 => "System.Int16",
        0x07 => "System.UInt16",
        0x08 => "System.Int32",
        0x09 => "System.UInt32",
        0x0a => "System.Int64",
        0x0b => "System.UInt64",
        0x0c => "System.Single",
        0x0d => "System.Double",
        0x0e => "System.String",
        0x16 => "System.TypedReference",
        0x18 => "System.IntPtr",
        0x19 => "System.UIntPtr",
        0x1c => "System.Object",
        _ => return None,
    })
}

/// A reader of a signature's compressed numbers and element types.
pub(crate) struct SignatureReader<'a> {
    /// The signature, and whatever follows it in the image.
    pub(crate) bytes: &'a [u8],
    /// The position of the next byte.
    pub(crate) at: usize,
}

impl SignatureReader<'_> {
    /// The next byte.
    pub(crate) fn byte(&mut self) -> Result<u8> {
        let byte = *self
            .bytes
            .get(self.at)
            .ok_or_else(|| self.malformed("the signature ends early"))?;
        self.at = self.at.saturating_add(1);
        Ok(byte)
    }

    /// The next ECMA-335 compressed unsigned number: one byte below `0x80`,
    /// two under `10` high bits, four under `110`.
    pub(crate) fn unsigned(&mut self) -> Result<u32> {
        let first = u32::from(self.byte()?);
        if first & 0x80 == 0 {
            return Ok(first);
        }
        if first & 0xc0 == 0x80 {
            return Ok(((first & 0x3f) << 8) | u32::from(self.byte()?));
        }
        let mut value = first & 0x1f;
        for _ in 0..3 {
            value = (value << 8) | u32::from(self.byte()?);
        }
        Ok(value)
    }

    /// Reads a method signature (`ReadyToRunMethodSigFlags`) as far as its
    /// token: the flags, the module the tokens are read in, the owning type.
    /// `None` for a method named by a vtable slot rather than a token.
    pub(crate) fn method(&mut self, module: Option<u32>) -> Result<Option<ModuleToken>> {
        let flags = self.unsigned()?;
        let module = if flags & METHOD_SIG_UPDATE_CONTEXT != 0 {
            Some(self.unsigned()?)
        } else {
            module
        };
        if flags & SIG_OWNER_TYPE != 0 {
            SignatureType::read(self, module)?;
        }
        if flags & METHOD_SIG_SLOT != 0 {
            return Ok(None);
        }
        let table = if flags & SIG_MEMBER_REF != 0 {
            MEMBER_REF_TABLE
        } else {
            METHOD_DEF_TABLE
        };
        let rid = self.unsigned()?;
        Ok(Some(ModuleToken::new(table, rid, module)))
    }

    /// Reads a field signature (`ReadyToRunFieldSigFlags`): the flags, the
    /// owning type, the token.
    pub(crate) fn field(&mut self, module: Option<u32>) -> Result<ModuleToken> {
        let flags = self.unsigned()?;
        if flags & SIG_OWNER_TYPE != 0 {
            SignatureType::read(self, module)?;
        }
        let table = if flags & SIG_MEMBER_REF != 0 {
            MEMBER_REF_TABLE
        } else {
            FIELD_TABLE
        };
        let rid = self.unsigned()?;
        Ok(ModuleToken::new(table, rid, module))
    }

    /// The error of a signature that does not read, at the current position.
    pub(crate) fn malformed(&self, what: &str) -> Error {
        malformed_error!("ReadyToRun fixup signature at byte {}: {what}", self.at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A type signature spells as its type**, generic arguments, the
    /// shared stand-in, arrays and function pointers included; a token in
    /// another module's metadata, or one the image does not name, spells
    /// nothing.
    #[test]
    fn a_type_signature_spells_as_its_type() {
        let name = |coded: u32| match coded {
            0x6d => Some("System.Collections.Generic.List`1".to_owned()),
            0x08 => Some("System.Text.StringBuilder".to_owned()),
            _ => None,
        };
        let spell = |bytes: &[u8]| {
            let mut reader = SignatureReader { bytes, at: 0 };
            let ty = SignatureType::read(&mut reader, None).expect("reads");
            assert_eq!(reader.at, bytes.len(), "reads the whole type");
            ty.spell(name)
        };
        assert_eq!(
            spell(&[0x15, 0x12, 0x6d, 0x02, 0x3e, 0x1d, 0x08]).as_deref(),
            Some("System.Collections.Generic.List`1<System.__Canon, System.Int32[]>")
        );
        // ARRAY: element, rank 2, one size, no lower bounds.
        assert_eq!(
            spell(&[0x14, 0x12, 0x08, 0x02, 0x01, 0x04, 0x00]).as_deref(),
            Some("System.Text.StringBuilder[,]")
        );
        // An array of arrays reads each shape after its own element.
        assert_eq!(
            spell(&[0x14, 0x14, 0x08, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00]).as_deref(),
            Some("System.Int32[,,][]")
        );
        // FNPTR: default convention, two parameters (varargs after a
        // sentinel), returning void.
        assert_eq!(
            spell(&[0x1b, 0x05, 0x02, 0x01, 0x0f, 0x08, 0x41, 0x0e]).as_deref(),
            Some("method System.Void *(System.Int32*, System.String)")
        );
        assert_eq!(
            spell(&[0x1b, 0x00, 0x00, 0x1c]).as_deref(),
            Some("method System.Object *()")
        );
        // CMOD_REQD and PINNED spell as the type they wrap.
        assert_eq!(
            spell(&[0x1f, 0x09, 0x45, 0x10, 0x0a]).as_deref(),
            Some("System.Int64&")
        );
        assert_eq!(
            spell(&[0x3f, 0x01, 0x12, 0x08]),
            None,
            "a token of module 1"
        );
        assert_eq!(
            spell(&[0x12, 0x0c]),
            None,
            "a token the image does not name"
        );
        let mut reader = SignatureReader {
            bytes: &[0x15, 0x08],
            at: 0,
        };
        assert!(
            SignatureType::read(&mut reader, None).is_err(),
            "a GENERICINST of a primitive"
        );
    }

    /// **A deep type reads and spells without recursing, in time linear in
    /// its length.** A hostile signature nests as deep as its bytes allow; a
    /// recursive reader would overflow the stack and a spelling that copied
    /// each level's text would be quadratic.
    #[test]
    fn a_deep_type_reads_and_spells_without_recursing() {
        let depth = 1_000_000;
        let mut bytes = vec![0x1d; depth];
        bytes.push(0x08);
        let mut reader = SignatureReader {
            bytes: &bytes,
            at: 0,
        };
        let ty = SignatureType::read(&mut reader, None).expect("reads");
        let spelled = ty.spell(|_| None).expect("spells");
        assert_eq!(spelled.len(), "System.Int32".len() + 2 * depth);
        let mut generic = Vec::new();
        for _ in 0..depth {
            generic.extend([0x15, 0x12, 0x6d, 0x01]);
        }
        generic.push(0x3e);
        let mut reader = SignatureReader {
            bytes: &generic,
            at: 0,
        };
        let ty = SignatureType::read(&mut reader, None).expect("reads");
        assert!(ty
            .spell(|_| Some("L".to_owned()))
            .is_some_and(|text| text.ends_with('>')));
    }
}
