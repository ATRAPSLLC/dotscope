//! A reader of BAML, the compiled XAML a WPF assembly embeds.
//!
//! The markup compiler turns each XAML page into a BAML stream and stores it
//! in the assembly's `<assembly>.g.resources` resource set, an entry
//! `<page>.baml` ([`ResourceType::Stream`](crate::metadata::resources::ResourceType::Stream)).
//! [`read_baml`] reads one stream into its element tree: each element's type,
//! the properties its markup sets with their values as the markup states
//! them, its children, and the connection id the code-behind's
//! `IComponentConnector.Connect` wires its name and events by.
//!
//! # Layout
//!
//! The stream starts with a header: a `u32` 12, then `MSBAML` in UTF-16LE,
//! then the reader, updater and writer versions, each a `u16` major and a
//! `u16` minor (0.96 for every version the markup compiler writes). Then come
//! records, each a type byte followed either by a payload of a size its type
//! fixes or, for a variable record, a 7-bit encoded length that counts itself
//! and the payload. Types, properties and strings are named by 16-bit ids: a
//! negative id is a built-in type or property ([`known`], `-id` its index in
//! WPF's `KnownElements` and `KnownProperties`), and any other the id an
//! earlier `TypeInfo`, `AttributeInfo` or `StringInfo` record declared.
//!
//! The layouts are WPF's own (`PresentationFramework/System/Windows/Markup/
//! BamlRecords.cs`, github.com/dotnet/wpf); a payload size the class declares
//! apart from what it reads (`DocumentStart`, `ContentProperty`,
//! `DefAttributeKeyType`) is the size it reads. Every read is bounded by the
//! stream, the tree is built without recursion, and a record of a type no
//! layout states ends the read with what was read before it.

pub mod known;

use std::collections::HashMap;

use self::known::{KNOWN_PROPERTIES, KNOWN_TYPES};
use crate::{file::parser::Parser, Result};

/// The header's signature, `MSBAML`, as the 12 bytes of its UTF-16LE text.
const SIGNATURE: &str = "MSBAML";

/// The record types, by their type byte (`BamlRecordType`).
mod record {
    pub const DOCUMENT_START: u8 = 1;
    pub const DOCUMENT_END: u8 = 2;
    pub const ELEMENT_START: u8 = 3;
    pub const ELEMENT_END: u8 = 4;
    pub const PROPERTY: u8 = 5;
    pub const PROPERTY_CUSTOM: u8 = 6;
    pub const PROPERTY_COMPLEX_START: u8 = 7;
    pub const PROPERTY_COMPLEX_END: u8 = 8;
    pub const PROPERTY_ARRAY_START: u8 = 9;
    pub const PROPERTY_ARRAY_END: u8 = 10;
    pub const PROPERTY_ILIST_START: u8 = 11;
    pub const PROPERTY_ILIST_END: u8 = 12;
    pub const PROPERTY_IDICTIONARY_START: u8 = 13;
    pub const PROPERTY_IDICTIONARY_END: u8 = 14;
    pub const LITERAL_CONTENT: u8 = 15;
    pub const TEXT: u8 = 16;
    pub const TEXT_WITH_CONVERTER: u8 = 17;
    pub const ROUTED_EVENT: u8 = 18;
    pub const XMLNS_PROPERTY: u8 = 20;
    pub const DEF_ATTRIBUTE: u8 = 25;
    pub const PI_MAPPING: u8 = 27;
    pub const ASSEMBLY_INFO: u8 = 28;
    pub const TYPE_INFO: u8 = 29;
    pub const TYPE_SERIALIZER_INFO: u8 = 30;
    pub const ATTRIBUTE_INFO: u8 = 31;
    pub const STRING_INFO: u8 = 32;
    pub const PROPERTY_STRING_REFERENCE: u8 = 33;
    pub const PROPERTY_TYPE_REFERENCE: u8 = 34;
    pub const PROPERTY_WITH_EXTENSION: u8 = 35;
    pub const PROPERTY_WITH_CONVERTER: u8 = 36;
    pub const DEFERABLE_CONTENT_START: u8 = 37;
    pub const DEF_ATTRIBUTE_KEY_STRING: u8 = 38;
    pub const DEF_ATTRIBUTE_KEY_TYPE: u8 = 39;
    pub const KEY_ELEMENT_START: u8 = 40;
    pub const KEY_ELEMENT_END: u8 = 41;
    pub const CONSTRUCTOR_PARAMETERS_START: u8 = 42;
    pub const CONSTRUCTOR_PARAMETERS_END: u8 = 43;
    pub const CONSTRUCTOR_PARAMETER_TYPE: u8 = 44;
    pub const CONNECTION_ID: u8 = 45;
    pub const CONTENT_PROPERTY: u8 = 46;
    pub const STATIC_RESOURCE_START: u8 = 48;
    pub const STATIC_RESOURCE_END: u8 = 49;
    pub const STATIC_RESOURCE_ID: u8 = 50;
    pub const TEXT_WITH_ID: u8 = 51;
    pub const PRESENTATION_OPTIONS_ATTRIBUTE: u8 = 52;
    pub const LINE_NUMBER_AND_POSITION: u8 = 53;
    pub const LINE_POSITION: u8 = 54;
    pub const OPTIMIZED_STATIC_RESOURCE: u8 = 55;
    pub const PROPERTY_WITH_STATIC_RESOURCE_ID: u8 = 56;
}

/// The payload size of a record whose type fixes it, or `None` for a variable
/// record (or a type no layout states).
fn fixed_size(kind: u8) -> Option<usize> {
    Some(match kind {
        record::DOCUMENT_START => 6,
        record::ELEMENT_START | record::STATIC_RESOURCE_START => 3,
        record::DOCUMENT_END
        | record::ELEMENT_END
        | record::PROPERTY_COMPLEX_END
        | record::PROPERTY_ARRAY_END
        | record::PROPERTY_ILIST_END
        | record::PROPERTY_IDICTIONARY_END
        | record::KEY_ELEMENT_END
        | record::CONSTRUCTOR_PARAMETERS_START
        | record::CONSTRUCTOR_PARAMETERS_END
        | record::STATIC_RESOURCE_END => 0,
        record::PROPERTY_COMPLEX_START
        | record::PROPERTY_ARRAY_START
        | record::PROPERTY_ILIST_START
        | record::PROPERTY_IDICTIONARY_START
        | record::CONSTRUCTOR_PARAMETER_TYPE
        | record::CONTENT_PROPERTY
        | record::STATIC_RESOURCE_ID => 2,
        record::PROPERTY_STRING_REFERENCE
        | record::PROPERTY_TYPE_REFERENCE
        | record::DEFERABLE_CONTENT_START
        | record::CONNECTION_ID
        | record::LINE_POSITION
        | record::PROPERTY_WITH_STATIC_RESOURCE_ID => 4,
        record::PROPERTY_WITH_EXTENSION => 6,
        record::DEF_ATTRIBUTE_KEY_TYPE | record::KEY_ELEMENT_START => 9,
        record::LINE_NUMBER_AND_POSITION => 8,
        record::OPTIMIZED_STATIC_RESOURCE => 3,
        _ => return None,
    })
}

/// Whether a record of type `kind` is a variable record, a 7-bit length after
/// its type byte.
fn is_variable(kind: u8) -> bool {
    matches!(
        kind,
        record::PROPERTY
            | record::PROPERTY_CUSTOM
            | record::LITERAL_CONTENT
            | record::TEXT
            | record::TEXT_WITH_CONVERTER
            | record::ROUTED_EVENT
            | record::XMLNS_PROPERTY
            | record::DEF_ATTRIBUTE
            | record::PI_MAPPING
            | record::ASSEMBLY_INFO
            | record::TYPE_INFO
            | record::TYPE_SERIALIZER_INFO
            | record::ATTRIBUTE_INFO
            | record::STRING_INFO
            | record::PROPERTY_WITH_CONVERTER
            | record::DEF_ATTRIBUTE_KEY_STRING
            | record::TEXT_WITH_ID
            | record::PRESENTATION_OPTIONS_ATTRIBUTE
    )
}

/// What a property's markup states it as (`BamlAttributeUsage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BamlAttributeUsage {
    /// An ordinary property.
    Default,
    /// `xml:lang`.
    XmlLang,
    /// `xml:space`.
    XmlSpace,
    /// The element's runtime name: `x:Name`, or the property a type names as
    /// its `RuntimeNameProperty`.
    RuntimeName,
}

/// A value as a property's markup states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BamlValue {
    /// Text the property's type converter turns into its value at run time
    /// (`Width="320"`), with that converter's type when the record names one.
    Text {
        /// The text.
        text: String,
        /// The type converter the record names.
        converter: Option<String>,
    },
    /// A value the markup compiler serialized in binary
    /// (`PropertyCustom`): the serializer's type and its bytes.
    Custom {
        /// The serializer's type.
        serializer: Option<String>,
        /// The serialized bytes.
        bytes: Vec<u8>,
    },
    /// A markup extension with one argument (`{StaticResource key}`,
    /// `{x:Static Member}`, `{x:Type T}`): the extension's type and the id of
    /// its argument, as the record states them.
    Extension {
        /// The extension's type.
        extension: Option<String>,
        /// The id its argument is named by.
        value_id: i16,
    },
    /// A type (`{x:Type T}` folded to a type reference).
    Type(Option<String>),
    /// A string of the stream's string table.
    String(Option<String>),
    /// A static resource of the stream, by its id.
    StaticResource(i16),
}

/// A property an element's markup sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BamlProperty {
    /// The full name of the type that declares the property (an attached
    /// property's owner: `System.Windows.Controls.Canvas` for `Canvas.Left`).
    pub owner: Option<String>,
    /// The property's name.
    pub name: Option<String>,
    /// What the markup states the property as.
    pub usage: BamlAttributeUsage,
    /// Its value.
    pub value: BamlValue,
}

/// A property element of an element: a property whose value is markup of its
/// own (`<Grid.ColumnDefinitions>`), with the elements its value holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BamlPropertyElement {
    /// The full name of the type that declares the property.
    pub owner: Option<String>,
    /// The property's name.
    pub name: Option<String>,
    /// The elements its value holds, in order, by their index in
    /// [`BamlDocument::elements`].
    pub elements: Vec<usize>,
}

/// One element of a BAML tree. The tree is flat: an element names its parent
/// and its children by their index in [`BamlDocument::elements`], so no
/// nesting the stream states recurses to read, walk or drop.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BamlElement {
    /// The index of the element it is a child or a property value of; `None`
    /// for the root.
    pub parent: Option<usize>,
    /// The element's type: a built-in type's full name, or the name its
    /// `TypeInfo` record declares (`Visus.Fixture.LoginWindow`). `None` for an
    /// id no record declares.
    pub type_name: Option<String>,
    /// The assembly the type's `TypeInfo` names, for a declared type.
    pub assembly: Option<String>,
    /// The connection id the code-behind wires the element by
    /// (`IComponentConnector.Connect`): set on every element the markup names
    /// or wires an event of.
    pub connection_id: Option<i32>,
    /// The properties its markup sets, in order.
    pub properties: Vec<BamlProperty>,
    /// Its property elements, in order.
    pub property_elements: Vec<BamlPropertyElement>,
    /// Its child elements, in order, by index.
    pub children: Vec<usize>,
    /// The text content it holds (`<TextBlock>Ready</TextBlock>`).
    pub text: Vec<String>,
}

impl BamlElement {
    /// Returns the element's runtime name (`x:Name`): the value of its
    /// property whose usage is [`BamlAttributeUsage::RuntimeName`].
    #[must_use]
    pub fn runtime_name(&self) -> Option<&str> {
        self.properties
            .iter()
            .find(|property| property.usage == BamlAttributeUsage::RuntimeName)
            .and_then(|property| match &property.value {
                BamlValue::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
    }

    /// Returns the value text of the property `name` declared by the type
    /// whose full name ends in `owner` (`"Canvas"` for `Canvas.Left`), or by
    /// any type when `owner` is `None`.
    #[must_use]
    pub fn property_text(&self, owner: Option<&str>, name: &str) -> Option<&str> {
        self.properties
            .iter()
            .filter(|property| property.name.as_deref() == Some(name))
            .filter(|property| {
                owner.is_none_or(|wanted| {
                    property
                        .owner
                        .as_deref()
                        .is_some_and(|full| full.rsplit('.').next() == Some(wanted))
                })
            })
            .find_map(|property| match &property.value {
                BamlValue::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
    }
}

/// One BAML stream: its versions, the assemblies it names and its root
/// element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BamlDocument {
    /// The writer version, its major and minor.
    pub writer_version: (u16, u16),
    /// The assemblies its `AssemblyInfo` records name, by id.
    pub assemblies: Vec<(i16, String)>,
    /// The XML namespaces its markup declares: each prefix and namespace.
    pub namespaces: Vec<(String, String)>,
    /// Every element, the root first, each before its children.
    pub elements: Vec<BamlElement>,
    /// Whether the read ended before the stream's `DocumentEnd`: a record of
    /// a type no layout states, or a record past the data.
    pub truncated: bool,
}

/// The declarations a stream's records make, which later ids name.
#[derive(Default)]
struct Declarations {
    /// Assemblies by id.
    assemblies: HashMap<i16, String>,
    /// Types by id: full name and assembly id.
    types: HashMap<i16, (String, i16)>,
    /// Attributes by id: owner type id, name and usage.
    attributes: HashMap<i16, (i16, String, BamlAttributeUsage)>,
    /// Strings by id.
    strings: HashMap<i16, String>,
}

impl Declarations {
    /// The full name of the type `id` names.
    fn type_name(&self, id: i16) -> Option<String> {
        if id < 0 {
            let index = usize::from(id.unsigned_abs());
            return KNOWN_TYPES.get(index).copied().flatten().map(str::to_owned);
        }
        self.types.get(&id).map(|(name, _)| name.clone())
    }

    /// The assembly of the type `id` names, for a declared type.
    fn type_assembly(&self, id: i16) -> Option<String> {
        let (_, assembly) = self.types.get(&id)?;
        self.assemblies.get(assembly).cloned()
    }

    /// The owner's full name, the name and the usage of the attribute `id`.
    fn attribute(&self, id: i16) -> (Option<String>, Option<String>, BamlAttributeUsage) {
        if id < 0 {
            let index = usize::from(id.unsigned_abs());
            return match KNOWN_PROPERTIES.get(index).copied().flatten() {
                Some((owner, name)) => (
                    KNOWN_TYPES
                        .get(usize::from(owner))
                        .copied()
                        .flatten()
                        .map(str::to_owned),
                    Some(name.to_owned()),
                    BamlAttributeUsage::Default,
                ),
                None => (None, None, BamlAttributeUsage::Default),
            };
        }
        match self.attributes.get(&id) {
            Some((owner, name, usage)) => (self.type_name(*owner), Some(name.clone()), *usage),
            None => (None, None, BamlAttributeUsage::Default),
        }
    }
}

/// What a frame of the read is in: an element, or a property element of the
/// element below it.
enum Frame {
    /// An element, by its index.
    Element(usize),
    /// A property element of the element below it: its owner and name, and
    /// the elements read into it so far.
    Property(BamlPropertyElement),
}

impl BamlDocument {
    /// Returns the root element, when the stream holds one.
    #[must_use]
    pub fn root(&self) -> Option<&BamlElement> {
        self.elements.first()
    }

    /// Returns the children of `element`, in order.
    pub fn children<'d>(
        &'d self,
        element: &'d BamlElement,
    ) -> impl Iterator<Item = &'d BamlElement> + 'd {
        element
            .children
            .iter()
            .filter_map(move |&index| self.elements.get(index))
    }
}

/// Reads the header of the BAML stream `data` and returns the writer version
/// and the offset of its first record.
fn read_header(parser: &mut Parser<'_>) -> Result<(u16, u16)> {
    let length = parser.read_le::<u32>()?;
    let bytes = parser.read_bytes(usize::try_from(length).unwrap_or(usize::MAX))?;
    let (units, _) = bytes.as_chunks::<2>();
    let units: Vec<u16> = units.iter().copied().map(u16::from_le_bytes).collect();
    if String::from_utf16(&units).ok().as_deref() != Some(SIGNATURE) {
        return Err(malformed_error!("BAML stream does not start with MSBAML"));
    }
    let mut writer = (0, 0);
    for _ in 0..3 {
        writer = (parser.read_le::<u16>()?, parser.read_le::<u16>()?);
    }
    Ok(writer)
}

/// Reads the BAML stream `data` into its element tree.
///
/// # Errors
///
/// A malformed-input error when the stream does not start with its header. A
/// record the read cannot take ends it with the elements read before it,
/// [`BamlDocument::truncated`] set.
pub fn read_baml(data: &[u8]) -> Result<BamlDocument> {
    let mut parser = Parser::new(data);
    let writer_version = read_header(&mut parser)?;
    let mut declarations = Declarations::default();
    let mut namespaces = Vec::new();
    let mut stack: Vec<Frame> = Vec::new();
    let mut elements: Vec<BamlElement> = Vec::new();
    let mut ended = false;
    while parser.has_more_data() {
        let Ok(kind) = parser.read_le::<u8>() else {
            break;
        };
        let (start, end) = if is_variable(kind) {
            let at = parser.pos();
            let Ok(length) = parser.read_7bit_encoded_int() else {
                break;
            };
            match at.checked_add(length as usize) {
                Some(end) if end >= parser.pos() && end <= data.len() => (parser.pos(), end),
                _ => break,
            }
        } else if let Some(size) = fixed_size(kind) {
            match parser.pos().checked_add(size) {
                Some(end) if end <= data.len() => (parser.pos(), end),
                _ => break,
            }
        } else {
            break;
        };
        let Some(payload) = data.get(start..end) else {
            break;
        };
        let mut body = Parser::new(payload);
        if read_record(
            kind,
            &mut body,
            &mut declarations,
            &mut namespaces,
            &mut stack,
            &mut elements,
        )
        .is_err()
        {
            break;
        }
        if kind == record::DOCUMENT_END {
            ended = true;
            break;
        }
        if parser.seek(end).is_err() {
            break;
        }
    }
    // A stream that ends inside its elements still states them: each open
    // frame closes into the one below it.
    while let Some(frame) = stack.pop() {
        close(frame, &mut stack, &mut elements);
    }
    let mut assemblies: Vec<(i16, String)> = declarations.assemblies.into_iter().collect();
    assemblies.sort();
    Ok(BamlDocument {
        writer_version,
        assemblies,
        namespaces,
        elements,
        truncated: !ended,
    })
}

/// Closes the frame `frame`: a property element is attached to the element
/// below it on `stack` (an element was attached as it opened).
fn close(frame: Frame, stack: &mut [Frame], elements: &mut [BamlElement]) {
    if let (Frame::Property(property), Some(Frame::Element(parent))) = (frame, stack.last()) {
        if let Some(parent) = elements.get_mut(*parent) {
            parent.property_elements.push(property);
        }
    }
}

/// Opens an element at the top of `stack`: appends it to `elements`, a child
/// of the element below it or a value of the property element below it.
fn open(mut element: BamlElement, stack: &mut Vec<Frame>, elements: &mut Vec<BamlElement>) {
    let index = elements.len();
    match stack.last_mut() {
        Some(Frame::Element(parent)) => {
            element.parent = Some(*parent);
            if let Some(parent) = elements.get_mut(*parent) {
                parent.children.push(index);
            }
        }
        Some(Frame::Property(property)) => {
            property.elements.push(index);
            element.parent = stack.iter().rev().find_map(|frame| match frame {
                Frame::Element(at) => Some(*at),
                Frame::Property(_) => None,
            });
        }
        // A second root is no element of the tree's: the stream has one.
        None if index > 0 => return,
        None => {}
    }
    elements.push(element);
    stack.push(Frame::Element(index));
}

/// The element at index `at` of `elements`: the one a record's values go to.
fn element_at(elements: &mut [BamlElement], at: Option<usize>) -> Option<&mut BamlElement> {
    at.and_then(|index| elements.get_mut(index))
}

/// Reads the payload of one record of type `kind` from `body` into the tree.
fn read_record(
    kind: u8,
    body: &mut Parser<'_>,
    declarations: &mut Declarations,
    namespaces: &mut Vec<(String, String)>,
    stack: &mut Vec<Frame>,
    elements: &mut Vec<BamlElement>,
) -> Result<()> {
    let at = match stack.last() {
        Some(Frame::Element(index)) => Some(*index),
        _ => None,
    };
    match kind {
        record::ASSEMBLY_INFO => {
            let id = body.read_le::<i16>()?;
            let name = body.read_prefixed_string_utf8()?;
            declarations.assemblies.insert(id, name);
        }
        record::TYPE_INFO | record::TYPE_SERIALIZER_INFO => {
            let id = body.read_le::<i16>()?;
            // The low 12 bits name the assembly; the high 4 are flags.
            let assembly = body.read_le::<i16>()? & 0x0FFF;
            let name = body.read_prefixed_string_utf8()?;
            declarations.types.insert(id, (name, assembly));
        }
        record::ATTRIBUTE_INFO => {
            let id = body.read_le::<i16>()?;
            let owner = body.read_le::<i16>()?;
            let usage = match body.read_le::<u8>()? {
                1 => BamlAttributeUsage::XmlLang,
                2 => BamlAttributeUsage::XmlSpace,
                3 => BamlAttributeUsage::RuntimeName,
                _ => BamlAttributeUsage::Default,
            };
            let name = body.read_prefixed_string_utf8()?;
            declarations.attributes.insert(id, (owner, name, usage));
        }
        record::STRING_INFO => {
            let id = body.read_le::<i16>()?;
            let value = body.read_prefixed_string_utf8()?;
            declarations.strings.insert(id, value);
        }
        record::XMLNS_PROPERTY => {
            let prefix = body.read_prefixed_string_utf8()?;
            let namespace = body.read_prefixed_string_utf8()?;
            namespaces.push((prefix, namespace));
        }
        record::ELEMENT_START | record::STATIC_RESOURCE_START => {
            let id = body.read_le::<i16>()?;
            let element = BamlElement {
                type_name: declarations.type_name(id),
                assembly: declarations.type_assembly(id),
                ..BamlElement::default()
            };
            open(element, stack, elements);
        }
        record::ELEMENT_END | record::STATIC_RESOURCE_END => {
            if let Some(Frame::Element(_)) = stack.last() {
                stack.pop();
            }
        }
        record::PROPERTY_COMPLEX_START
        | record::PROPERTY_ARRAY_START
        | record::PROPERTY_ILIST_START
        | record::PROPERTY_IDICTIONARY_START => {
            let (owner, name, _) = declarations.attribute(body.read_le::<i16>()?);
            stack.push(Frame::Property(BamlPropertyElement {
                owner,
                name,
                elements: Vec::new(),
            }));
        }
        record::PROPERTY_COMPLEX_END
        | record::PROPERTY_ARRAY_END
        | record::PROPERTY_ILIST_END
        | record::PROPERTY_IDICTIONARY_END => {
            if let Some(Frame::Property(_)) = stack.last() {
                if let Some(frame) = stack.pop() {
                    close(frame, stack, elements);
                }
            }
        }
        record::PROPERTY | record::PROPERTY_WITH_CONVERTER => {
            let (owner, name, usage) = declarations.attribute(body.read_le::<i16>()?);
            let text = body.read_prefixed_string_utf8()?;
            let converter = if kind == record::PROPERTY_WITH_CONVERTER {
                declarations.type_name(body.read_le::<i16>()?)
            } else {
                None
            };
            if let Some(element) = element_at(elements, at) {
                element.properties.push(BamlProperty {
                    owner,
                    name,
                    usage,
                    value: BamlValue::Text { text, converter },
                });
            }
        }
        record::PROPERTY_CUSTOM => {
            let (owner, name, usage) = declarations.attribute(body.read_le::<i16>()?);
            // The serializer is a known type's positive index; 0x4000 marks
            // a value named by id rather than by its bytes.
            let serializer = body.read_le::<i16>()? & !0x4000;
            let bytes = body.read_bytes(body.remaining())?.to_vec();
            if let Some(element) = element_at(elements, at) {
                element.properties.push(BamlProperty {
                    owner,
                    name,
                    usage,
                    value: BamlValue::Custom {
                        serializer: KNOWN_TYPES
                            .get(usize::try_from(serializer).unwrap_or(usize::MAX))
                            .copied()
                            .flatten()
                            .map(str::to_owned),
                        bytes,
                    },
                });
            }
        }
        record::PROPERTY_WITH_EXTENSION => {
            let (owner, name, usage) = declarations.attribute(body.read_le::<i16>()?);
            // The low 12 bits name the extension's known type.
            let extension = body.read_le::<i16>()? & 0x0FFF;
            let value_id = body.read_le::<i16>()?;
            if let Some(element) = element_at(elements, at) {
                element.properties.push(BamlProperty {
                    owner,
                    name,
                    usage,
                    value: BamlValue::Extension {
                        extension: KNOWN_TYPES
                            .get(usize::try_from(extension).unwrap_or(usize::MAX))
                            .copied()
                            .flatten()
                            .map(str::to_owned),
                        value_id,
                    },
                });
            }
        }
        record::PROPERTY_TYPE_REFERENCE | record::PROPERTY_STRING_REFERENCE => {
            let (owner, name, usage) = declarations.attribute(body.read_le::<i16>()?);
            let id = body.read_le::<i16>()?;
            let value = if kind == record::PROPERTY_TYPE_REFERENCE {
                BamlValue::Type(declarations.type_name(id))
            } else {
                BamlValue::String(declarations.strings.get(&id).cloned())
            };
            if let Some(element) = element_at(elements, at) {
                element.properties.push(BamlProperty {
                    owner,
                    name,
                    usage,
                    value,
                });
            }
        }
        record::PROPERTY_WITH_STATIC_RESOURCE_ID => {
            let (owner, name, usage) = declarations.attribute(body.read_le::<i16>()?);
            let id = body.read_le::<i16>()?;
            if let Some(element) = element_at(elements, at) {
                element.properties.push(BamlProperty {
                    owner,
                    name,
                    usage,
                    value: BamlValue::StaticResource(id),
                });
            }
        }
        record::CONNECTION_ID => {
            let id = body.read_le::<i32>()?;
            if let Some(element) = element_at(elements, at) {
                element.connection_id = Some(id);
            }
        }
        record::TEXT | record::TEXT_WITH_CONVERTER | record::LITERAL_CONTENT => {
            let text = body.read_prefixed_string_utf8()?;
            if let Some(element) = element_at(elements, at) {
                element.text.push(text);
            }
        }
        record::TEXT_WITH_ID => {
            let id = body.read_le::<i16>()?;
            if let (Some(text), Some(element)) = (
                declarations.strings.get(&id).cloned(),
                element_at(elements, at),
            ) {
                element.text.push(text);
            }
        }
        // Records that state nothing the tree holds: the document's options,
        // the CLR namespace mappings, the content property and the line
        // positions, a dictionary's keys and deferred content's size, a
        // constructor's parameters, static resource references by id, and
        // definition and presentation-options attributes.
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream with its header and `records`.
    fn stream(records: &[u8]) -> Vec<u8> {
        let mut bytes = 12u32.to_le_bytes().to_vec();
        for unit in SIGNATURE.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        for _ in 0..3 {
            bytes.extend_from_slice(&[0, 0, 0x60, 0]);
        }
        bytes.extend_from_slice(records);
        bytes
    }

    /// A variable record of `kind` with `payload`, its length counting
    /// itself.
    fn variable(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![kind, u8::try_from(payload.len() + 1).unwrap()];
        bytes.extend_from_slice(payload);
        bytes
    }

    /// A BinaryWriter string: its 7-bit length and its UTF-8 bytes.
    fn text(value: &str) -> Vec<u8> {
        let mut bytes = vec![u8::try_from(value.len()).unwrap()];
        bytes.extend_from_slice(value.as_bytes());
        bytes
    }

    /// **A stream's elements, properties, names and connection ids read into
    /// its tree**: a known `Canvas` holding a known `Button` that a declared
    /// attribute names (`x:Name`, usage RuntimeName) and a known property
    /// sizes, its connection id, and a declared root type.
    #[test]
    fn a_stream_reads_into_its_element_tree() {
        let canvas = KNOWN_TYPES
            .iter()
            .position(|t| *t == Some("System.Windows.Controls.Canvas"))
            .unwrap();
        let button = KNOWN_TYPES
            .iter()
            .position(|t| *t == Some("System.Windows.Controls.Button"))
            .unwrap();
        let width = KNOWN_PROPERTIES
            .iter()
            .position(|p| {
                p.is_some_and(|(owner, name)| {
                    name == "Width"
                        && KNOWN_TYPES[usize::from(owner)]
                            == Some("System.Windows.FrameworkElement")
                })
            })
            .unwrap();
        let id = |index: usize| (-(i16::try_from(index).unwrap())).to_le_bytes();
        let mut records = vec![record::DOCUMENT_START, 0, 0xff, 0xff, 0xff, 0xff, 0];
        let mut assembly = 0i16.to_le_bytes().to_vec();
        assembly.extend(text("app"));
        records.extend(variable(record::ASSEMBLY_INFO, &assembly));
        let mut window = 0i16.to_le_bytes().to_vec();
        window.extend(0i16.to_le_bytes());
        window.extend(text("App.Main"));
        records.extend(variable(record::TYPE_INFO, &window));
        records.extend([record::ELEMENT_START, 0, 0, 0]);
        records.push(record::ELEMENT_START);
        records.extend(id(canvas));
        records.push(0);
        records.push(record::ELEMENT_START);
        records.extend(id(button));
        records.push(0);
        records.push(record::CONNECTION_ID);
        records.extend(4i32.to_le_bytes());
        let mut name = 0i16.to_le_bytes().to_vec();
        name.extend(id(button));
        name.push(3);
        name.extend(text("Name"));
        records.extend(variable(record::ATTRIBUTE_INFO, &name));
        let mut set = 0i16.to_le_bytes().to_vec();
        set.extend(text("ok"));
        records.extend(variable(record::PROPERTY, &set));
        let mut sized = id(width).to_vec();
        sized.extend(text("75"));
        records.extend(variable(record::PROPERTY, &sized));
        records.extend([
            record::ELEMENT_END,
            record::ELEMENT_END,
            record::ELEMENT_END,
            record::DOCUMENT_END,
        ]);
        let document = read_baml(&stream(&records)).expect("the stream reads");
        assert!(!document.truncated);
        assert_eq!(document.assemblies, [(0, "app".to_owned())]);
        let root = document.root().expect("a root");
        assert_eq!(root.type_name.as_deref(), Some("App.Main"));
        assert_eq!(root.assembly.as_deref(), Some("app"));
        let canvas = document.children(root).next().expect("the canvas");
        assert_eq!(
            canvas.type_name.as_deref(),
            Some("System.Windows.Controls.Canvas")
        );
        assert_eq!(canvas.parent, Some(0));
        let button = document.children(canvas).next().expect("the button");
        assert_eq!(button.runtime_name(), Some("ok"));
        assert_eq!(button.connection_id, Some(4));
        assert_eq!(
            button.property_text(Some("FrameworkElement"), "Width"),
            Some("75")
        );
    }

    /// **The markup compiler's BAML reads back as its XAML states it**: the
    /// fixture's `LoginWindow.xaml` and `StatusPanel.xaml`, compiled by the
    /// .NET 9 SDK. The window is its declared class with its title, its
    /// Canvas holding eight controls in order, each named control's
    /// `x:Name` and connection id, an attached `Canvas.Left`, a known
    /// `Width` and a converter's text; the user control's Grid states its
    /// column definitions as a property element and its children's
    /// `Grid.Column`.
    #[test]
    fn the_markup_compilers_baml_reads_as_its_xaml_states() {
        let resources = crate::metadata::resources::parse_dotnet_resource(include_bytes!(
            "../../../../tests/samples/resources/wpf_window.g.resources"
        ))
        .expect("the resource set reads");
        let page = |name: &str| match &resources.get(name).expect(name).data {
            crate::metadata::resources::ResourceType::Stream(bytes) => {
                read_baml(bytes).expect("the page reads")
            }
            other => panic!("{name} is a {other:?}"),
        };
        let window = page("loginwindow.baml");
        assert!(!window.truncated);
        assert_eq!(window.writer_version, (0, 0x60));
        let root = window.root().expect("a root");
        assert_eq!(root.type_name.as_deref(), Some("Visus.Fixture.LoginWindow"));
        assert_eq!(root.property_text(Some("Window"), "Title"), Some("Sign in"));
        assert_eq!(root.property_text(None, "Width"), Some("320"));
        let canvas = window.children(root).next().expect("the canvas");
        assert_eq!(
            canvas.type_name.as_deref(),
            Some("System.Windows.Controls.Canvas")
        );
        let controls: Vec<(Option<&str>, Option<&str>, Option<i32>)> = window
            .children(canvas)
            .map(|c| {
                (
                    c.type_name.as_deref().and_then(|t| t.rsplit('.').next()),
                    c.runtime_name(),
                    c.connection_id,
                )
            })
            .collect();
        assert_eq!(
            controls,
            [
                (Some("Label"), None, None),
                (Some("TextBox"), Some("user"), Some(1)),
                (Some("Label"), None, None),
                (Some("PasswordBox"), Some("password"), Some(2)),
                (Some("CheckBox"), Some("remember"), Some(3)),
                (Some("Button"), Some("ok"), Some(4)),
                (Some("Button"), Some("cancel"), Some(5)),
                (Some("StatusPanel"), Some("status"), Some(6)),
            ]
        );
        let ok = window.children(canvas).nth(5).expect("ok");
        assert_eq!(ok.property_text(Some("Canvas"), "Left"), Some("120"));
        assert_eq!(ok.property_text(Some("Canvas"), "Top"), Some("140"));
        assert_eq!(ok.property_text(None, "Content"), Some("OK"));
        assert!(matches!(
            ok.properties.iter().find(|p| p.name.as_deref() == Some("IsDefault")).map(|p| &p.value),
            Some(BamlValue::Text { text, converter: Some(converter) })
                if text == "True" && converter == "System.ComponentModel.BooleanConverter"
        ));

        let panel = page("statuspanel.baml");
        let root = panel.root().expect("a root");
        assert_eq!(root.type_name.as_deref(), Some("Visus.Fixture.StatusPanel"));
        let grid = panel.children(root).next().expect("the grid");
        assert_eq!(
            grid.type_name.as_deref(),
            Some("System.Windows.Controls.Grid")
        );
        let columns = grid
            .property_elements
            .iter()
            .find(|p| p.name.as_deref() == Some("ColumnDefinitions"))
            .expect("the column definitions");
        assert_eq!(columns.elements.len(), 2);
        let widths: Vec<Option<&str>> = columns
            .elements
            .iter()
            .map(|&i| panel.elements[i].property_text(None, "Width"))
            .collect();
        assert_eq!(widths, [Some("Auto"), Some("*")]);
        let children: Vec<(Option<&str>, Option<&str>)> = panel
            .children(grid)
            .map(|c| (c.runtime_name(), c.property_text(Some("Grid"), "Column")))
            .collect();
        assert_eq!(
            children,
            [(Some("state"), Some("0")), (Some("progress"), Some("1"))]
        );
    }

    /// **A record of a type no layout states ends the read with what came
    /// before**, the open elements closed into the tree; a stream without
    /// its header is refused.
    #[test]
    fn an_unknown_record_ends_the_read() {
        let records = [
            record::DOCUMENT_START,
            0,
            0,
            0,
            0,
            0,
            0,
            record::ELEMENT_START,
            0xff,
            0xff,
            0,
            19,
            1,
            2,
        ];
        let document = read_baml(&stream(&records)).expect("the stream reads");
        assert!(document.truncated);
        assert!(document.root().is_some(), "the open element is in the tree");
        assert!(read_baml(b"not baml at all").is_err());
    }

    /// **A deeply nested stream reads, walks and drops without recursing**:
    /// 100,000 nested elements, each four bytes, build the tree's spine.
    #[test]
    fn a_deep_stream_reads_without_recursion() {
        let mut records = vec![record::DOCUMENT_START, 0, 0, 0, 0, 0, 0];
        for _ in 0..100_000 {
            records.extend([record::ELEMENT_START, 0xff, 0xff, 0]);
        }
        let document = read_baml(&stream(&records)).expect("the stream reads");
        assert!(document.truncated);
        assert_eq!(document.elements.len(), 100_000);
        let mut depth = 0;
        let mut at = document.root();
        while let Some(element) = at {
            depth += 1;
            at = document.children(element).next();
        }
        assert_eq!(depth, 100_000);
        // The tree is flat, so dropping it does not recurse either.
        drop(document);
    }
}
