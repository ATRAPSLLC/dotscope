//! What a fixup names, spelled from the image's own metadata.

use std::{collections::HashMap, sync::OnceLock};

use crate::{
    metadata::{
        readytorun::{
            imports::{helper_name, Fixup, FixupSubject},
            signature::{ModuleToken, MEMBER_REF_TABLE, METHOD_DEF_TABLE},
        },
        tables::TableId,
        token::Token,
    },
    CilObject,
};

/// The metadata table of a `Field` token.
const FIELD_TABLE: u8 = 0x04;

/// Names the subjects of an image's fixups: a method `Type::Method`, a field
/// `Type::field`, a type by its full name with its generic arguments, a
/// helper by its `ReadyToRunHelper` name, a string by its text.
///
/// A token read in another module's metadata, which the image does not hold,
/// names nothing; nor does a token whose row the image does not hold.
pub struct FixupNames<'a> {
    /// The image whose metadata the tokens are read in.
    asm: &'a CilObject,
    /// Each field's declaring type's full name, by the field's token, built
    /// the first time a field is named.
    field_owners: OnceLock<HashMap<u32, String>>,
}

impl<'a> FixupNames<'a> {
    /// A namer over `asm`'s metadata.
    #[must_use]
    pub fn new(asm: &'a CilObject) -> Self {
        Self {
            asm,
            field_owners: OnceLock::new(),
        }
    }

    /// The name of what `fixup` takes; `None` when it takes nothing this
    /// image names.
    #[must_use]
    pub fn subject(&self, fixup: &Fixup) -> Option<String> {
        match &fixup.subject {
            FixupSubject::Method(method) => self.method(*method),
            FixupSubject::Field(field) => self.field(*field),
            FixupSubject::Type(ty) => ty.spell(|coded| self.coded_type(coded)),
            FixupSubject::Helper(number) => helper_name(*number).map(str::to_owned),
            FixupSubject::String(offset) => Some(
                self.asm
                    .userstrings()?
                    .get(*offset as usize)
                    .ok()?
                    .to_string_lossy(),
            ),
            FixupSubject::Unnamed => None,
        }
    }

    /// A `MethodDef` or `MemberRef` token's `Type::Method`.
    fn method(&self, method: ModuleToken) -> Option<String> {
        if method.module.is_some() {
            return None;
        }
        let token = Token::new(method.token);
        match method.token >> 24 {
            METHOD_DEF_TABLE => {
                let entry = self.asm.methods().get(&token)?;
                let method = entry.value();
                Some(qualified(method.declaring_type_fullname(), &method.name))
            }
            MEMBER_REF_TABLE => self.member_ref(token),
            _ => None,
        }
    }

    /// A `Field` or `MemberRef` token's `Type::field`.
    fn field(&self, field: ModuleToken) -> Option<String> {
        if field.module.is_some() {
            return None;
        }
        let token = Token::new(field.token);
        if token.table() != FIELD_TABLE {
            return self.member_ref(token);
        }
        let name = self.asm.fields().get(&token)?.value().name.clone();
        let owners = self.field_owners.get_or_init(|| {
            let mut owners = HashMap::new();
            // Only an entry keyed by a TypeDef token is a definition.
            for entry in self.asm.types().iter() {
                if !entry.key().is_table(TableId::TypeDef) {
                    continue;
                }
                let owner = entry.value();
                let fullname = owner.fullname().to_string();
                for (_, field) in owner.fields.iter() {
                    owners.insert(field.token.value(), fullname.clone());
                }
            }
            owners
        });
        Some(qualified(owners.get(&field.token).cloned(), &name))
    }

    /// A `MemberRef` token's `Type::member`.
    fn member_ref(&self, token: Token) -> Option<String> {
        let entry = self.asm.refs_members().get(&token)?;
        let member = entry.value();
        Some(qualified(member.declaredby.fullname(), &member.name))
    }

    /// The full name of the type a `TypeDefOrRef` coded index names: the row
    /// above two bits saying `TypeDef`, `TypeRef` or `TypeSpec`.
    fn coded_type(&self, coded: u32) -> Option<String> {
        let table = match coded & 3 {
            0 => TableId::TypeDef,
            1 => TableId::TypeRef,
            2 => TableId::TypeSpec,
            _ => return None,
        };
        self.asm
            .types()
            .get(&Token::from_parts(table, coded >> 2))
            .map(|ty| ty.fullname().to_string())
    }
}

/// `owner::name`, or `name` alone with no owner.
fn qualified(owner: Option<String>, name: &str) -> String {
    match owner.filter(|owner| !owner.is_empty()) {
        Some(owner) => format!("{owner}::{name}"),
        None => name.to_owned(),
    }
}
