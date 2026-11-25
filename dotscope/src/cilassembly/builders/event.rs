//! High-level event builder for creating .NET event definitions.
//!
//! This module provides [`EventBuilder`] for creating complete event definitions
//! including backing delegates, add/remove methods, and event metadata. It orchestrates
//! the existing low-level builders to provide a fluent, high-level API for various event patterns.

use crate::{
    cilassembly::{builders::method::MethodBuilder, ChangeRefRc, CilAssembly},
    metadata::{
        signatures::{encode_field_signature, SignatureField, TypeSignature},
        tables::{
            CodedIndex, CodedIndexType, EventAttributes, EventBuilder as EventTableBuilder,
            FieldAttributes, FieldBuilder, TableId,
        },
        token::Token,
    },
    Error, Result,
};

/// Event implementation strategy.
pub enum EventImplementation {
    /// Auto-event with automatic backing delegate field
    Auto {
        /// Name of the backing delegate field (auto-generated if None)
        backing_field_name: Option<String>,
        /// Backing delegate field attributes
        backing_field_attributes: FieldAttributes,
    },
    /// Custom event with user-provided add/remove logic
    Custom {
        /// Custom add implementation
        add_method: Option<Box<dyn FnOnce(MethodBuilder) -> MethodBuilder + Send>>,
        /// Custom remove implementation
        remove_method: Option<Box<dyn FnOnce(MethodBuilder) -> MethodBuilder + Send>>,
    },
    /// Manual implementation (user provides all methods separately)
    Manual,
}

/// High-level builder for creating complete event definitions.
///
/// `EventBuilder` provides a fluent API for creating events with various patterns:
/// auto-events, custom events, and manual implementations. It composes the existing
/// low-level builders to provide convenient high-level interfaces.
///
/// # Design
///
/// The builder supports multiple event patterns:
/// - **Auto-events**: Automatic backing delegate fields with generated add/remove methods
/// - **Custom events**: Custom logic for managing event subscriptions
/// - **Manual events**: Complete custom control over implementation
///
/// # Examples
///
/// ## Simple Auto-Event
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = CilAssemblyView::from_path("test.dll")?;
/// # let mut assembly = CilAssembly::new(view);
/// let event_token = EventBuilder::new("OnClick", TypeSignature::Object)
///     .auto_event()
///     .public_accessors()
///     .build(&mut assembly)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Custom Event with Logic
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = CilAssemblyView::from_path("test.dll")?;
/// # let mut assembly = CilAssembly::new(view);
/// let event_token = EventBuilder::new("OnDataChanged", TypeSignature::Object)
///     .custom()
///     .add_method(|method| method
///         .implementation(|body| {
///             body.implementation(|asm| {
///                 // Custom add logic
///                 asm.ldarg_0()? // Load 'this'
///                    .ldarg_1()? // Load delegate
///                    .call(Token::new(0x0A000001))? // Call Delegate.Combine
///                    .ret()?;
///                 Ok(())
///             })
///         }))
///     .remove_method(|method| method
///         .implementation(|body| {
///             body.implementation(|asm| {
///                 // Custom remove logic
///                 asm.ldarg_0()? // Load 'this'
///                    .ldarg_1()? // Load delegate
///                    .call(Token::new(0x0A000002))? // Call Delegate.Remove
///                    .ret()?;
///                 Ok(())
///             })
///         }))
///     .build(&mut assembly)?;
/// # Ok(())
/// # }
/// ```
pub struct EventBuilder {
    /// Event name
    name: String,

    /// Event delegate type (used for field/method signatures)
    event_type: TypeSignature,

    /// Event type as CodedIndex (for Event table metadata)
    /// If None, falls back to System.Object placeholder
    event_type_index: Option<CodedIndex>,

    /// Event attributes
    attributes: EventAttributes,

    /// Add method visibility (separate from event attributes)
    add_attributes: u32,
    remove_attributes: u32,

    /// Implementation strategy
    implementation: EventImplementation,
}

impl EventBuilder {
    /// Create a new event builder with the given name and delegate type.
    ///
    /// # Arguments
    ///
    /// * `name` - Event name
    /// * `event_type` - Event delegate type signature
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EventBuilder::new("OnClick", TypeSignature::Object);
    /// ```
    #[must_use]
    pub fn new(name: &str, event_type: TypeSignature) -> Self {
        Self {
            name: name.to_string(),
            event_type,
            event_type_index: None,
            attributes: EventAttributes::ZERO, // Default event attributes
            add_attributes: 0x0006,            // PUBLIC
            remove_attributes: 0x0006,         // PUBLIC
            implementation: EventImplementation::Auto {
                backing_field_name: None,
                backing_field_attributes: FieldAttributes::PRIVATE,
            },
        }
    }

    /// Configure this as an auto-event with automatic backing delegate field.
    ///
    /// This is the default behavior and creates an event similar to C# auto-events.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EventBuilder::new("OnClick", TypeSignature::Object)
    ///     .auto_event();
    /// ```
    #[must_use]
    pub fn auto_event(mut self) -> Self {
        self.implementation = EventImplementation::Auto {
            backing_field_name: None,
            backing_field_attributes: FieldAttributes::PRIVATE,
        };
        self
    }

    /// Configure this as a custom event with user-provided logic.
    ///
    /// Custom events allow complete control over add/remove implementations
    /// while still providing convenience methods for common patterns.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EventBuilder::new("OnDataChanged", TypeSignature::Object)
    ///     .custom();
    /// ```
    #[must_use]
    pub fn custom(mut self) -> Self {
        self.implementation = EventImplementation::Custom {
            add_method: None,
            remove_method: None,
        };
        self
    }

    /// Configure this as a manual event where all methods are provided separately.
    ///
    /// Manual events give complete control but require the user to provide all implementations.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EventBuilder::new("ComplexEvent", TypeSignature::Object)
    ///     .manual();
    /// ```
    #[must_use]
    pub fn manual(mut self) -> Self {
        self.implementation = EventImplementation::Manual;
        self
    }

    /// Set a custom name for the backing delegate field (auto-events only).
    ///
    /// # Arguments
    ///
    /// * `field_name` - Custom backing field name
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EventBuilder::new("OnClick", TypeSignature::Object)
    ///     .backing_field("_onClick");
    /// ```
    #[must_use]
    pub fn backing_field(mut self, field_name: &str) -> Self {
        if let EventImplementation::Auto {
            backing_field_name, ..
        } = &mut self.implementation
        {
            *backing_field_name = Some(field_name.to_string());
        }
        self
    }

    /// Make the backing field private (default for auto-events).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EventBuilder::new("OnClick", TypeSignature::Object)
    ///     .private_backing_field();
    /// ```
    #[must_use]
    pub fn private_backing_field(mut self) -> Self {
        if let EventImplementation::Auto {
            backing_field_attributes,
            ..
        } = &mut self.implementation
        {
            *backing_field_attributes = FieldAttributes::PRIVATE;
        }
        self
    }

    /// Make the backing field protected (unusual but possible).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EventBuilder::new("OnClick", TypeSignature::Object)
    ///     .protected_backing_field();
    /// ```
    #[must_use]
    pub fn protected_backing_field(mut self) -> Self {
        if let EventImplementation::Auto {
            backing_field_attributes,
            ..
        } = &mut self.implementation
        {
            *backing_field_attributes = FieldAttributes::FAMILY;
        }
        self
    }

    /// Make both add and remove accessors public.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EventBuilder::new("OnClick", TypeSignature::Object)
    ///     .public_accessors();
    /// ```
    #[must_use]
    pub fn public_accessors(mut self) -> Self {
        self.add_attributes = 0x0006; // PUBLIC
        self.remove_attributes = 0x0006; // PUBLIC
        self
    }

    /// Make both add and remove accessors private.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EventBuilder::new("OnClick", TypeSignature::Object)
    ///     .private_accessors();
    /// ```
    #[must_use]
    pub fn private_accessors(mut self) -> Self {
        self.add_attributes = 0x0001; // PRIVATE
        self.remove_attributes = 0x0001; // PRIVATE
        self
    }

    /// Set add method visibility separately.
    ///
    /// # Arguments
    ///
    /// * `attributes` - Method attributes for the add method
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EventBuilder::new("OnClick", TypeSignature::Object)
    ///     .add_visibility(0x0006); // PUBLIC
    /// ```
    #[must_use]
    pub fn add_visibility(mut self, attributes: u32) -> Self {
        self.add_attributes = attributes;
        self
    }

    /// Set remove method visibility separately.
    ///
    /// # Arguments
    ///
    /// * `attributes` - Method attributes for the remove method
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EventBuilder::new("OnClick", TypeSignature::Object)
    ///     .remove_visibility(0x0001); // PRIVATE
    /// ```
    #[must_use]
    pub fn remove_visibility(mut self, attributes: u32) -> Self {
        self.remove_attributes = attributes;
        self
    }

    /// Add a custom add method implementation (for custom events).
    ///
    /// # Arguments
    ///
    /// * `implementation` - Function that configures the add method
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// # let view = CilAssemblyView::from_path("test.dll")?;
    /// # let mut assembly = CilAssembly::new(view);
    /// let builder = EventBuilder::new("OnDataChanged", TypeSignature::Object)
    ///     .custom()
    ///     .add_method(|method| method
    ///         .implementation(|body| {
    ///             body.implementation(|asm| {
    ///                 asm.ldarg_0()?.ldarg_1()?.call(Token::new(0x0A000001))?.ret()?;
    ///                 Ok(())
    ///             })
    ///         }));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn add_method<F>(mut self, implementation: F) -> Self
    where
        F: FnOnce(MethodBuilder) -> MethodBuilder + Send + 'static,
    {
        if let EventImplementation::Custom { add_method, .. } = &mut self.implementation {
            *add_method = Some(Box::new(implementation));
        }
        self
    }

    /// Add a custom remove method implementation (for custom events).
    ///
    /// # Arguments
    ///
    /// * `implementation` - Function that configures the remove method
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// # let view = CilAssemblyView::from_path("test.dll")?;
    /// # let mut assembly = CilAssembly::new(view);
    /// let builder = EventBuilder::new("OnDataChanged", TypeSignature::Object)
    ///     .custom()
    ///     .remove_method(|method| method
    ///         .implementation(|body| {
    ///             body.implementation(|asm| {
    ///                 asm.ldarg_0()?.ldarg_1()?.call(Token::new(0x0A000002))?.ret()?;
    ///                 Ok(())
    ///             })
    ///         }));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn remove_method<F>(mut self, implementation: F) -> Self
    where
        F: FnOnce(MethodBuilder) -> MethodBuilder + Send + 'static,
    {
        if let EventImplementation::Custom { remove_method, .. } = &mut self.implementation {
            *remove_method = Some(Box::new(implementation));
        }
        self
    }

    /// Set event attributes.
    ///
    /// # Arguments
    ///
    /// * `attributes` - Event attributes bitmask
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = EventBuilder::new("OnClick", TypeSignature::Object)
    ///     .attributes(EventAttributes::SPECIAL_NAME);
    /// ```
    #[must_use]
    pub fn attributes(mut self, attributes: EventAttributes) -> Self {
        self.attributes = attributes;
        self
    }

    /// Set the event type as a `CodedIndex` for accurate Event table metadata.
    ///
    /// This method allows specifying the exact delegate type reference (TypeDef, TypeRef,
    /// or TypeSpec) that should be stored in the Event table. If not set, a placeholder
    /// `System.Object` reference is used.
    ///
    /// # Arguments
    ///
    /// * `coded_index` - The CodedIndex pointing to the delegate type
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    /// use dotscope::metadata::tables::{CodedIndex, CodedIndexType, TableId};
    ///
    /// // Reference EventHandler from System.TypeRef index 42
    /// let event_handler_ref = CodedIndex::new(TableId::TypeRef, 42, CodedIndexType::TypeDefOrRef);
    ///
    /// let builder = EventBuilder::new("OnClick", TypeSignature::Object)
    ///     .event_type_index(event_handler_ref);
    /// ```
    #[must_use]
    pub fn event_type_index(mut self, coded_index: CodedIndex) -> Self {
        self.event_type_index = Some(coded_index);
        self
    }

    /// Build the complete event and add it to the assembly.
    ///
    /// This method orchestrates the creation of:
    /// 1. Event table entry
    /// 2. Backing delegate field (for auto-events)
    /// 3. Add method
    /// 4. Remove method
    /// 5. MethodSemantics entries linking methods to the event
    ///
    /// # Arguments
    ///
    /// * `assembly` - CilAssembly for managing the assembly
    ///
    /// # Returns
    ///
    /// A `ChangeRefRc` representing the newly created event definition.
    ///
    /// # Errors
    ///
    /// Returns an error if event creation fails at any step.
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        // Use the provided event type index, or fall back to System.Object placeholder
        let event_type_coded_index = self
            .event_type_index
            .unwrap_or_else(|| CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef));

        // Create the event table entry
        let event_ref = EventTableBuilder::new()
            .name(&self.name)
            .flags(self.attributes)
            .event_type(event_type_coded_index)
            .build(assembly)?;

        // Handle different implementation strategies
        match self.implementation {
            EventImplementation::Auto {
                backing_field_name,
                backing_field_attributes,
            } => {
                // Generate backing field name if not provided
                let field_name = backing_field_name.unwrap_or_else(|| self.name.clone());

                // Create backing delegate field
                let field_sig = SignatureField {
                    modifiers: Vec::new(),
                    base: self.event_type.clone(),
                };
                let sig_bytes = encode_field_signature(&field_sig)?;

                let backing_field_ref = FieldBuilder::new()
                    .name(&field_name)
                    .flags(backing_field_attributes)
                    .signature(&sig_bytes)
                    .build(assembly)?;

                // Get placeholder token for the backing field
                let backing_field_token =
                    backing_field_ref.placeholder_token().ok_or_else(|| {
                        Error::ModificationInvalid(
                            "Failed to get placeholder token for backing field".to_string(),
                        )
                    })?;

                // Create add method
                let add_field_token = backing_field_token; // Copy for move
                let add_name = format!("add_{}", self.name);
                let add_visibility = self.add_attributes;

                let add_method = MethodBuilder::event_add(&add_name, self.event_type.clone());
                let add_method = match add_visibility {
                    0x0001 => add_method.private(),
                    _ => add_method.public(),
                };

                add_method
                    .implementation(move |body| {
                        body.implementation(move |asm| {
                            asm.ldarg_0()? // Load 'this'
                                .ldfld(add_field_token)? // Load current delegate
                                .ldarg_1()? // Load new delegate
                                .call(Token::new(0x0A00_0001))? // Call Delegate.Combine
                                .stfld(add_field_token)? // Store combined delegate
                                .ret()?;
                            Ok(())
                        })
                    })
                    .build(assembly)?;

                // Create remove method
                let remove_field_token = backing_field_token; // Copy for move
                let remove_name = format!("remove_{}", self.name);
                let remove_visibility = self.remove_attributes;

                let remove_method =
                    MethodBuilder::event_remove(&remove_name, self.event_type.clone());
                let remove_method = match remove_visibility {
                    0x0001 => remove_method.private(),
                    _ => remove_method.public(),
                };

                remove_method
                    .implementation(move |body| {
                        body.implementation(move |asm| {
                            asm.ldarg_0()? // Load 'this'
                                .ldfld(remove_field_token)? // Load current delegate
                                .ldarg_1()? // Load delegate to remove
                                .call(Token::new(0x0A00_0002))? // Call Delegate.Remove
                                .stfld(remove_field_token)? // Store updated delegate
                                .ret()?;
                            Ok(())
                        })
                    })
                    .build(assembly)?;

                Ok(event_ref)
            }
            EventImplementation::Custom {
                add_method,
                remove_method,
            } => {
                // Create add method if provided
                if let Some(add_impl) = add_method {
                    let add_method_builder = MethodBuilder::event_add(
                        &format!("add_{}", self.name),
                        self.event_type.clone(),
                    );
                    let add_method_builder = match self.add_attributes {
                        0x0001 => add_method_builder.private(),
                        _ => add_method_builder.public(),
                    };

                    let configured_add = add_impl(add_method_builder);
                    configured_add.build(assembly)?;
                } else {
                    return Err(Error::ModificationInvalid(
                        "Custom event requires add method implementation".to_string(),
                    ));
                }

                // Create remove method if provided
                if let Some(remove_impl) = remove_method {
                    let remove_method_builder = MethodBuilder::event_remove(
                        &format!("remove_{}", self.name),
                        self.event_type.clone(),
                    );
                    let remove_method_builder = match self.remove_attributes {
                        0x0001 => remove_method_builder.private(),
                        _ => remove_method_builder.public(),
                    };

                    let configured_remove = remove_impl(remove_method_builder);
                    configured_remove.build(assembly)?;
                } else {
                    return Err(Error::ModificationInvalid(
                        "Custom event requires remove method implementation".to_string(),
                    ));
                }

                Ok(event_ref)
            }
            EventImplementation::Manual => {
                // For manual implementation, just return the event ref
                // User is responsible for creating methods separately
                Ok(event_ref)
            }
        }
    }
}

impl Default for EventBuilder {
    fn default() -> Self {
        Self::new("DefaultEvent", TypeSignature::Object)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        cilassembly::{changes::ChangeRefKind, CilAssembly},
        metadata::{cilassemblyview::CilAssemblyView, signatures::TypeSignature, tables::TableId},
        testkit::fixture,
    };

    fn get_test_assembly() -> Result<CilAssembly> {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path)?;
        Ok(CilAssembly::new(view))
    }

    #[test]
    fn test_simple_auto_event() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let event_ref = EventBuilder::new("OnClick", TypeSignature::Object)
            .auto_event()
            .public_accessors()
            .build(&mut assembly)?;

        // Should create a valid Event reference
        assert_eq!(event_ref.kind(), ChangeRefKind::TableRow(TableId::Event));

        Ok(())
    }

    #[test]
    fn test_custom_event() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let event_ref = EventBuilder::new("OnDataChanged", TypeSignature::Object)
            .custom()
            .add_method(|method| {
                method.implementation(|body| {
                    body.implementation(|asm| {
                        asm.ldarg_0()?
                            .ldarg_1()?
                            .call(Token::new(0x0A000001))?
                            .ret()?;
                        Ok(())
                    })
                })
            })
            .remove_method(|method| {
                method.implementation(|body| {
                    body.implementation(|asm| {
                        asm.ldarg_0()?
                            .ldarg_1()?
                            .call(Token::new(0x0A000002))?
                            .ret()?;
                        Ok(())
                    })
                })
            })
            .build(&mut assembly)?;

        assert_eq!(event_ref.kind(), ChangeRefKind::TableRow(TableId::Event));

        Ok(())
    }

    #[test]
    fn test_manual_event() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let event_ref = EventBuilder::new("ManualEvent", TypeSignature::Object)
            .manual()
            .build(&mut assembly)?;

        assert_eq!(event_ref.kind(), ChangeRefKind::TableRow(TableId::Event));

        Ok(())
    }

    #[test]
    fn test_custom_backing_field() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let event_ref = EventBuilder::new("OnValueChanged", TypeSignature::Object)
            .auto_event()
            .backing_field("_onValueChanged")
            .private_backing_field()
            .public_accessors()
            .build(&mut assembly)?;

        assert_eq!(event_ref.kind(), ChangeRefKind::TableRow(TableId::Event));

        Ok(())
    }

    #[test]
    fn test_event_with_different_accessor_visibility() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let event_ref = EventBuilder::new("MixedVisibility", TypeSignature::Object)
            .auto_event()
            .add_visibility(0x0006) // PUBLIC
            .remove_visibility(0x0001) // PRIVATE
            .build(&mut assembly)?;

        assert_eq!(event_ref.kind(), ChangeRefKind::TableRow(TableId::Event));

        Ok(())
    }

    #[test]
    fn test_custom_event_missing_add_fails() {
        let mut assembly = get_test_assembly().unwrap();

        let result = EventBuilder::new("InvalidCustom", TypeSignature::Object)
            .custom()
            .remove_method(|method| {
                method.implementation(|body| {
                    body.implementation(|asm| {
                        asm.ret()?;
                        Ok(())
                    })
                })
            })
            .build(&mut assembly);

        assert!(result.is_err());
    }

    #[test]
    fn test_custom_event_missing_remove_fails() {
        let mut assembly = get_test_assembly().unwrap();

        let result = EventBuilder::new("InvalidCustom", TypeSignature::Object)
            .custom()
            .add_method(|method| {
                method.implementation(|body| {
                    body.implementation(|asm| {
                        asm.ret()?;
                        Ok(())
                    })
                })
            })
            .build(&mut assembly);

        assert!(result.is_err());
    }

    #[test]
    fn test_event_with_explicit_type_index() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create event with explicit delegate type reference (e.g., EventHandler at TypeRef index 5)
        let event_handler_ref = CodedIndex::new(TableId::TypeRef, 5, CodedIndexType::TypeDefOrRef);

        let event_ref = EventBuilder::new("OnExplicitType", TypeSignature::Object)
            .manual()
            .event_type_index(event_handler_ref)
            .build(&mut assembly)?;

        // Should create a valid Event reference
        assert_eq!(event_ref.kind(), ChangeRefKind::TableRow(TableId::Event));

        Ok(())
    }
}
