//! Reflection and dynamic method operations for the managed heap.
//!
//! This module provides operations for ReflectionMethod, ReflectionType,
//! ReflectionField, ReflectionProperty, ReflectionParameter, DynamicMethod,
//! and ILGenerator objects on [`ManagedHeap`].

use std::sync::{Arc, Mutex};

use crate::{
    assembly::InstructionAssembler,
    emulation::{
        engine::EmulationError,
        memory::heap::{HeapObject, ManagedHeap, ReflectionPropertyInfo, TypeWrapper},
        HeapRef,
    },
    metadata::{signatures::TypeSignature, token::Token},
    Result,
};

impl ManagedHeap {
    /// Allocates a reflection method info object on the heap.
    ///
    /// Creates a `ReflectionMethod` object that stores the resolved method token.
    /// Used by reflection stubs to track method resolution for later invocation.
    ///
    /// # Arguments
    ///
    /// * `method_token` - The token of the resolved method.
    ///
    /// # Returns
    ///
    /// A [`HeapRef`] pointing to the new reflection method object.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    pub fn alloc_reflection_method(&self, method_token: Token) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::ReflectionMethod {
                method_token,
                method_type_args: None,
            },
            None,
        )
    }

    /// Gets the method token from a reflection method object.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the reflection method object.
    ///
    /// # Returns
    ///
    /// The method token if the reference points to a `ReflectionMethod`, or `None` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn get_reflection_method_token(&self, heap_ref: HeapRef) -> Result<Option<Token>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&heap_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::ReflectionMethod { method_token, .. }) => Some(*method_token),
            _ => None,
        })
    }

    /// Allocates a `ReflectionMethod` object with generic type arguments.
    ///
    /// Used by `MethodInfo.MakeGenericMethod()` to create a closed generic method
    /// reference that carries the type arguments for later dispatch.
    pub fn alloc_reflection_method_generic(
        &self,
        method_token: Token,
        type_args: Vec<Token>,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::ReflectionMethod {
                method_token,
                method_type_args: Some(type_args),
            },
            None,
        )
    }

    /// Gets the method-level generic type arguments from a reflection method object.
    ///
    /// Returns `None` if the reference is not a `ReflectionMethod` or if the method
    /// is not a closed generic instantiation.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn get_reflection_method_type_args(&self, heap_ref: HeapRef) -> Result<Option<Vec<Token>>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&heap_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::ReflectionMethod {
                method_type_args, ..
            }) => method_type_args.clone(),
            _ => None,
        })
    }

    /// Allocates a reflection type object on the heap.
    ///
    /// Creates a `ReflectionType` object that stores the actual metadata type token.
    /// Used by `Type.GetTypeFromHandle()` to track which type was resolved, enabling
    /// subsequent calls like `Type.GetFields()` to look up the type's fields.
    ///
    /// When `wrapper` is provided (via `Type.MakeByRefType()`, `Type.MakeArrayType()`,
    /// `Type.MakeGenericType()`), it takes precedence over type registry lookups for
    /// boolean property checks like `IsByRef`, `IsArray`, `IsPointer`.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    pub fn alloc_reflection_type(
        &self,
        type_token: Token,
        wrapper: Option<TypeWrapper>,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::ReflectionType {
                type_token,
                wrapper,
            },
            None,
        )
    }

    /// Gets the wrapper override from a reflection type object.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn get_reflection_type_wrapper(&self, heap_ref: HeapRef) -> Result<Option<TypeWrapper>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&heap_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::ReflectionType { wrapper, .. }) => wrapper.clone(),
            _ => None,
        })
    }

    /// Gets the type token from a reflection type object.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn get_reflection_type_token(&self, heap_ref: HeapRef) -> Result<Option<Token>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&heap_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::ReflectionType { type_token, .. }) => Some(*type_token),
            _ => None,
        })
    }

    /// Allocates a reflection field info object on the heap.
    ///
    /// Creates a `ReflectionField` object that stores the field's metadata token and
    /// declaring type token. Used by `FieldInfo.SetValue()` and `FieldInfo.GetValue()`
    /// to determine which field to read/write.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The FieldDef metadata token.
    /// * `declaring_type_token` - The TypeDef token of the declaring type.
    /// * `is_static` - Whether this is a static field.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    pub fn alloc_reflection_field(
        &self,
        field_token: Token,
        declaring_type_token: Token,
        is_static: bool,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::ReflectionField {
                field_token,
                declaring_type_token,
                is_static,
            },
            None,
        )
    }

    /// Gets the field info from a reflection field object.
    ///
    /// Returns `(field_token, declaring_type_token, is_static)` if the reference
    /// points to a `ReflectionField`, or `None` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn get_reflection_field_info(
        &self,
        heap_ref: HeapRef,
    ) -> Result<Option<(Token, Token, bool)>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&heap_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::ReflectionField {
                field_token,
                declaring_type_token,
                is_static,
            }) => Some((*field_token, *declaring_type_token, *is_static)),
            _ => None,
        })
    }

    /// Allocates a reflection property info object on the heap.
    ///
    /// Creates a `ReflectionProperty` object that stores the property name,
    /// declaring type token, and optional getter/setter method tokens.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    pub fn alloc_reflection_property(
        &self,
        property_name: Arc<str>,
        declaring_type_token: Token,
        getter_token: Option<Token>,
        setter_token: Option<Token>,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::ReflectionProperty {
                property_name,
                declaring_type_token,
                getter_token,
                setter_token,
            },
            None,
        )
    }

    /// Gets the property info from a reflection property object.
    ///
    /// Returns `(property_name, declaring_type_token, getter_token, setter_token)`.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn get_reflection_property_info(
        &self,
        heap_ref: HeapRef,
    ) -> Result<Option<ReflectionPropertyInfo>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&heap_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::ReflectionProperty {
                property_name,
                declaring_type_token,
                getter_token,
                setter_token,
            }) => Some((
                property_name.clone(),
                *declaring_type_token,
                *getter_token,
                *setter_token,
            )),
            _ => None,
        })
    }

    /// Allocates a reflection parameter info object on the heap.
    ///
    /// Creates a `ReflectionParameter` object that stores the method token,
    /// parameter position, and type signature.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    pub fn alloc_reflection_parameter(
        &self,
        method_token: Token,
        position: u32,
        parameter_type: TypeSignature,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::ReflectionParameter {
                method_token,
                position,
                parameter_type,
            },
            None,
        )
    }

    /// Gets the parameter info from a reflection parameter object.
    ///
    /// Returns `(method_token, position, parameter_type)`.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn get_reflection_parameter_info(
        &self,
        heap_ref: HeapRef,
    ) -> Result<Option<(Token, u32, TypeSignature)>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&heap_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::ReflectionParameter {
                method_token,
                position,
                parameter_type,
            }) => Some((*method_token, *position, parameter_type.clone())),
            _ => None,
        })
    }

    /// Allocates a new `DynamicMethod` on the heap.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_dynamic_method(&self) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::DynamicMethod {
                il_generator: None,
                is_static: true,
                param_types: Vec::new(),
                return_type: None,
            },
            None,
        )
    }

    /// Allocates a new `DynamicMethod` with explicit static flag and parameter types.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_dynamic_method_with_params(
        &self,
        is_static: bool,
        param_types: Vec<Token>,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::DynamicMethod {
                il_generator: None,
                is_static,
                param_types,
                return_type: None,
            },
            None,
        )
    }

    /// Allocates a new `ILGenerator` linked to the given `DynamicMethod`.
    ///
    /// Creates an `InstructionAssembler` for accumulating IL instructions.
    /// Also updates the DynamicMethod to reference this ILGenerator.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_il_generator(&self, dynamic_method: HeapRef) -> Result<HeapRef> {
        let il_ref = self.alloc_object_internal(
            HeapObject::ILGenerator {
                dynamic_method,
                assembler: Arc::new(Mutex::new(InstructionAssembler::new())),
                label_names: Box::new(boxcar::Vec::new()),
                token_map: Box::new(boxcar::Vec::new()),
                local_types: Box::new(boxcar::Vec::new()),
            },
            None,
        )?;
        // Link the ILGenerator back to the DynamicMethod
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::DynamicMethod { il_generator, .. }) = state
            .objects
            .get_mut(&dynamic_method.id())
            .map(Arc::make_mut)
        {
            *il_generator = Some(il_ref);
        }
        Ok(il_ref)
    }

    /// Sets the parameter types on a `DynamicMethod` (called from `.ctor` hook).
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn set_dynamic_method_params(&self, dm_ref: HeapRef, params: Vec<Token>) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::DynamicMethod { param_types, .. }) =
            state.objects.get_mut(&dm_ref.id()).map(Arc::make_mut)
        {
            *param_types = params;
        }
        Ok(())
    }

    /// Sets the return type on a `DynamicMethod`.
    pub fn set_dynamic_method_return_type(
        &self,
        dm_ref: HeapRef,
        ret_type: Option<Token>,
    ) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::DynamicMethod { return_type, .. }) =
            state.objects.get_mut(&dm_ref.id()).map(Arc::make_mut)
        {
            *return_type = ret_type;
        }
        Ok(())
    }

    /// Gets the return type token from a `DynamicMethod`.
    pub fn get_dynamic_method_return_type(&self, dm_ref: HeapRef) -> Result<Option<Token>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&dm_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::DynamicMethod { return_type, .. }) => *return_type,
            _ => None,
        })
    }

    /// Gets the ILGenerator heap reference from a `DynamicMethod`.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn get_dynamic_method_il_generator(&self, dm_ref: HeapRef) -> Result<Option<HeapRef>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&dm_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::DynamicMethod { il_generator, .. }) => *il_generator,
            _ => None,
        })
    }

    /// Gets the ILGenerator's `InstructionAssembler`.
    ///
    /// Returns a cloned `Arc` so callers can work with the assembler without
    /// holding the heap lock.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn get_il_generator_assembler(
        &self,
        il_ref: HeapRef,
    ) -> Result<Option<Arc<Mutex<InstructionAssembler>>>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&il_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::ILGenerator { assembler, .. }) => Some(Arc::clone(assembler)),
            _ => None,
        })
    }

    /// Defines a new label in the ILGenerator's label registry.
    ///
    /// Generates a unique label name and appends it. Returns the label ID (index)
    /// and the generated label name.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn il_generator_define_label(&self, il_ref: HeapRef) -> Result<Option<(usize, String)>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&il_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::ILGenerator { label_names, .. }) => {
                let id = label_names.count();
                let name = format!("_dyn_L{id}");
                label_names.push(name.clone());
                Some((id, name))
            }
            _ => None,
        })
    }

    /// Gets a label name by index from the ILGenerator.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn il_generator_get_label(&self, il_ref: HeapRef, index: usize) -> Result<Option<String>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&il_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::ILGenerator { label_names, .. }) => label_names.get(index).cloned(),
            _ => None,
        })
    }

    /// Appends a local variable type token to the ILGenerator.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn il_generator_push_local(
        &self,
        il_ref: HeapRef,
        type_token: Token,
    ) -> Result<Option<usize>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&il_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::ILGenerator { local_types, .. }) => Some(local_types.push(type_token)),
            _ => None,
        })
    }

    /// Collects all local variable type tokens from the ILGenerator.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn il_generator_get_locals(&self, il_ref: HeapRef) -> Result<Option<Vec<Token>>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&il_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::ILGenerator { local_types, .. }) => {
                Some(local_types.iter().map(|(_, t)| *t).collect())
            }
            _ => None,
        })
    }

    /// Appends a token mapping to the ILGenerator.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn il_generator_push_token_map(
        &self,
        il_ref: HeapRef,
        synthetic_id: u32,
        real_token: Token,
    ) -> Result<Option<usize>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&il_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::ILGenerator { token_map, .. }) => {
                Some(token_map.push((synthetic_id, real_token)))
            }
            _ => None,
        })
    }

    /// Gets the DynamicMethod's parameter types and static flag.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn get_dynamic_method_info(&self, dm_ref: HeapRef) -> Result<Option<(bool, Vec<Token>)>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&dm_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::DynamicMethod {
                is_static,
                param_types,
                ..
            }) => Some((*is_static, param_types.clone())),
            _ => None,
        })
    }

    /// Gets the owning DynamicMethod reference from an ILGenerator.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn get_il_generator_owner(&self, il_ref: HeapRef) -> Result<Option<HeapRef>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&il_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::ILGenerator { dynamic_method, .. }) => Some(*dynamic_method),
            _ => None,
        })
    }
}
