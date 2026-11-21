//! Array type operations for the managed heap.
//!
//! This module provides operations for single-dimensional arrays, multi-dimensional
//! arrays, and byte array convenience methods on [`ManagedHeap`].

use std::sync::Arc;

use crate::{
    emulation::{
        engine::EmulationError,
        memory::heap::{HeapObject, ManagedHeap},
        EmValue, HeapRef,
    },
    metadata::typesystem::{CilFlavor, PointerSize},
    Result,
};

impl ManagedHeap {
    /// Allocates a single-dimensional array on the heap.
    ///
    /// # Arguments
    ///
    /// * `element_type` - Type of array elements
    /// * `length` - Number of elements
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if the array would exceed the heap
    /// budget. The check happens **before** any host memory is committed — `length` comes
    /// straight off the emulated evaluation stack via `newarr`, so building the backing store
    /// first and asking afterwards means the limit can never fire.
    pub fn alloc_array(&self, element_type: CilFlavor, length: usize) -> Result<HeapRef> {
        self.reserve_elements(length)?;
        let mut elements = Vec::new();
        elements.try_reserve_exact(length).map_err(|_| {
            EmulationError::HeapMemoryLimitExceeded {
                current: self.current_size(),
                limit: self.max_size(),
            }
        })?;
        elements.resize(length, EmValue::default_for_flavor(&element_type));
        self.alloc_object_internal(
            HeapObject::Array {
                element_type,
                elements,
            },
            None,
        )
    }

    /// Allocates an array with explicit initial values.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_array_with_values(
        &self,
        element_type: CilFlavor,
        elements: Vec<EmValue>,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::Array {
                element_type,
                elements,
            },
            None,
        )
    }

    /// Allocates a multi-dimensional array on the heap.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_multi_array(
        &self,
        element_type: CilFlavor,
        dimensions: Vec<usize>,
    ) -> Result<HeapRef> {
        // `iter().product()` wraps on overflow in release builds and panics in debug, so the
        // element count is computed with checked arithmetic before it is used for anything.
        let total_elements = dimensions
            .iter()
            .try_fold(1usize, |acc, &d| acc.checked_mul(d))
            .ok_or(EmulationError::HeapMemoryLimitExceeded {
                current: self.current_size(),
                limit: self.max_size(),
            })?;

        self.reserve_elements(total_elements)?;
        let mut elements = Vec::new();
        elements.try_reserve_exact(total_elements).map_err(|_| {
            EmulationError::HeapMemoryLimitExceeded {
                current: self.current_size(),
                limit: self.max_size(),
            }
        })?;
        elements.resize(total_elements, EmValue::default_for_flavor(&element_type));
        self.alloc_object_internal(
            HeapObject::MultiArray {
                element_type,
                dimensions,
                elements,
            },
            None,
        )
    }

    /// Gets an array element (cloned).
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid, not an array, or index out of bounds.
    pub fn get_array_element(&self, heap_ref: HeapRef, index: usize) -> Result<EmValue> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get(&heap_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::Array { elements, .. }) => {
                if let Some(elem) = elements.get(index) {
                    Ok(elem.clone())
                } else {
                    Err(EmulationError::ArrayIndexOutOfBounds {
                        index: i64::try_from(index).unwrap_or(i64::MAX),
                        length: elements.len(),
                    }
                    .into())
                }
            }
            Some(other) => Err(EmulationError::HeapTypeMismatch {
                expected: "array",
                found: other.kind(),
            }
            .into()),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Sets an array element.
    ///
    /// # Heap accounting
    ///
    /// Deliberately none. This overwrites an existing slot rather than extending the array, and
    /// [`HeapObject::estimated_size`] charges arrays a flat `EMVALUE_SIZE` per element, so the
    /// accounted footprint is identical before and after — a delta calculation here would always
    /// be zero.
    ///
    /// The residual gap is that the estimate is *shallow*: an `EmValue::ValueType` carries a
    /// `Vec<EmValue>` whose contents are not walked, so a deeply nested value costs more host
    /// memory than it is charged. Building such values is bounded by the instruction budget
    /// rather than by the heap budget. Closing that properly means making `estimated_size`
    /// recursive, which costs a walk on every size query; it is not fixed here.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid, not an array, or index out of bounds.
    pub fn set_array_element(&self, heap_ref: HeapRef, index: usize, value: EmValue) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get_mut(&heap_ref.id()).map(Arc::make_mut) {
            Some(HeapObject::Array { elements, .. }) => {
                let len = elements.len();
                if let Some(slot) = elements.get_mut(index) {
                    *slot = value;
                    Ok(())
                } else {
                    Err(EmulationError::ArrayIndexOutOfBounds {
                        index: i64::try_from(index).unwrap_or(i64::MAX),
                        length: len,
                    }
                    .into())
                }
            }
            Some(other) => Err(EmulationError::HeapTypeMismatch {
                expected: "array",
                found: other.kind(),
            }
            .into()),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Gets the length of an array.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid or not an array.
    pub fn get_array_length(&self, heap_ref: HeapRef) -> Result<usize> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get(&heap_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::Array { elements, .. }) => Ok(elements.len()),
            Some(HeapObject::MultiArray { dimensions, .. }) => Ok(dimensions.iter().product()),
            Some(other) => Err(EmulationError::HeapTypeMismatch {
                expected: "array",
                found: other.kind(),
            }
            .into()),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Gets the element type of an array.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid or not an array.
    pub fn get_array_element_type(&self, heap_ref: HeapRef) -> Result<CilFlavor> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get(&heap_ref.id()).map(Arc::as_ref) {
            Some(
                HeapObject::Array { element_type, .. }
                | HeapObject::MultiArray { element_type, .. },
            ) => Ok(element_type.clone()),
            Some(other) => Err(EmulationError::HeapTypeMismatch {
                expected: "array",
                found: other.kind(),
            }
            .into()),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Allocates a byte array on the heap.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_byte_array(&self, data: &[u8]) -> Result<HeapRef> {
        // Each byte becomes a full `EmValue`, so a byte array costs an order of magnitude more
        // host memory than its logical size. Charge for that before expanding.
        self.reserve_elements(data.len())?;
        let mut elements = Vec::new();
        elements.try_reserve_exact(data.len()).map_err(|_| {
            EmulationError::HeapMemoryLimitExceeded {
                current: self.current_size(),
                limit: self.max_size(),
            }
        })?;
        elements.extend(data.iter().map(|&b| EmValue::I32(i32::from(b))));
        self.alloc_array_with_values(CilFlavor::U1, elements)
    }

    /// Gets a byte array from the heap.
    ///
    /// Returns `Ok(None)` if the reference is invalid, not a byte array, or contains
    /// any non-I32 elements (including Symbolic values). This fail-fast behavior
    /// ensures callers don't silently receive partial/corrupted data.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn get_byte_array(&self, heap_ref: HeapRef) -> Result<Option<Vec<u8>>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&heap_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::Array { elements, .. }) => {
                let mut bytes = Vec::with_capacity(elements.len());
                for e in elements {
                    match e {
                        EmValue::I32(n) => bytes.push(*n as u8),
                        _ => return Ok(None),
                    }
                }
                Some(bytes)
            }
            _ => None,
        })
    }

    /// Converts an array's elements to a byte vector, respecting element type.
    ///
    /// Unlike `get_byte_array` which only takes the low byte, this method
    /// properly serializes multi-byte elements (uint32, int64, etc.) to bytes
    /// in little-endian order.
    ///
    /// Returns `Ok(None)` if the reference is invalid, not an array, or contains
    /// non-numeric types.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn get_array_as_bytes(
        &self,
        heap_ref: HeapRef,
        ptr_size: PointerSize,
    ) -> Result<Option<Vec<u8>>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&heap_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::Array {
                elements,
                element_type,
            }) => {
                let element_size = element_type.element_size(ptr_size);
                match element_size {
                    Some(element_size) => {
                        let mut bytes =
                            Vec::with_capacity(elements.len().saturating_mul(element_size));
                        let mut valid = true;
                        for e in elements {
                            match e {
                                EmValue::I32(n) => match element_size {
                                    2 => bytes.extend_from_slice(&(*n as i16).to_le_bytes()),
                                    4 => bytes.extend_from_slice(&n.to_le_bytes()),
                                    _ => bytes.push(*n as u8),
                                },
                                EmValue::I64(n) => {
                                    bytes.extend_from_slice(&n.to_le_bytes());
                                }
                                EmValue::F32(f) => {
                                    bytes.extend_from_slice(&f.to_le_bytes());
                                }
                                EmValue::F64(f) => {
                                    bytes.extend_from_slice(&f.to_le_bytes());
                                }
                                _ => {
                                    valid = false;
                                    break;
                                }
                            }
                        }
                        if valid {
                            Some(bytes)
                        } else {
                            None
                        }
                    }
                    None => None,
                }
            }
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{memory::heap::ManagedHeap, EmValue},
        metadata::typesystem::CilFlavor,
    };

    #[test]
    fn test_heap_alloc_array() {
        let heap = ManagedHeap::new(1024 * 1024);

        let array_ref = heap.alloc_array(CilFlavor::I4, 10).unwrap();
        assert!(heap.contains(array_ref).unwrap());

        let length = heap.get_array_length(array_ref).unwrap();
        assert_eq!(length, 10);

        // Elements should be default initialized
        let elem = heap.get_array_element(array_ref, 0).unwrap();
        assert_eq!(elem, EmValue::I32(0));
    }

    #[test]
    fn test_heap_array_operations() {
        let heap = ManagedHeap::new(1024 * 1024);

        let array_ref = heap.alloc_array(CilFlavor::I4, 5).unwrap();

        heap.set_array_element(array_ref, 2, EmValue::I32(42))
            .unwrap();
        let elem = heap.get_array_element(array_ref, 2).unwrap();
        assert_eq!(elem, EmValue::I32(42));

        // Out of bounds
        assert!(heap.get_array_element(array_ref, 10).is_err());
        assert!(heap
            .set_array_element(array_ref, 10, EmValue::I32(0))
            .is_err());
    }

    // The allocators below take their element count from emulated, attacker-controlled values,
    // so the heap budget has to be consulted before any host memory is committed. These cases
    // assert that: a failure shows up as an OOM-killed or aborted test process rather than an
    // assertion failure, because the rejected length would otherwise be allocated for real.

    /// 64 MiB budget: large enough for ordinary test allocations, small enough that the
    /// hostile lengths below are rejected rather than attempted.
    const HEAP_BUDGET: usize = 64 * 1024 * 1024;

    #[test]
    fn alloc_array_rejects_absurd_length_without_allocating() {
        let heap = ManagedHeap::new(HEAP_BUDGET);
        // The length must be refused before materialisation: constructing the object first
        // would evaluate `vec![EmValue; 2^40]` before any guard could fire.
        assert!(heap.alloc_array(CilFlavor::I4, 1 << 40).is_err());
        assert_eq!(heap.current_size(), 0, "rejected array must not be charged");
    }

    #[test]
    fn alloc_array_rejects_usize_max() {
        let heap = ManagedHeap::new(HEAP_BUDGET);
        // The value a bare `-1 as usize` produces.
        assert!(heap.alloc_array(CilFlavor::I4, usize::MAX).is_err());
    }

    #[test]
    fn alloc_array_still_serves_reasonable_requests() {
        let heap = ManagedHeap::new(HEAP_BUDGET);
        let r = heap
            .alloc_array(CilFlavor::I4, 1000)
            .expect("1000 elements");
        assert_eq!(heap.get_array_length(r).unwrap(), 1000);
    }

    #[test]
    fn alloc_multi_array_rejects_overflowing_dimensions() {
        let heap = ManagedHeap::new(HEAP_BUDGET);
        // The product of these wraps `usize`; `iter().product()` would have silently produced
        // a small number and allocated an array of the wrong size.
        let dims = vec![usize::MAX, 2, 2];
        assert!(heap.alloc_multi_array(CilFlavor::I4, dims).is_err());
    }

    #[test]
    fn alloc_multi_array_rejects_oversized_product() {
        let heap = ManagedHeap::new(HEAP_BUDGET);
        assert!(heap
            .alloc_multi_array(CilFlavor::I4, vec![1 << 20, 1 << 20])
            .is_err());
    }

    #[test]
    fn alloc_byte_array_is_charged_per_emvalue_not_per_byte() {
        let heap = ManagedHeap::new(HEAP_BUDGET);
        // Each byte expands to a full EmValue, so a buffer that looks like it fits by byte
        // count must still be rejected when its real cost exceeds the budget.
        let too_big = vec![0u8; HEAP_BUDGET / 2];
        assert!(heap.alloc_byte_array(&too_big).is_err());
    }

    #[test]
    fn estimated_size_charges_the_real_element_width() {
        let heap = ManagedHeap::new(HEAP_BUDGET);
        heap.alloc_array(CilFlavor::I4, 100).expect("alloc");
        // A hard-coded 8 bytes/element would under-charge by roughly 30x.
        assert!(
            heap.current_size() >= 100 * std::mem::size_of::<EmValue>(),
            "charged {} for 100 elements of {} bytes each",
            heap.current_size(),
            std::mem::size_of::<EmValue>()
        );
    }

    #[test]
    fn reserve_gates_without_charging() {
        let heap = ManagedHeap::new(HEAP_BUDGET);
        assert!(heap.reserve(HEAP_BUDGET * 2).is_err());
        assert!(heap.reserve(1024).is_ok());
        assert_eq!(heap.current_size(), 0, "reserve must not itself account");
    }
}
