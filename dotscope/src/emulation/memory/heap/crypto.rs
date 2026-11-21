//! Cryptographic type operations for the managed heap.
//!
//! This module provides operations for CryptoAlgorithm (hash), SymmetricAlgorithm,
//! CryptoTransform (encryptor/decryptor), and KeyDerivation objects on [`ManagedHeap`].

use std::sync::Arc;

#[cfg(feature = "legacy-crypto")]
use crate::utils::{compute_md5, compute_sha1};
use crate::{
    emulation::{
        engine::EmulationError,
        memory::heap::{
            CryptoTransformInfo, HeapObject, KeyDerivationInfo, ManagedHeap, SymmetricAlgorithmInfo,
        },
        HeapRef,
    },
    metadata::token::Token,
    utils::{
        compute_hmac_sha256, compute_hmac_sha512, compute_sha256, compute_sha384, compute_sha512,
    },
    Result,
};

impl ManagedHeap {
    /// Allocates a cryptographic hash algorithm object.
    ///
    /// Used for MD5, SHA1, SHA256, etc.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    pub fn alloc_crypto_algorithm(
        &self,
        algorithm_type: &str,
        type_token: Option<Token>,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::CryptoAlgorithm {
                algorithm_type: algorithm_type.into(),
                accumulated_data: Vec::new(),
                hash_result: None,
                rsa_public_key: None,
                hmac_key: None,
            },
            type_token,
        )
    }

    /// Allocates a keyed HMAC algorithm on the heap with the given key.
    ///
    /// Creates a `CryptoAlgorithm` object with `hmac_key` pre-populated.
    /// Used by `HMACSHA256..ctor(byte[])` and `HMACSHA512..ctor(byte[])`.
    ///
    /// # Arguments
    ///
    /// * `algorithm_type` - Algorithm name (e.g., "HMACSHA256", "HMACSHA512")
    /// * `key` - The HMAC key bytes
    /// * `type_token` - Optional type token for the object
    pub fn alloc_hmac_algorithm(
        &self,
        algorithm_type: &str,
        key: Vec<u8>,
        type_token: Option<Token>,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::CryptoAlgorithm {
                algorithm_type: algorithm_type.into(),
                accumulated_data: Vec::new(),
                hash_result: None,
                rsa_public_key: None,
                hmac_key: Some(key),
            },
            type_token,
        )
    }

    /// Returns the HMAC key from a `CryptoAlgorithm` object, if present.
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned.
    pub fn get_hmac_key(&self, heap_ref: HeapRef) -> Result<Option<Vec<u8>>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::CryptoAlgorithm { hmac_key, .. }) =
            state.objects.get(&heap_ref.id()).map(Arc::as_ref)
        {
            Ok(hmac_key.clone())
        } else {
            Ok(None)
        }
    }

    /// Gets the algorithm type from a crypto algorithm object.
    ///
    /// Returns an `Arc<str>` for efficient, borrow-free access.
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned.
    pub fn get_crypto_algorithm_type(&self, heap_ref: HeapRef) -> Result<Option<Arc<str>>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get(&heap_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::CryptoAlgorithm { algorithm_type, .. }) => {
                Ok(Some(Arc::clone(algorithm_type)))
            }
            _ => Ok(None),
        }
    }

    /// Appends data to a `CryptoAlgorithm`'s accumulated hash buffer.
    ///
    /// Used by `HashAlgorithm.TransformBlock` to feed incremental data.
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned.
    pub fn append_hash_data(&self, heap_ref: HeapRef, data: &[u8]) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::CryptoAlgorithm {
            accumulated_data, ..
        }) = state.objects.get_mut(&heap_ref.id()).map(Arc::make_mut)
        {
            accumulated_data.extend_from_slice(data);
        }
        Ok(())
    }

    /// Finalizes incremental hashing on a `CryptoAlgorithm` object.
    ///
    /// Computes the hash from `accumulated_data` using the stored `algorithm_type`,
    /// stores the result in `hash_result`, and returns a copy.
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned.
    pub fn finalize_hash(&self, heap_ref: HeapRef) -> Result<Option<Vec<u8>>> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::CryptoAlgorithm {
            algorithm_type,
            accumulated_data,
            hash_result,
            hmac_key,
            ..
        }) = state.objects.get_mut(&heap_ref.id()).map(Arc::make_mut)
        {
            let hash = match algorithm_type.as_ref() {
                "HMACSHA256" => {
                    let key = hmac_key.as_deref().unwrap_or(&[]);
                    compute_hmac_sha256(key, accumulated_data)
                }
                "HMACSHA512" => {
                    let key = hmac_key.as_deref().unwrap_or(&[]);
                    compute_hmac_sha512(key, accumulated_data)
                }
                "SHA256" | "SHA256Managed" => compute_sha256(accumulated_data),
                "SHA384" => compute_sha384(accumulated_data),
                "SHA512" => compute_sha512(accumulated_data),
                #[cfg(feature = "legacy-crypto")]
                "SHA1" | "SHA1Managed" => compute_sha1(accumulated_data),
                #[cfg(feature = "legacy-crypto")]
                "MD5" => compute_md5(accumulated_data),
                _ => compute_sha256(accumulated_data),
            };
            *hash_result = Some(hash.clone());
            Ok(Some(hash))
        } else {
            Ok(None)
        }
    }

    /// Returns the stored hash result from a `CryptoAlgorithm` object.
    ///
    /// Available after `finalize_hash` has been called.
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned.
    pub fn get_hash_result(&self, heap_ref: HeapRef) -> Result<Option<Vec<u8>>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::CryptoAlgorithm { hash_result, .. }) =
            state.objects.get(&heap_ref.id()).map(Arc::as_ref)
        {
            Ok(hash_result.clone())
        } else {
            Ok(None)
        }
    }

    /// Stores an RSA public key (modulus, exponent) on a `CryptoAlgorithm` object.
    ///
    /// Used by `RSACryptoServiceProvider.FromXmlString` to import a public key.
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned.
    pub fn set_rsa_public_key(
        &self,
        heap_ref: HeapRef,
        modulus: Vec<u8>,
        exponent: Vec<u8>,
    ) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::CryptoAlgorithm { rsa_public_key, .. }) =
            state.objects.get_mut(&heap_ref.id()).map(Arc::make_mut)
        {
            *rsa_public_key = Some((modulus, exponent));
        }
        Ok(())
    }

    /// Returns the RSA public key (modulus, exponent) from a `CryptoAlgorithm` object.
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned.
    pub fn get_rsa_public_key(&self, heap_ref: HeapRef) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::CryptoAlgorithm { rsa_public_key, .. }) =
            state.objects.get(&heap_ref.id()).map(Arc::as_ref)
        {
            Ok(rsa_public_key.clone())
        } else {
            Ok(None)
        }
    }

    /// Allocates a symmetric encryption algorithm object.
    ///
    /// Used for AES, DES, TripleDES, etc.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    pub fn alloc_symmetric_algorithm(
        &self,
        algorithm_type: &str,
        type_token: Option<Token>,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::SymmetricAlgorithm {
                algorithm_type: algorithm_type.into(),
                key: None,
                iv: None,
                mode: 1,    // CBC
                padding: 2, // PKCS7
            },
            type_token,
        )
    }

    /// Replaces a heap object with a symmetric algorithm object.
    ///
    /// Used by constructor hooks (e.g., `RijndaelManaged..ctor`, `AesManaged..ctor`)
    /// where `newobj` allocates a generic `Object` and the constructor must convert it
    /// to a `SymmetricAlgorithm`.
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned, or an error if the
    /// heap reference is invalid.
    pub fn replace_with_symmetric_algorithm(
        &self,
        heap_ref: HeapRef,
        algorithm_type: &str,
    ) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        let id = heap_ref.id();
        Self::preserve_original_type(&mut state, id);
        if state.objects.contains_key(&id) {
            state.objects.insert(
                id,
                Arc::new(HeapObject::SymmetricAlgorithm {
                    algorithm_type: algorithm_type.into(),
                    key: None,
                    iv: None,
                    mode: 1,    // CBC
                    padding: 2, // PKCS7
                }),
            );
        }
        Ok(())
    }

    /// Sets the key for a symmetric algorithm.
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned, or an error if the
    /// heap reference is invalid or not a symmetric algorithm.
    pub fn set_symmetric_key(&self, heap_ref: HeapRef, key: Vec<u8>) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::SymmetricAlgorithm { key: key_slot, .. }) =
            state.objects.get_mut(&heap_ref.id()).map(Arc::make_mut)
        {
            *key_slot = Some(key);
            return Ok(());
        }
        Err(EmulationError::HeapTypeMismatch {
            expected: "SymmetricAlgorithm",
            found: "other",
        }
        .into())
    }

    /// Sets the IV for a symmetric algorithm.
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned, or an error if the
    /// heap reference is invalid or not a symmetric algorithm.
    pub fn set_symmetric_iv(&self, heap_ref: HeapRef, iv: Vec<u8>) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::SymmetricAlgorithm { iv: iv_slot, .. }) =
            state.objects.get_mut(&heap_ref.id()).map(Arc::make_mut)
        {
            *iv_slot = Some(iv);
            return Ok(());
        }
        Err(EmulationError::HeapTypeMismatch {
            expected: "SymmetricAlgorithm",
            found: "other",
        }
        .into())
    }

    /// Sets the cipher mode for a symmetric algorithm.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the symmetric algorithm object.
    /// * `mode` - Cipher mode (1=CBC, 2=ECB, 4=CFB).
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned.
    pub fn set_symmetric_algorithm_mode(&self, heap_ref: HeapRef, new_mode: u8) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::SymmetricAlgorithm { mode, .. }) =
            state.objects.get_mut(&heap_ref.id()).map(Arc::make_mut)
        {
            *mode = new_mode;
            return Ok(());
        }
        Err(EmulationError::HeapTypeMismatch {
            expected: "SymmetricAlgorithm",
            found: "other",
        }
        .into())
    }

    /// Sets the padding mode for a symmetric algorithm.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the symmetric algorithm object.
    /// * `padding` - Padding mode (1=None, 2=PKCS7, 3=Zeros).
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned.
    pub fn set_symmetric_algorithm_padding(
        &self,
        heap_ref: HeapRef,
        new_padding: u8,
    ) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        if let Some(HeapObject::SymmetricAlgorithm { padding, .. }) =
            state.objects.get_mut(&heap_ref.id()).map(Arc::make_mut)
        {
            *padding = new_padding;
            return Ok(());
        }
        Err(EmulationError::HeapTypeMismatch {
            expected: "SymmetricAlgorithm",
            found: "other",
        }
        .into())
    }

    /// Gets the symmetric algorithm parameters.
    ///
    /// # Returns
    ///
    /// A tuple of (algorithm_type, key, iv) if valid, or `None` otherwise.
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned.
    pub fn get_symmetric_algorithm_info(
        &self,
        heap_ref: HeapRef,
    ) -> Result<Option<SymmetricAlgorithmInfo>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get(&heap_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::SymmetricAlgorithm {
                algorithm_type,
                key,
                iv,
                mode,
                padding,
            }) => Ok(Some((
                algorithm_type.clone(),
                key.clone(),
                iv.clone(),
                *mode,
                *padding,
            ))),
            _ => Ok(None),
        }
    }

    /// Allocates a crypto transform object (encryptor/decryptor).
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    /// Allocates a crypto transform with all parameters needed for encryption/decryption.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm name (e.g., "AES", "DES", "Rijndael")
    /// * `key` - The encryption/decryption key
    /// * `iv` - The initialization vector
    /// * `is_encryptor` - True for encryption, false for decryption
    #[allow(clippy::too_many_arguments)]
    pub fn alloc_crypto_transform(
        &self,
        algorithm: &str,
        key: Vec<u8>,
        iv: Vec<u8>,
        is_encryptor: bool,
        mode: u8,
        padding: u8,
        type_token: Option<Token>,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::CryptoTransform {
                algorithm: algorithm.into(),
                key,
                initial_iv: iv.clone(),
                iv,
                is_encryptor,
                mode,
                padding,
                held_back: Vec::new(),
            },
            type_token,
        )
    }

    /// Gets the crypto transform parameters.
    ///
    /// # Returns
    ///
    /// A tuple of (algorithm, key, iv, is_encryptor) if valid, or `None` otherwise.
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned.
    pub fn get_crypto_transform_info(
        &self,
        heap_ref: HeapRef,
    ) -> Result<Option<CryptoTransformInfo>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get(&heap_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::CryptoTransform {
                algorithm,
                key,
                iv,
                is_encryptor,
                mode,
                padding,
                ..
            }) => Ok(Some((
                algorithm.clone(),
                key.clone(),
                iv.clone(),
                *is_encryptor,
                *mode,
                *padding,
            ))),
            _ => Ok(None),
        }
    }

    /// Updates the initialization vector on a `CryptoTransform` heap object.
    ///
    /// Used by `ICryptoTransform.TransformBlock` to maintain CBC IV chaining
    /// across successive block operations. For encryption the new IV is the
    /// ciphertext block; for decryption the new IV is the original ciphertext
    /// input block.
    ///
    /// Returns `true` if the IV was updated, `false` if the object is not a
    /// `CryptoTransform`.
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned.
    pub fn update_crypto_transform_iv(&self, heap_ref: HeapRef, new_iv: Vec<u8>) -> Result<bool> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get_mut(&heap_ref.id()).map(Arc::make_mut) {
            Some(HeapObject::CryptoTransform { iv, .. }) => {
                *iv = new_iv;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Takes the input a decryptor kept back from its last `TransformBlock`, leaving none.
    ///
    /// Empty when nothing is held back, or the object is not a `CryptoTransform`.
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned.
    pub fn take_crypto_transform_held_back(&self, heap_ref: HeapRef) -> Result<Vec<u8>> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get_mut(&heap_ref.id()).map(Arc::make_mut) {
            Some(HeapObject::CryptoTransform { held_back, .. }) => Ok(std::mem::take(held_back)),
            _ => Ok(Vec::new()),
        }
    }

    /// Records the input a decryptor keeps back from a `TransformBlock` until the next call.
    ///
    /// Returns `false` if the object is not a `CryptoTransform`.
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned.
    pub fn set_crypto_transform_held_back(
        &self,
        heap_ref: HeapRef,
        bytes: Vec<u8>,
    ) -> Result<bool> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get_mut(&heap_ref.id()).map(Arc::make_mut) {
            Some(HeapObject::CryptoTransform { held_back, .. }) => {
                *held_back = bytes;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Returns a transform to the state it was created in, as `TransformFinalBlock` leaves it:
    /// its initial IV, nothing held back.
    ///
    /// Returns `false` if the object is not a `CryptoTransform`.
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned.
    pub fn reset_crypto_transform(&self, heap_ref: HeapRef) -> Result<bool> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get_mut(&heap_ref.id()).map(Arc::make_mut) {
            Some(HeapObject::CryptoTransform {
                iv,
                initial_iv,
                held_back,
                ..
            }) => {
                iv.clone_from(initial_iv);
                held_back.clear();
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Replaces a heap object with a key derivation object.
    ///
    /// This is used by constructor stubs to replace the pre-allocated generic object
    /// with a specialized `KeyDerivation` object storing PBKDF2 parameters.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the object to replace.
    /// * `password` - The password bytes.
    /// * `salt` - The salt bytes.
    /// * `iterations` - The iteration count.
    /// * `hash_algorithm` - The hash algorithm name (e.g., "SHA1", "SHA256").
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned, or an error if the
    /// heap reference is invalid.
    pub fn replace_with_key_derivation(
        &self,
        heap_ref: HeapRef,
        password: Vec<u8>,
        salt: Vec<u8>,
        iterations: u32,
        hash_algorithm: &str,
    ) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        let id = heap_ref.id();
        Self::preserve_original_type(&mut state, id);

        if state.objects.contains_key(&id) {
            state.objects.insert(
                id,
                Arc::new(HeapObject::KeyDerivation {
                    password,
                    salt,
                    iterations,
                    hash_algorithm: hash_algorithm.into(),
                }),
            );
            Ok(())
        } else {
            Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into())
        }
    }

    /// Allocates a key derivation object on the heap.
    ///
    /// Creates a `KeyDerivation` object that stores PBKDF2 parameters.
    /// Used by `Rfc2898DeriveBytes` and `PasswordDeriveBytes` stubs.
    ///
    /// # Arguments
    ///
    /// * `password` - The password bytes.
    /// * `salt` - The salt bytes.
    /// * `iterations` - The iteration count.
    /// * `hash_algorithm` - The hash algorithm name (e.g., "SHA1", "SHA256").
    ///
    /// # Returns
    ///
    /// A [`HeapRef`] pointing to the new key derivation object.
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    pub fn alloc_key_derivation(
        &self,
        password: Vec<u8>,
        salt: Vec<u8>,
        iterations: u32,
        hash_algorithm: &str,
        type_token: Option<Token>,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::KeyDerivation {
                password,
                salt,
                iterations,
                hash_algorithm: hash_algorithm.into(),
            },
            type_token,
        )
    }

    /// Gets the key derivation parameters from a key derivation object.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the key derivation object.
    ///
    /// # Returns
    ///
    /// A tuple of (password, salt, iterations, hash_algorithm) if the reference
    /// points to a `KeyDerivation`, or `None` otherwise.
    ///
    /// # Errors
    ///
    /// Returns `LockPoisoned` if the internal `RwLock` is poisoned.
    pub fn get_key_derivation_params(
        &self,
        heap_ref: HeapRef,
    ) -> Result<Option<KeyDerivationInfo>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get(&heap_ref.id()).map(Arc::as_ref) {
            Some(HeapObject::KeyDerivation {
                password,
                salt,
                iterations,
                hash_algorithm,
            }) => Ok(Some((
                password.clone(),
                salt.clone(),
                *iterations,
                hash_algorithm.clone(),
            ))),
            _ => Ok(None),
        }
    }
}
