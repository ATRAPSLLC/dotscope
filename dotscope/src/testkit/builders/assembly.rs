//! Assembly and AssemblyRef builders for creating mock assembly references
//!
//! This module provides builders for creating AssemblyRef instances with
//! realistic metadata including versioning, culture, and hash information.

use std::sync::{atomic::AtomicU32, Arc};

use crate::metadata::{
    tables::{AssemblyFlags, AssemblyRef, AssemblyRefHash, AssemblyRefRc},
    token::Token,
};

/// Builder for creating mock AssemblyRef instances with realistic metadata
pub struct AssemblyRefBuilder {
    rid: u32,
    name: String,
    culture: Option<String>,
    major_version: u32,
    minor_version: u32,
    build_number: u32,
    revision_number: u32,
    flags: AssemblyFlags,
    hash: Option<AssemblyRefHash>,
}

impl AssemblyRefBuilder {
    pub fn new() -> Self {
        Self {
            rid: 1,
            name: "TestAssembly".to_string(),
            culture: None,
            major_version: 1,
            minor_version: 0,
            build_number: 0,
            revision_number: 0,
            flags: AssemblyFlags::ZERO,
            hash: None,
        }
    }

    pub fn with_rid(mut self, rid: u32) -> Self {
        self.rid = rid;
        self
    }

    pub fn with_name(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }

    pub fn build(self) -> AssemblyRefRc {
        Arc::new(AssemblyRef {
            rid: self.rid,
            token: Token::new(0x23000000 + self.rid),
            offset: self.rid as usize,
            name: self.name.into(),
            culture: self.culture.map(Into::into),
            major_version: self.major_version,
            minor_version: self.minor_version,
            build_number: self.build_number,
            revision_number: self.revision_number,
            flags: self.flags,
            identifier: None,
            hash: self.hash,
            os_platform_id: AtomicU32::new(0),
            os_major_version: AtomicU32::new(0),
            os_minor_version: AtomicU32::new(0),
            processor: AtomicU32::new(0),
            custom_attributes: Default::default(),
        })
    }
}

impl Default for AssemblyRefBuilder {
    fn default() -> Self {
        Self::new()
    }
}
