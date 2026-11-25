//! Sequential replacement names for obfuscated identifiers.
//!
//! The renamer gives every obfuscated type, method, field and parameter a short,
//! readable name drawn from a per-kind counter. The names carry no
//! meaning beyond their kind; their purpose is to make decompiled output legible
//! and stable, not to recover the original identifiers.

/// Generator for simple sequential names used when renaming obfuscated identifiers.
///
/// Maintains separate counters for types, methods, fields, and parameters.
/// Names are produced in base-26 alphabetic order: `A`, `B`, ..., `Z`, `AA`,
/// `AB`, .... Type names are uppercase; method names are lowercase; field and
/// parameter names carry an `f_` or `p_` prefix respectively.
#[derive(Debug, Default)]
pub struct SimpleNameGenerator {
    types: usize,
    methods: usize,
    fields: usize,
    params: usize,
}

impl SimpleNameGenerator {
    /// Creates a new generator with all counters set to zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Generates the next type name and advances the type counter.
    ///
    /// Names are uppercase base-26: `A`, `B`, ..., `Z`, `AA`, `AB`, ...
    pub fn next_type_name(&mut self) -> String {
        let name = Self::index_to_name(self.types);
        self.types = self.types.saturating_add(1);
        name
    }

    /// Generates the next method name and advances the method counter.
    ///
    /// Names are lowercase base-26: `a`, `b`, ..., `z`, `aa`, `ab`, ...
    pub fn next_method_name(&mut self) -> String {
        let name = Self::index_to_name_lower(self.methods);
        self.methods = self.methods.saturating_add(1);
        name
    }

    /// Generates the next field name and advances the field counter.
    ///
    /// Field names are prefixed with `f_` followed by a lowercase base-26
    /// sequence: `f_a`, `f_b`, ..., `f_z`, `f_aa`, ...
    pub fn next_field_name(&mut self) -> String {
        let name = format!("f_{}", Self::index_to_name_lower(self.fields));
        self.fields = self.fields.saturating_add(1);
        name
    }

    /// Generates the next parameter name and advances the parameter counter.
    ///
    /// Parameter names are prefixed with `p_` followed by a lowercase base-26
    /// sequence: `p_a`, `p_b`, ..., `p_z`, `p_aa`, ...
    pub fn next_param_name(&mut self) -> String {
        let name = format!("p_{}", Self::index_to_name_lower(self.params));
        self.params = self.params.saturating_add(1);
        name
    }

    /// Converts a zero-based index to an uppercase base-26 alphabetic name.
    ///
    /// The mapping is: `0 → "A"`, `25 → "Z"`, `26 → "AA"`, `27 → "AB"`, ...
    #[must_use]
    pub fn index_to_name(mut index: usize) -> String {
        let mut result = String::new();
        loop {
            let remainder = index.checked_rem(26).unwrap_or(0);
            #[allow(clippy::cast_possible_truncation)]
            result.insert(0, (b'A'.saturating_add(remainder as u8)) as char);
            if index < 26 {
                break;
            }
            index = index.checked_div(26).unwrap_or(0).saturating_sub(1);
        }
        result
    }

    /// Converts a zero-based index to a lowercase base-26 alphabetic name.
    ///
    /// Identical to [`index_to_name`](Self::index_to_name) but uses lowercase
    /// letters: `0 → "a"`, `25 → "z"`, `26 → "aa"`, ...
    #[must_use]
    pub fn index_to_name_lower(mut index: usize) -> String {
        let mut result = String::new();
        loop {
            let remainder = index.checked_rem(26).unwrap_or(0);
            #[allow(clippy::cast_possible_truncation)]
            result.insert(0, (b'a'.saturating_add(remainder as u8)) as char);
            if index < 26 {
                break;
            }
            index = index.checked_div(26).unwrap_or(0).saturating_sub(1);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_generator() {
        assert_eq!(SimpleNameGenerator::index_to_name(0), "A");
        assert_eq!(SimpleNameGenerator::index_to_name(25), "Z");
        assert_eq!(SimpleNameGenerator::index_to_name(26), "AA");
        assert_eq!(SimpleNameGenerator::index_to_name(27), "AB");
        assert_eq!(SimpleNameGenerator::index_to_name(702), "AAA");
    }

    #[test]
    fn test_name_generator_lower() {
        assert_eq!(SimpleNameGenerator::index_to_name_lower(0), "a");
        assert_eq!(SimpleNameGenerator::index_to_name_lower(25), "z");
        assert_eq!(SimpleNameGenerator::index_to_name_lower(26), "aa");
    }

    #[test]
    fn test_name_generator_sequential() {
        let mut gen = SimpleNameGenerator::new();
        assert_eq!(gen.next_type_name(), "A");
        assert_eq!(gen.next_type_name(), "B");
        assert_eq!(gen.next_method_name(), "a");
        assert_eq!(gen.next_field_name(), "f_a");
        assert_eq!(gen.next_param_name(), "p_a");
    }
}
