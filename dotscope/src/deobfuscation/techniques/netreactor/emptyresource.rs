//! .NET Reactor's injected empty `<Assembly>.g.resources`.
//!
//! A .NET Reactor-protected assembly carries a manifest resource named after
//! the assembly, `<Assembly>.g.resources`, that the program never had: a
//! `.resources` container with a valid header and no entries. Nothing reads
//! it, but it is there for everything that lists the assembly's resources -
//! `Assembly.GetManifestResourceNames` returns one more name than the program
//! was built with.
//!
//! # Detection
//!
//! The `<Module>` trial guard proves the assembly is .NET Reactor's (see
//! [`netreactor.antitrial`]), and the resource must be exactly the empty
//! container: a `<Assembly>.g.resources` with entries is a WPF application's
//! own, and is left alone.
//!
//! # Cleanup
//!
//! The resource is removed.
//!
//! [`netreactor.antitrial`]: super::antitrial

use crate::{
    deobfuscation::techniques::{
        netreactor::helpers, Detection, Evidence, Technique, TechniqueCategory,
    },
    CilObject,
};

/// Detects and removes .NET Reactor's empty `<Assembly>.g.resources`.
pub struct NetReactorEmptyResource;

impl Technique for NetReactorEmptyResource {
    fn id(&self) -> &'static str {
        "netreactor.emptyresource"
    }

    fn name(&self) -> &'static str {
        ".NET Reactor Empty Resource Removal"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Neutralization
    }

    fn requires(&self) -> &[&'static str] {
        &["netreactor.antitrial"]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let is_netreactor = helpers::find_trial_checks(assembly)
            .iter()
            .any(|trial| trial.is_on_module_type);
        if !is_netreactor {
            return Detection::new_empty();
        }
        let Some(name) = assembly
            .assembly()
            .map(|identity| format!("{}.g.resources", identity.name))
        else {
            return Detection::new_empty();
        };
        let resources = assembly.resources();
        let Some(resource) = resources.get(&name) else {
            return Detection::new_empty();
        };
        let empty = resources
            .parse_dotnet_resource(&resource)
            .is_some_and(|entries| entries.is_empty());
        if !empty {
            return Detection::new_empty();
        }

        let mut detection = Detection::new_detected(
            vec![Evidence::Resource(format!(
                "{name}: an empty resource container .NET Reactor adds"
            ))],
            None,
        );
        detection
            .cleanup_mut()
            .add_manifest_resource(resource.token);
        detection
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{metadata::validation::ValidationConfig, testkit::fixture};

    fn load(name: &str) -> CilObject {
        CilObject::from_path_with_validation(
            fixture(&format!("packers/netreactor/7.5.0/{name}")),
            ValidationConfig::analysis(),
        )
        .unwrap()
    }

    /// Every protected sample carries the empty container, and it is marked.
    #[test]
    fn the_empty_container_is_marked_for_removal() {
        let detection = NetReactorEmptyResource.detect(&load("reactor_obfuscation.exe"));
        assert!(detection.is_detected());
        assert_eq!(detection.cleanup().manifest_resources_len(), 1);
    }

    /// The unprotected program has no such resource and nothing is marked.
    #[test]
    fn an_unprotected_assembly_is_left_alone() {
        let detection = NetReactorEmptyResource.detect(&load("original.exe"));
        assert!(!detection.is_detected());
    }
}
