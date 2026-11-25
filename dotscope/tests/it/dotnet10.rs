#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

//! .NET 10 runtime assemblies: every one loads, as a `CilAssemblyView` and through
//! `ProjectLoader` with its dependencies, which exercises modern metadata such as nullable
//! reference types, default interface methods and InterfaceImpl custom attributes.

use dotscope::testkit::fixture;

mod full {
    use dotscope::testkit::{compatibility::run_assembly_compatibility_test, fixture};

    /// Every .NET 10 runtime assembly loads, alone and as a project with its dependencies.
    #[test]
    fn every_dotnet10_runtime_assembly_loads() {
        run_assembly_compatibility_test(&fixture("dotnet_10.0"), ".NET 10");
    }
}

/// The core library's structs are value types on every load.
///
/// A type defined in the image gets its base linked by the inheritance pass,
/// which runs beside loaders that may already ask for the type's flavor; a
/// flavor computed before the link was a class for good, so `System.DateTime`
/// read as a reference type on some loads and a struct on others.
#[test]
fn core_library_structs_are_value_types_on_every_load() {
    let corelib = fixture("dotnet_10.0/System.Private.CoreLib.dll");
    let data = std::fs::read(corelib).expect("System.Private.CoreLib.dll");
    for _ in 0..3 {
        let assembly = dotscope::CilObject::from_mem_with_validation(
            data.clone(),
            dotscope::metadata::validation::ValidationConfig::analysis(),
        )
        .expect("loads");
        for name in ["DateTime", "TimeSpan", "Guid", "Decimal", "DayOfWeek"] {
            let flavors: Vec<bool> = assembly
                .types()
                .iter()
                .filter(|entry| {
                    let ty = entry.value();
                    ty.namespace == "System" && ty.name == name && ty.token.table() == 0x02
                })
                .map(|entry| entry.value().flavor().is_value_type())
                .collect();
            assert_eq!(flavors, [true], "System.{name}");
        }
    }
}
