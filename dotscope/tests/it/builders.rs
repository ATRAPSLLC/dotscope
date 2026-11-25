//! Integration tests for high-level builder combinations.
//!
//! This module tests realistic scenarios where multiple builders are used together
//! to create complete .NET types with properties, events, and methods.

use dotscope::{
    metadata::tables::TableId, prelude::*, testkit::fixture, ChangeRefKind, Error, Result,
};

fn get_test_assembly() -> Result<CilAssembly> {
    let path = fixture("WindowsBase.dll");
    CilAssembly::from_path(&path)
}

/// Test creating a complete MVVM ViewModel class with properties and events.
/// This simulates a realistic .NET development scenario.
#[test]
fn test_mvvm_viewmodel_with_properties_and_events() -> Result<()> {
    let mut assembly = get_test_assembly()?;

    // Create a complete ViewModel class similar to:
    // public class PersonViewModel {
    //     public string Name { get; set; }
    //     public int Age { get; set; }
    // }
    let viewmodel_token = ClassBuilder::new("PersonViewModel")
        .public()
        .namespace("MyApp.ViewModels")
        // Add properties
        .auto_property("Name", TypeSignature::String)
        .auto_property("Age", TypeSignature::I4)
        // Add OnPropertyChanged method
        .method(|method| {
            method
                .public()
                .parameter("propertyName", TypeSignature::String)
                .implementation(|body| {
                    body.implementation(|asm| {
                        // Simple implementation that just returns
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        // Add default constructor
        .default_constructor()
        .build(&mut assembly)?;

    // Verify the class was created successfully (TypeDef table)
    assert_eq!(
        viewmodel_token.kind(),
        ChangeRefKind::TableRow(TableId::TypeDef)
    );

    Ok(())
}

/// Test creating a data model class with validation properties and events.
/// This demonstrates complex property patterns with backing logic.
#[test]
fn test_data_model_with_validation() -> Result<()> {
    let mut assembly = get_test_assembly()?;

    // Create a data model similar to:
    // public class Customer {
    //     public string Name { get; set; }
    // }
    let customer_token = ClassBuilder::new("Customer")
        .public()
        .namespace("MyApp.Models")
        // Add auto property
        .auto_property("Name", TypeSignature::String)
        // Add validation method
        .method(|method| {
            method
                .private()
                .parameter("propertyName", TypeSignature::String)
                .parameter("value", TypeSignature::Object)
                .returns(TypeSignature::Boolean)
                .implementation(|body| {
                    body.implementation(|asm| {
                        // Simple validation - just return true
                        asm.ldc_i4_1()? // Load true
                            .ret()?;
                        Ok(())
                    })
                })
        })
        .build(&mut assembly)?;

    // Verify it's a TypeDef table entry
    assert_eq!(
        customer_token.kind(),
        ChangeRefKind::TableRow(TableId::TypeDef)
    );

    Ok(())
}

/// Test creating a complete business service class with events and methods.
/// This demonstrates service-oriented architecture patterns.
#[test]
fn test_business_service_with_events() -> Result<()> {
    let mut assembly = get_test_assembly()?;

    // Create a service similar to:
    // public class CustomerService {
    //     public void AddCustomer(Customer customer) { ... }
    //     public void UpdateCustomer(Customer customer) { ... }
    //     private void OnCustomerAdded(Customer customer) { ... }
    // }
    let service_token = ClassBuilder::new("CustomerService")
        .public()
        .namespace("MyApp.Services")
        // Add business methods
        .method(|method| {
            method
                .public()
                .parameter("customer", TypeSignature::Object)
                .implementation(|body| {
                    body.implementation(|asm| {
                        // Simple method implementation
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        .method(|method| {
            method
                .public()
                .parameter("customer", TypeSignature::Object)
                .implementation(|body| {
                    body.implementation(|asm| {
                        // Simple method implementation
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        // Add private helper method
        .method(|method| {
            method
                .private()
                .parameter("customer", TypeSignature::Object)
                .implementation(|body| {
                    body.implementation(|asm| {
                        // Simple helper method
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        .default_constructor()
        .build(&mut assembly)?;

    // Verify it's a TypeDef table entry
    assert_eq!(
        service_token.kind(),
        ChangeRefKind::TableRow(TableId::TypeDef)
    );

    Ok(())
}

/// Test creating a class with inheritance, implementing common .NET patterns.
/// This tests that ClassBuilder works with inheritance scenarios.
#[test]
fn test_inherited_class_with_virtual_properties() -> Result<()> {
    let mut assembly = get_test_assembly()?;

    // First create a base class
    let base_token = ClassBuilder::new("BaseEntity")
        .public()
        .abstract_class()
        .namespace("MyApp.Entities")
        // Add ID property
        .auto_property("Id", TypeSignature::I4)
        // Add additional property
        .auto_property("Name", TypeSignature::String)
        // Add virtual method
        .method(|method| {
            method
                .public()
                .virtual_method()
                .returns(TypeSignature::Boolean)
                .implementation(|body| {
                    body.implementation(|asm| {
                        asm.ldc_i4_1()? // Return true by default
                            .ret()?;
                        Ok(())
                    })
                })
        })
        .default_constructor()
        .build(&mut assembly)?;

    // Create derived class with inheritance using CodedIndex
    let base_coded_index = CodedIndex::new(
        TableId::TypeDef,
        base_token.row(),
        CodedIndexType::TypeDefOrRef,
    );
    let derived_token = ClassBuilder::new("Customer")
        .public()
        .namespace("MyApp.Entities")
        .inherits(base_coded_index) // Inherit from BaseEntity
        // Add additional properties
        .auto_property("Email", TypeSignature::String)
        .auto_property("IsActive", TypeSignature::Boolean)
        // Override virtual method
        .method(|method| {
            method
                .public()
                .virtual_method()
                .returns(TypeSignature::Boolean)
                .implementation(|body| {
                    body.implementation(|asm| {
                        // Simple validation logic
                        asm.ldc_i4_1()? // Return true
                            .ret()?;
                        Ok(())
                    })
                })
        })
        .default_constructor()
        .build(&mut assembly)?;

    // Verify both are TypeDef table entries
    assert_eq!(base_token.kind(), ChangeRefKind::TableRow(TableId::TypeDef));
    assert_eq!(
        derived_token.kind(),
        ChangeRefKind::TableRow(TableId::TypeDef)
    );

    Ok(())
}

/// Test creating multiple related classes that interact through events.
/// This simulates a complete event-driven system architecture.
#[test]
fn test_event_driven_architecture() -> Result<()> {
    let mut assembly = get_test_assembly()?;

    // Create Publisher class
    let publisher_token = ClassBuilder::new("EventPublisher")
        .public()
        .namespace("MyApp.Events")
        .field("DataChanged", TypeSignature::Object)
        .method(|method| {
            method
                .public()
                .parameter("data", TypeSignature::Object)
                .implementation(|body| {
                    body.implementation(|asm| {
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        .default_constructor()
        .build(&mut assembly)?;

    // Create Subscriber class
    let subscriber_token = ClassBuilder::new("EventSubscriber")
        .public()
        .namespace("MyApp.Events")
        .auto_property("LastData", TypeSignature::Object)
        .method(|method| {
            method
                .public()
                .parameter("sender", TypeSignature::Object)
                .parameter("data", TypeSignature::Object)
                .implementation(|body| {
                    body.implementation(|asm| {
                        // Simple implementation
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        .method(|method| {
            method
                .public()
                .parameter("publisher", TypeSignature::Object)
                .implementation(|body| {
                    body.implementation(|asm| {
                        // Simple implementation
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        .default_constructor()
        .build(&mut assembly)?;

    // Create Coordinator class that uses both
    let coordinator_token = ClassBuilder::new("EventCoordinator")
        .public()
        .namespace("MyApp.Events")
        .auto_property("Publisher", TypeSignature::Object)
        .auto_property("Subscriber", TypeSignature::Object)
        .method(|method| {
            method.public().implementation(|body| {
                body.implementation(|asm| {
                    // Simple implementation
                    asm.ret()?;
                    Ok(())
                })
            })
        })
        .default_constructor()
        .build(&mut assembly)?;

    // Verify all are TypeDef table entries
    assert_eq!(
        publisher_token.kind(),
        ChangeRefKind::TableRow(TableId::TypeDef)
    );
    assert_eq!(
        subscriber_token.kind(),
        ChangeRefKind::TableRow(TableId::TypeDef)
    );
    assert_eq!(
        coordinator_token.kind(),
        ChangeRefKind::TableRow(TableId::TypeDef)
    );

    Ok(())
}

/// Test creating a complex class with all builder types combined.
/// This is the ultimate integration test showing all features working together.
#[test]
fn test_ultimate_integration_all_builders() -> Result<()> {
    let mut assembly = get_test_assembly()?;

    // Create the most comprehensive class possible using all builders
    let ultimate_token = ClassBuilder::new("UltimateClass")
        .public()
        .namespace("MyApp.Ultimate")
        // Multiple auto-properties
        .auto_property("Id", TypeSignature::I4)
        .auto_property("Name", TypeSignature::String)
        .auto_property("IsEnabled", TypeSignature::Boolean)
        // Additional computed property
        .readonly_property("DisplayName", TypeSignature::String)
        // Read-only property
        .readonly_property("CreatedAt", TypeSignature::Object)
        // Multiple event fields
        .field("PropertyChanged", TypeSignature::Object)
        .field("StatusUpdated", TypeSignature::Object)
        // Various methods with different patterns
        .method(|method| {
            method
                .public()
                .parameter("newStatus", TypeSignature::String)
                .implementation(|body| {
                    body.implementation(|asm| {
                        // Simple implementation
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        .method(|method| {
            method
                .protected()
                .parameter("propertyName", TypeSignature::String)
                .implementation(|body| {
                    body.implementation(|asm| {
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        .method(|method| {
            method
                .private()
                .parameter("status", TypeSignature::String)
                .implementation(|body| {
                    body.implementation(|asm| {
                        asm.ret()?;
                        Ok(())
                    })
                })
        })
        // Static method
        .method(|method| {
            method
                .public()
                .static_method()
                .returns(TypeSignature::Object)
                .implementation(|body| {
                    body.implementation(|asm| {
                        asm.ldnull()? // Return null for simplicity
                            .ret()?;
                        Ok(())
                    })
                })
        })
        // Default constructor
        .default_constructor()
        .build(&mut assembly)?;

    // Verify it's a TypeDef table entry
    assert_eq!(
        ultimate_token.kind(),
        ChangeRefKind::TableRow(TableId::TypeDef)
    );

    Ok(())
}

/// A type and then a method appended without explicit lists: the type starts an empty method
/// list at the next MethodDef row and an empty field list at the next Field row, so the
/// method added after it is its own; the method starts an empty parameter list at the next
/// Param row. Nothing that was in the file before changes owner.
#[test]
fn appended_rows_start_empty_lists_at_the_next_row() -> Result<()> {
    let mut assembly = get_test_assembly()?;
    let original = |table| assembly.original_table_row_count(table);
    let (types, methods, fields, params) = (
        original(TableId::TypeDef),
        original(TableId::MethodDef),
        original(TableId::Field),
        original(TableId::Param),
    );

    TypeDefBuilder::new()
        .name("AppendedType")
        .namespace("Test")
        .flags(TypeAttributes::PUBLIC | TypeAttributes::ABSTRACT)
        .build(&mut assembly)?;
    MethodDefBuilder::new()
        .name("AppendedMethod")
        .flags(0x0006 | 0x0040 | 0x0400) // Public, Virtual, Abstract
        .impl_flags(0x0000) // IL
        .signature(&[0x00, 0x00, 0x01])
        .build(&mut assembly)?;

    let view = CilAssemblyView::from_mem(assembly.to_memory()?)?;
    let missing = |what: &str| Error::Other(format!("the written file has no {what}"));
    let tables = view.tables().ok_or_else(|| missing("tables"))?;
    let typedefs = tables
        .table::<TypeDefRaw>()
        .ok_or_else(|| missing("TypeDef table"))?;
    let methoddefs = tables
        .table::<MethodDefRaw>()
        .ok_or_else(|| missing("MethodDef table"))?;
    let last_type = typedefs
        .get(types)?
        .ok_or_else(|| missing("last original type"))?;
    let appended_type = typedefs
        .get(types + 1)?
        .ok_or_else(|| missing("appended type"))?;
    let appended_method = methoddefs
        .get(methods + 1)?
        .ok_or_else(|| missing("appended method"))?;

    assert_eq!(
        appended_type.method_list,
        methods + 1,
        "the appended method is the type's"
    );
    assert_eq!(
        appended_type.field_list,
        fields + 1,
        "the type owns no field"
    );
    assert_eq!(
        appended_method.param_list,
        params + 1,
        "the method owns no parameter"
    );
    assert!(
        last_type.method_list <= methods + 1 && last_type.field_list <= fields + 1,
        "the last original type keeps its members"
    );
    Ok(())
}
