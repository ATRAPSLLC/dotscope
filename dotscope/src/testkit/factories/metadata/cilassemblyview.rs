//! Factory methods for CilAssemblyView test validation.
//!
//! Contains helper methods migrated from CilAssemblyView source files
//! for creating and verifying test data related to assembly views.

use crate::metadata::cilassemblyview::CilAssemblyView;

/// Verification of a CilAssemblyView instance.
///
/// Originally from: `src/metadata/cilassemblyview.rs`
pub fn verify_assembly_view_complete(view: &CilAssemblyView) {
    let cor20_header = view.cor20header();
    assert!(cor20_header.meta_data_rva > 0);
    assert!(cor20_header.meta_data_size > 0);
    assert!(cor20_header.cb >= 72); // Minimum COR20 header size
    assert!(cor20_header.major_runtime_version > 0);

    let metadata_root = view.metadata_root();
    assert!(!metadata_root.stream_headers.is_empty());
    assert!(metadata_root.major_version > 0);

    let stream_names: Vec<&str> = metadata_root
        .stream_headers
        .iter()
        .map(|h| h.name.as_str())
        .collect();
    assert!(stream_names.contains(&"#~") || stream_names.contains(&"#-"));
    assert!(stream_names.contains(&"#Strings"));

    let tables = view.tables();
    assert!(tables.is_some());
    let tables = tables.unwrap();
    assert!(tables.major_version > 0 || tables.minor_version > 0);
    assert!(tables.valid > 0);

    let strings = view.strings();
    assert!(strings.is_some());
    let strings = strings.unwrap();
    assert_eq!(strings.get(0).unwrap(), "");

    for i in 1..10 {
        let _ = strings.get(i); // Just verify we can call get without panicking
    }

    if let Some(userstrings) = view.userstrings() {
        let _ = userstrings.get(0); // Should not panic
        let _ = userstrings.get(1); // Should not panic
    }

    if let Some(guids) = view.guids() {
        // If present, verify it's accessible
        // Index 0 is typically null GUID, index 1+ contain actual GUIDs
        for i in 1..5 {
            let _ = guids.get(i); // Should not panic
        }
    }

    let blobs = view.blobs().unwrap();
    assert_eq!(blobs.get(0).unwrap(), &[] as &[u8]);

    let streams = view.streams();
    assert!(!streams.is_empty());
    for stream in streams {
        assert!(!stream.name.is_empty());
        assert!(stream.size > 0);
        assert!(stream.offset < u32::MAX);
    }

    let stream_names: Vec<&str> = streams.iter().map(|s| s.name.as_str()).collect();
    assert!(stream_names.contains(&"#~") || stream_names.contains(&"#-"));
    assert!(stream_names.contains(&"#Strings"));

    for stream in streams {
        match stream.name.as_str() {
            "#~" | "#-" => {
                assert!(stream.size >= 24); // Minimum tables header size
            }
            "#Strings" => {
                assert!(stream.size > 1); // Should contain at least empty string
            }
            "#GUID" => {
                assert!(stream.size % 16 == 0); // GUIDs are 16 bytes each
            }
            "#Blob" => {
                assert!(stream.size > 1); // Should contain at least empty blob
            }
            _ => {}
        }
    }

    let file = view.file();
    assert!(!file.data().is_empty());

    let (clr_rva, clr_size) = file.clr().expect("Should have CLR header");
    assert!(clr_rva > 0);
    assert!(clr_size > 0);
    assert!(clr_size >= 72); // Minimum COR20 header size

    let data = view.data();
    assert!(data.len() > 100);
    assert_eq!(&data[0..2], b"MZ"); // PE signature

    // Verify consistency between different access methods
    assert_eq!(
        view.streams().len(),
        view.metadata_root().stream_headers.len()
    );
    assert_eq!(view.data().len(), view.file().data().len());

    // Test that stream headers match between metadata_root and streams
    let root_streams = &view.metadata_root().stream_headers;
    let direct_streams = view.streams();

    for (i, stream) in direct_streams.iter().enumerate() {
        assert_eq!(stream.name, root_streams[i].name);
        assert_eq!(stream.size, root_streams[i].size);
        assert_eq!(stream.offset, root_streams[i].offset);
    }
}
