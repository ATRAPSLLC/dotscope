//! # Low-Level API Assembly Analysis
//!
//! **What this example teaches:**
//! - Using low-level APIs to parse .NET assemblies from byte buffers
//! - Direct PE structure parsing with the File API
//! - Working with raw structs like Root, Cor20Header, TablesHeader
//! - Accessing metadata streams (Strings, Blob, etc.) directly
//! - Understanding the internal workings of dotscope
//!
//! **When to use this pattern:**
//! - Building custom parsing tools
//! - Understanding dotscope internals
//! - Working with non-standard assembly formats
//! - Performance-critical parsing scenarios
//!
//! **Prerequisites:**
//! - Strong understanding of PE file format
//! - Familiarity with ECMA-335 metadata structures
//! - Experience with binary parsing concepts

use std::{env, fs, path::Path};

use dotscope::prelude::*;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let prog = args.first().map_or("lowlevel", String::as_str);
    let Some(path_arg) = args.get(1) else {
        eprintln!("Usage: {prog} <path-to-dotnet-assembly>");
        eprintln!();
        eprintln!("This example demonstrates low-level API usage for binary parsing:");
        eprintln!("  • Direct PE structure parsing");
        eprintln!("  • Raw metadata stream access");
        eprintln!("  • Working with byte buffers");
        eprintln!("  • Understanding dotscope internals");
        eprintln!();
        eprintln!("Recommended: {prog} tests/samples/WindowsBase.dll");
        return Ok(());
    };

    let path = Path::new(path_arg);
    println!("🔧 Low-level analysis of: {}", path.display());

    // Step 1: Load the entire assembly into memory as Vec<u8>
    println!("\n=== Step 1: Loading Assembly into Memory ===");
    let assembly_data = fs::read(path)?;
    println!("Loaded {} bytes into memory", assembly_data.len());

    // Step 2: Create File from memory buffer using low-level API
    println!("\n=== Step 2: Parsing PE Structure ===");
    let file = File::from_mem(assembly_data)?;

    // Display basic PE information
    println!("PE Information:");
    println!("  - Data size: {} bytes", file.data().len());

    // Display section information
    println!("  - Sections:");
    for (i, section) in file.sections().iter().enumerate() {
        let name = section.name.as_str();
        println!(
            "    [{}] {} - RVA: 0x{:08X}, Size: 0x{:08X}",
            i, name, section.virtual_address, section.size_of_raw_data
        );
    }

    // Step 3: Parse CLR metadata using low-level Cor20Header struct
    println!("\n=== Step 3: Parsing CLR Header using Cor20Header ===");
    let (clr_rva, clr_size) = file
        .clr()
        .ok_or_else(|| dotscope::Error::Other("File should have CLR runtime header".into()))?;
    println!("CLR Runtime Header: RVA=0x{clr_rva:08X}, Size={clr_size} bytes");

    // Convert RVA to file offset and read CLR header
    let clr_offset = file.rva_to_offset(clr_rva)?;
    let clr_data = file.data_slice(clr_offset, clr_size)?;

    // Parse CLR header using the Cor20Header struct
    let cor20_header = Cor20Header::read(clr_data)?;

    println!("CLR Header Details (using Cor20Header struct):");
    println!("  - Header size: {} bytes", cor20_header.cb);
    println!(
        "  - Runtime version: {}.{}",
        cor20_header.major_runtime_version, cor20_header.minor_runtime_version
    );
    println!("  - Metadata RVA: 0x{:08X}", cor20_header.meta_data_rva);
    println!("  - Metadata size: {} bytes", cor20_header.meta_data_size);
    println!("  - Flags: 0x{:08X}", cor20_header.flags);
    println!(
        "  - Entry point token: 0x{:08X}",
        cor20_header.entry_point_token
    );

    // Step 4: Parse metadata root using the Root struct
    println!("\n=== Step 4: Parsing Metadata Root using Root struct ===");
    let metadata_offset = file.rva_to_offset(cor20_header.meta_data_rva as usize)?;
    let metadata_data = file.data_slice(metadata_offset, cor20_header.meta_data_size as usize)?;

    // Parse metadata root using the Root struct
    let metadata_root = Root::read(metadata_data)?;

    println!("Metadata Root (using Root struct):");
    println!("  - Signature: 0x{:08X} (valid)", metadata_root.signature);
    println!(
        "  - Version: {}.{}",
        metadata_root.major_version, metadata_root.minor_version
    );
    println!("  - Reserved: 0x{:08X}", metadata_root.reserved);
    println!("  - Version string length: {}", metadata_root.length);
    println!("  - Version string: '{}'", metadata_root.version);
    println!("  - Flags: 0x{:04X}", metadata_root.flags);
    println!("  - Number of streams: {}", metadata_root.stream_number);

    // Step 5: Display stream headers from the Root struct
    println!("\n=== Step 5: Stream Headers from Root struct ===");
    for (i, stream_header) in metadata_root.stream_headers.iter().enumerate() {
        println!(
            "  Stream [{}]: '{}' - Offset: 0x{:08X}, Size: {} bytes",
            i, stream_header.name, stream_header.offset, stream_header.size
        );
    }

    // Step 6: Access individual metadata streams using low-level APIs
    println!("\n=== Step 6: Accessing Metadata Streams ===");

    // Find and parse the #Strings stream
    if let Some(strings_stream) = metadata_root
        .stream_headers
        .iter()
        .find(|stream| stream.name == "#Strings")
    {
        println!("\n--- #Strings Stream ---");
        let start = strings_stream.offset as usize;
        let end = start.saturating_add(strings_stream.size as usize);
        let Some(strings_data) = metadata_data.get(start..end) else {
            println!("#Strings stream extends past metadata buffer; skipping");
            return Ok(());
        };

        match Strings::from(strings_data) {
            Ok(strings) => {
                println!(
                    "Successfully parsed #Strings heap ({} bytes)",
                    strings_data.len()
                );

                // Sample some strings from the heap
                println!("Sample strings from heap:");
                for i in &[1, 10, 50, 100] {
                    if let Ok(s) = strings.get(*i) {
                        if !s.is_empty() && s.len() < 50 {
                            println!("  [{i}]: '{s}'");
                        }
                    }
                }
            }
            Err(e) => println!("Failed to parse #Strings: {e}"),
        }
    }

    // Find and parse the #Blob stream
    if let Some(blob_stream) = metadata_root
        .stream_headers
        .iter()
        .find(|stream| stream.name == "#Blob")
    {
        println!("\n--- #Blob Stream ---");
        let start = blob_stream.offset as usize;
        let end = start.saturating_add(blob_stream.size as usize);
        let Some(blob_data) = metadata_data.get(start..end) else {
            println!("#Blob stream extends past metadata buffer; skipping");
            return Ok(());
        };

        match Blob::from(blob_data) {
            Ok(blob) => {
                println!("Successfully parsed #Blob heap ({} bytes)", blob_data.len());

                // Sample some blobs from the heap
                println!("Sample blobs from heap:");
                for i in &[1, 10, 50] {
                    if let Ok(data) = blob.get(*i) {
                        if !data.is_empty() && data.len() <= 16 {
                            println!("  [{}]: {} bytes - {:02X?}", i, data.len(), data);
                        }
                    }
                }
            }
            Err(e) => println!("Failed to parse #Blob: {e}"),
        }
    }

    // Find and parse the #US stream (User Strings)
    if let Some(us_stream) = metadata_root
        .stream_headers
        .iter()
        .find(|stream| stream.name == "#US")
    {
        println!("\n--- #US Stream (User Strings) ---");
        let start = us_stream.offset as usize;
        let end = start.saturating_add(us_stream.size as usize);
        let Some(us_data) = metadata_data.get(start..end) else {
            println!("#US stream extends past metadata buffer; skipping");
            return Ok(());
        };

        match UserStrings::from(us_data) {
            Ok(user_strings) => {
                println!("Successfully parsed #US heap ({} bytes)", us_data.len());

                // Sample some user strings
                println!("Sample user strings from heap:");
                for i in &[1, 10, 50] {
                    if let Ok(s) = user_strings.get(*i) {
                        if !s.is_empty() && s.len() < 50 {
                            println!("  [{}]: '{}'", i, s.to_string_lossy());
                        }
                    }
                }
            }
            Err(e) => println!("Failed to parse #US: {e}"),
        }
    }

    // Find and parse the #~ stream (Tables) using TablesHeader struct
    if let Some(tables_stream) = metadata_root
        .stream_headers
        .iter()
        .find(|stream| stream.name == "#~")
    {
        println!("\n--- #~ Stream (Metadata Tables) using TablesHeader struct ---");
        let start = tables_stream.offset as usize;
        let end = start.saturating_add(tables_stream.size as usize);
        let Some(tables_data) = metadata_data.get(start..end) else {
            println!("#~ stream extends past metadata buffer; skipping");
            return Ok(());
        };

        match TablesHeader::from(tables_data, false) {
            Ok(tables_header) => {
                println!(
                    "Successfully parsed TablesHeader ({} bytes)",
                    tables_data.len()
                );
                println!("Tables Header information:");
                println!(
                    "  - Version: {}.{}",
                    tables_header.major_version, tables_header.minor_version
                );
                println!("  - Valid tables: 0x{:016X}", tables_header.valid);
                println!("  - Sorted tables: 0x{:016X}", tables_header.sorted);
                println!("  - Total table count: {}", tables_header.table_count());

                // Display table summaries
                let summaries = tables_header.table_summary();
                println!("  - Present tables ({} total):", summaries.len());
                for summary in summaries.iter().take(10) {
                    // Show first 10 for brevity
                    println!("    {:?}: {} rows", summary.table_id, summary.row_count);
                }
                if summaries.len() > 10 {
                    println!(
                        "    ... and {} more tables",
                        summaries.len().saturating_sub(10)
                    );
                }
            }
            Err(e) => println!("Failed to parse TablesHeader: {e}"),
        }
    }

    // Step 7: Demonstrate low-level binary parsing with Parser
    println!("\n=== Step 7: Raw Binary Parsing with Parser ===");
    println!("Demonstrating Parser capabilities on raw data:");

    // Create sample binary data
    let sample_data = vec![
        0x42, 0x00, 0x00, 0x00, // u32 little-endian: 66
        0x00, 0x01, // u16 little-endian: 256
        0x85, 0x02, // Compressed uint: 277
        0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00, // String: "Hello"
    ];

    let mut sample_parser = Parser::new(&sample_data);

    let value1 = sample_parser.read_le::<u32>()?;
    let value2 = sample_parser.read_le::<u16>()?;
    let compressed = sample_parser.read_compressed_uint()?;
    let string = sample_parser.read_string_utf8()?;

    println!("Parsed from raw binary data:");
    println!("  - u32 value: {value1}");
    println!("  - u16 value: {value2}");
    println!("  - Compressed uint: {compressed}");
    println!("  - String: '{string}'");

    println!("\n✅ Low-level analysis complete!");
    println!("This example showed how to use the low-level structs (Root, Cor20Header,");
    println!("TablesHeader, etc.) that underlie the high-level CilObject interface for");
    println!("custom analysis scenarios without manual binary parsing.");

    Ok(())
}
