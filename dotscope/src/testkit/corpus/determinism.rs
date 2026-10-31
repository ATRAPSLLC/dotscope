//! Determinism: what dotscope makes of an assembly does not depend on how many threads made
//! it.

use rayon::ThreadPoolBuilder;

use crate::{
    cilassembly::CilAssembly,
    formatting::{FormatterOptions, IlFormatter},
    testkit::corpus::{CorpusCheck, CorpusItem},
    CilAssemblyView, CilObject,
};

/// The thread counts the check compares.
const THREADS: [usize; 2] = [1, 8];

/// Every assembly loads to the same model and writes back to the same bytes on one thread as
/// on several: the model compared as its full IL listing, which every type, member,
/// attribute and declaration shows up in, in the order the loader keeps them.
pub struct Deterministic;

/// What one run makes of an assembly: its listing and its bytes written back unchanged, or
/// why it could not.
fn made_of(bytes: &[u8], threads: usize) -> Result<(String, Vec<u8>), String> {
    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|error| error.to_string())?;
    pool.install(|| {
        let object = CilObject::from_mem(bytes.to_vec()).map_err(|error| error.to_string())?;
        let mut listing = Vec::new();
        IlFormatter::new(FormatterOptions::default())
            .format_assembly(&mut listing, &object)
            .map_err(|error| error.to_string())?;
        let view = CilAssemblyView::from_mem(bytes.to_vec()).map_err(|error| error.to_string())?;
        let written = CilAssembly::new(view)
            .to_memory()
            .map_err(|error| error.to_string())?;
        Ok((String::from_utf8_lossy(&listing).into_owned(), written))
    })
}

impl CorpusCheck for Deterministic {
    fn id(&self) -> &'static str {
        "determinism"
    }

    fn run(&self, item: &CorpusItem) -> Vec<String> {
        if item.fixture.reject.is_some() {
            return Vec::new();
        }
        let Ok(bytes) = item.bytes() else {
            return Vec::new();
        };
        let [few, many] = THREADS.map(|threads| made_of(&bytes, threads));
        let mut findings = Vec::new();
        match (few, many) {
            (Ok((listing, written)), Ok((other_listing, other_written))) => {
                if let Some((line, (one, other))) = listing
                    .lines()
                    .zip(other_listing.lines())
                    .enumerate()
                    .find(|(_, (one, other))| one != other)
                {
                    findings.push(format!(
                        "listing line {line} on {} thread(s) reads {one:?}, on {}: {other:?}",
                        THREADS[0], THREADS[1]
                    ));
                } else if listing.lines().count() != other_listing.lines().count() {
                    findings.push("the listings differ in length".to_string());
                }
                if written != other_written {
                    let at = written
                        .iter()
                        .zip(&other_written)
                        .position(|(one, other)| one != other)
                        .unwrap_or(written.len().min(other_written.len()));
                    findings.push(format!(
                        "written back on {} thread(s) and on {}, the bytes differ at {at}",
                        THREADS[0], THREADS[1]
                    ));
                }
            }
            (Err(error), Err(other)) if error == other => {}
            (few, many) => findings.push(format!(
                "on {} thread(s): {:?}; on {}: {:?}",
                THREADS[0],
                few.err(),
                THREADS[1],
                many.err()
            )),
        }
        findings
    }
}
