//! Codegen equivalence: code generated for a method computes what the method's SSA computes.

use std::{collections::BTreeMap, sync::Mutex};

use crate::testkit::{
    corpus::{CorpusCheck, CorpusItem},
    equivalence::{regenerate_and_compare, Equivalence},
};

/// Every method lifted with no pass run on it regenerates to code that, lifted again, returns
/// what the SSA returns on the same arguments (see [`regenerate_and_compare`]).
///
/// Methods the evaluator does not compute, the generator's refusals (which keep their
/// original code, and which the codegen validation sweep judges) and runs the evaluator
/// cannot finish are counted as [tallies](CorpusCheck::take_tallies), not findings. A method that
/// does not lift is [`Lifts`](crate::testkit::corpus::Lifts)' finding.
#[derive(Default)]
pub struct CodegenEquivalence {
    tallies: Mutex<BTreeMap<String, usize>>,
}

impl CorpusCheck for CodegenEquivalence {
    fn id(&self) -> &'static str {
        "codegen.equivalence"
    }

    fn run(&self, item: &CorpusItem) -> Vec<String> {
        let Ok(assembly) = item.object() else {
            return Vec::new();
        };
        let mut findings = Vec::new();
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for entry in assembly.methods().iter() {
            let method = entry.value();
            if method.body.get().is_none() {
                continue;
            }
            let Ok(ssa) = method.ssa(assembly) else {
                continue;
            };
            match regenerate_and_compare(&ssa) {
                Equivalence::Equivalent {
                    conclusive,
                    inconclusive,
                } => {
                    *counts.entry("equivalent methods".to_string()).or_default() += 1;
                    *counts.entry("conclusive runs".to_string()).or_default() += conclusive;
                    *counts.entry("inconclusive runs".to_string()).or_default() += inconclusive;
                }
                Equivalence::Unsupported(reason) => {
                    *counts.entry(format!("unsupported: {reason}")).or_default() += 1;
                }
                Equivalence::Refused(_) => {
                    *counts
                        .entry("refused by the generator".to_string())
                        .or_default() += 1;
                }
                Equivalence::Differs(difference) => {
                    let owner = method
                        .declaring_type_rc()
                        .map(|owner| owner.fullname())
                        .unwrap_or_default();
                    findings.push(format!(
                        "{owner}::{} ({:#010x}): {difference}",
                        method.name,
                        method.token.value()
                    ));
                }
            }
        }
        let mut tallies = self
            .tallies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (kind, count) in counts {
            *tallies.entry(kind).or_default() += count;
        }
        findings
    }

    fn take_tallies(&self) -> BTreeMap<String, usize> {
        std::mem::take(
            &mut *self
                .tallies
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}
