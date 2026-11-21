//! Parallel iteration whose outcome does not depend on scheduling.
//!
//! Rayon's `try_for_each` stops at whichever item fails first in time, so over input with
//! several faults, which one an error names changes from run to run. A load or a validation
//! of the same bytes must give the same answer every time.

use rayon::iter::{IndexedParallelIterator, ParallelIterator};

use crate::Result;

/// `try_for_each` that fails with the error of the first failing item in iteration order.
pub trait TryForEachInOrder: IndexedParallelIterator {
    /// Runs `operation` on every item, in parallel, and returns the error of the failing item
    /// with the lowest index, or `Ok(())` when none fails.
    ///
    /// Every item is processed, failing or not: stopping early would leave the outcome to
    /// which items had started when the first error arrived.
    ///
    /// # Errors
    ///
    /// The error `operation` returned for the lowest-indexed item it failed on.
    fn try_for_each_in_order<F>(self, operation: F) -> Result<()>
    where
        F: Fn(Self::Item) -> Result<()> + Sync + Send,
    {
        self.enumerate()
            .filter_map(|(index, item)| operation(item).err().map(|error| (index, error)))
            .min_by_key(|(index, _)| *index)
            .map_or(Ok(()), |(_, error)| Err(error))
    }
}

impl<I: IndexedParallelIterator> TryForEachInOrder for I {}

#[cfg(test)]
mod tests {
    use rayon::prelude::*;

    use super::*;
    use crate::Error;

    #[test]
    fn the_first_failure_in_order_is_the_error() {
        for _ in 0..64 {
            let outcome = (0..10_000u32).into_par_iter().try_for_each_in_order(|n| {
                if n % 997 == 3 {
                    Err(Error::Other(format!("item {n}")))
                } else {
                    Ok(())
                }
            });
            assert_eq!(
                outcome.unwrap_err().to_string(),
                Error::Other("item 3".into()).to_string()
            );
        }
    }

    #[test]
    fn no_failure_is_success() {
        assert!((0..100u32)
            .into_par_iter()
            .try_for_each_in_order(|_| Ok(()))
            .is_ok());
    }
}
