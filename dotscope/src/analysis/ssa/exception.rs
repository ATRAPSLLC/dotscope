//! Re-export shim — generic SSA exception handlers live in `analyssa::ir::exception`.
//!
//! CIL-specific construction (`from_exception_handler`) and the
//! `class_token` accessor are provided here, since they reference dotscope
//! metadata types that analyssa doesn't see.

use analyssa::ir::exception::SsaExceptionHandler as AnalyssaSsaExceptionHandler;
// The vocabulary a clause is read in. Re-exported here so a caller reaching for
// dotscope's `SsaExceptionHandler` finds the range, part and kind types it
// answers in without also depending on analyssa by name.
pub use analyssa::ir::exception::{
    BlockRange, ClauseLayout, ClausePart, ExceptionBlocks, ExceptionTableError, HandlerKind,
    LaidOutHandler,
};

use crate::{
    analysis::ssa::target::CilTarget,
    metadata::{
        method::{ExceptionHandler, ExceptionHandlerFlags},
        token::Token,
    },
};

/// CIL-defaulted alias of `analyssa::ir::exception::SsaExceptionHandler`.
pub type SsaExceptionHandler<T = CilTarget> = AnalyssaSsaExceptionHandler<T>;

/// Creates a new SSA exception handler from the original CIL exception handler.
///
/// CIL-specific factory; callers historically used
/// `SsaExceptionHandler::from_exception_handler(...)` (an inherent method on
/// the CIL impl). After the analyssa extraction it's a free function because
/// orphan rules forbid inherent impls on foreign types.
#[must_use]
pub fn from_exception_handler(handler: &ExceptionHandler) -> SsaExceptionHandler {
    let class_token_or_filter = if handler.flags == ExceptionHandlerFlags::EXCEPTION {
        handler
            .handler
            .as_ref()
            .map_or(handler.filter_offset, |t| t.token.value())
    } else {
        handler.filter_offset
    };

    SsaExceptionHandler {
        flags: handler.flags,
        try_offset: handler.try_offset,
        try_length: handler.try_length,
        handler_offset: handler.handler_offset,
        handler_length: handler.handler_length,
        class_token_or_filter,
        // Block ranges are established by SSA construction, which is the only
        // place block indices exist; a clause built straight from the method
        // body maps none of them yet.
        protected_range: None,
        handler_range: None,
        filter_range: None,
        // The CLR hands a handler no choice among clauses.
        selector: None,
    }
}

/// CIL-specific extension methods on `SsaExceptionHandler<CilTarget>`.
pub trait SsaExceptionHandlerCilExt {
    /// Returns the class token for EXCEPTION handlers.
    fn class_token(&self) -> Option<Token>;
}

impl SsaExceptionHandlerCilExt for AnalyssaSsaExceptionHandler<CilTarget> {
    fn class_token(&self) -> Option<Token> {
        if self.flags == ExceptionHandlerFlags::EXCEPTION {
            Some(Token::new(self.class_token_or_filter))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use analyssa::ir::HandlerKind;

    use super::*;

    /// A method-body clause with the given flags and dual-purpose field.
    ///
    /// `handler` is left `None`, which is the state of every clause before type
    /// resolution runs: `filter_offset` then carries the caught type's token for
    /// an `EXCEPTION` clause and the filter's IL offset for a `FILTER` one, which
    /// is precisely the ambiguity `from_exception_handler` resolves.
    fn cil_handler(flags: ExceptionHandlerFlags, filter_offset: u32) -> ExceptionHandler {
        ExceptionHandler {
            flags,
            try_offset: 0,
            try_length: 10,
            handler_offset: 10,
            handler_length: 5,
            filter_offset,
            handler: None,
        }
    }

    #[test]
    fn from_exception_handler_maps_no_block_yet() {
        let converted =
            from_exception_handler(&cil_handler(ExceptionHandlerFlags::EXCEPTION, 0x0100_0001));

        assert_eq!(converted.protected_range, None);
        assert_eq!(converted.handler_range, None);
        assert_eq!(converted.filter_range, None);
        assert!(!converted.has_block_mapping());
    }

    #[test]
    fn catch_carries_its_class_token() {
        let converted =
            from_exception_handler(&cil_handler(ExceptionHandlerFlags::EXCEPTION, 0x0100_0001));

        assert_eq!(converted.kind(), HandlerKind::Catch);
        assert_eq!(converted.class_token(), Some(Token::new(0x0100_0001)));
        assert_eq!(
            converted.filter_offset(),
            None,
            "a catch clause has no filter offset to read"
        );
    }

    #[test]
    fn filter_carries_its_offset() {
        let converted = from_exception_handler(&cil_handler(ExceptionHandlerFlags::FILTER, 0x20));

        assert_eq!(converted.kind(), HandlerKind::Filter);
        assert_eq!(converted.class_token(), None);
        assert_eq!(converted.filter_offset(), Some(0x20));
    }

    #[test]
    fn finally_and_fault_are_neither() {
        for (flags, expected) in [
            (ExceptionHandlerFlags::FINALLY, HandlerKind::Finally),
            (ExceptionHandlerFlags::FAULT, HandlerKind::Fault),
        ] {
            let converted = from_exception_handler(&cil_handler(flags, 0x20));

            assert_eq!(converted.kind(), expected);
            assert_eq!(converted.class_token(), None);
            assert_eq!(
                converted.filter_offset(),
                None,
                "only a filter clause reads the dual-purpose field as an offset"
            );
        }
    }
}
