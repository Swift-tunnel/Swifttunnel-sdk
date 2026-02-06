//! Tokio runtime for async operations.
//!
//! Provides a lazily-initialized global multi-thread runtime used by FFI
//! functions via `runtime().block_on()`.

use once_cell::sync::Lazy;

static RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("swifttunnel-sdk")
        .build()
        .expect("failed to create tokio runtime")
});

/// Returns a reference to the global Tokio runtime.
pub fn runtime() -> &'static tokio::runtime::Runtime {
    &RUNTIME
}
