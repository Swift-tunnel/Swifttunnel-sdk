//! C-callable callback registry for state changes, errors, and process detection.

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::ffi::CString;
use std::os::raw::c_void;

// ── Callback type aliases ───────────────────────────────────────────────────

/// `fn(state_code: i32, user_context: *mut c_void)`
pub type StateCallback = Option<unsafe extern "C" fn(i32, *mut c_void)>;

/// `fn(error_code: i32, message: *const i8, user_context: *mut c_void)`
pub type ErrorCallback = Option<unsafe extern "C" fn(i32, *const i8, *mut c_void)>;

/// `fn(process_name: *const i8, added: i32, user_context: *mut c_void)`
pub type ProcessCallback = Option<unsafe extern "C" fn(*const i8, i32, *mut c_void)>;

// ── Send + Sync wrapper for raw pointers ────────────────────────────────────

/// Wrapper so that raw user-context pointers can be stored in a `Mutex`.
/// The caller is responsible for thread-safety of the pointed-to data.
#[derive(Clone, Copy)]
struct SendPtr(*mut c_void);
unsafe impl Send for SendPtr {}
unsafe impl Sync for SendPtr {}

impl Default for SendPtr {
    fn default() -> Self {
        SendPtr(std::ptr::null_mut())
    }
}

// ── Registry ────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct CallbackRegistry {
    state_cb: StateCallback,
    state_ctx: SendPtr,

    error_cb: ErrorCallback,
    error_ctx: SendPtr,

    process_cb: ProcessCallback,
    process_ctx: SendPtr,
}

pub static CALLBACKS: Lazy<Mutex<CallbackRegistry>> =
    Lazy::new(|| Mutex::new(CallbackRegistry::default()));

// ── Registration ────────────────────────────────────────────────────────────

pub fn register_state_callback(cb: StateCallback, ctx: *mut c_void) {
    let mut reg = CALLBACKS.lock();
    reg.state_cb = cb;
    reg.state_ctx = SendPtr(ctx);
}

pub fn register_error_callback(cb: ErrorCallback, ctx: *mut c_void) {
    let mut reg = CALLBACKS.lock();
    reg.error_cb = cb;
    reg.error_ctx = SendPtr(ctx);
}

pub fn register_process_callback(cb: ProcessCallback, ctx: *mut c_void) {
    let mut reg = CALLBACKS.lock();
    reg.process_cb = cb;
    reg.process_ctx = SendPtr(ctx);
}

// ── Invocation helpers ──────────────────────────────────────────────────────

/// Notify the host application that the VPN state changed.
pub fn fire_state_change(state: i32) {
    let reg = CALLBACKS.lock();
    if let Some(cb) = reg.state_cb {
        let ctx = reg.state_ctx.0;
        // Drop lock before calling into foreign code to avoid deadlocks.
        drop(reg);
        unsafe { cb(state, ctx) };
    }
}

/// Notify the host application of an error.
pub fn fire_error(code: i32, msg: &str) {
    let reg = CALLBACKS.lock();
    if let Some(cb) = reg.error_cb {
        let ctx = reg.error_ctx.0;
        drop(reg);
        if let Ok(c_msg) = CString::new(msg) {
            unsafe { cb(code, c_msg.as_ptr(), ctx) };
        }
    }
}

/// Notify the host application that a tunnelled process was detected or removed.
pub fn fire_process_detected(name: &str, added: bool) {
    let reg = CALLBACKS.lock();
    if let Some(cb) = reg.process_cb {
        let ctx = reg.process_ctx.0;
        drop(reg);
        if let Ok(c_name) = CString::new(name) {
            unsafe { cb(c_name.as_ptr(), if added { 1 } else { 0 }, ctx) };
        }
    }
}
