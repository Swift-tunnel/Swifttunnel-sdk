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

/// `fn(event_json: *const i8, user_context: *mut c_void)`
pub type AutoRoutingCallback = Option<unsafe extern "C" fn(*const i8, *mut c_void)>;

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

    auto_routing_cb: AutoRoutingCallback,
    auto_routing_ctx: SendPtr,
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

pub fn register_auto_routing_callback(cb: AutoRoutingCallback, ctx: *mut c_void) {
    let mut reg = CALLBACKS.lock();
    reg.auto_routing_cb = cb;
    reg.auto_routing_ctx = SendPtr(ctx);
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

/// Notify host application of an auto-routing event.
pub fn fire_auto_routing_event(event_json: &str) {
    let reg = CALLBACKS.lock();
    if let Some(cb) = reg.auto_routing_cb {
        let ctx = reg.auto_routing_ctx.0;
        drop(reg);
        if let Ok(c_event) = CString::new(event_json) {
            unsafe { cb(c_event.as_ptr(), ctx) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    use std::ptr;
    use std::sync::atomic::{AtomicI32, Ordering};

    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static STATE_CODE: AtomicI32 = AtomicI32::new(0);
    static ERROR_CODE: AtomicI32 = AtomicI32::new(0);
    static PROCESS_ADDED: AtomicI32 = AtomicI32::new(-1);
    static AUTO_ROUTING_HIT: AtomicI32 = AtomicI32::new(0);
    static LAST_ERROR_MSG: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));
    static LAST_PROCESS_NAME: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));
    static LAST_AUTO_ROUTING_EVENT: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));

    unsafe extern "C" fn state_cb(code: i32, _ctx: *mut c_void) {
        STATE_CODE.store(code, Ordering::Relaxed);
    }

    unsafe extern "C" fn error_cb(code: i32, msg: *const i8, _ctx: *mut c_void) {
        ERROR_CODE.store(code, Ordering::Relaxed);
        let parsed = if msg.is_null() {
            String::new()
        } else {
            CStr::from_ptr(msg).to_string_lossy().to_string()
        };
        *LAST_ERROR_MSG.lock() = parsed;
    }

    unsafe extern "C" fn process_cb(name: *const i8, added: i32, _ctx: *mut c_void) {
        PROCESS_ADDED.store(added, Ordering::Relaxed);
        let parsed = if name.is_null() {
            String::new()
        } else {
            CStr::from_ptr(name).to_string_lossy().to_string()
        };
        *LAST_PROCESS_NAME.lock() = parsed;
    }

    unsafe extern "C" fn auto_routing_cb(event_json: *const i8, _ctx: *mut c_void) {
        AUTO_ROUTING_HIT.fetch_add(1, Ordering::Relaxed);
        let parsed = if event_json.is_null() {
            String::new()
        } else {
            CStr::from_ptr(event_json).to_string_lossy().to_string()
        };
        *LAST_AUTO_ROUTING_EVENT.lock() = parsed;
    }

    #[test]
    fn callbacks_register_fire_and_deregister() {
        let _guard = TEST_LOCK.lock().unwrap();

        STATE_CODE.store(0, Ordering::Relaxed);
        ERROR_CODE.store(0, Ordering::Relaxed);
        PROCESS_ADDED.store(-1, Ordering::Relaxed);
        AUTO_ROUTING_HIT.store(0, Ordering::Relaxed);
        LAST_ERROR_MSG.lock().clear();
        LAST_PROCESS_NAME.lock().clear();
        LAST_AUTO_ROUTING_EVENT.lock().clear();

        register_state_callback(Some(state_cb), ptr::null_mut());
        register_error_callback(Some(error_cb), ptr::null_mut());
        register_process_callback(Some(process_cb), ptr::null_mut());
        register_auto_routing_callback(Some(auto_routing_cb), ptr::null_mut());

        fire_state_change(4);
        fire_error(-10, "vpn failure");
        fire_process_detected("RobloxPlayerBeta.exe", true);
        fire_auto_routing_event("{\"type\":\"relay_switched\"}");

        assert_eq!(STATE_CODE.load(Ordering::Relaxed), 4);
        assert_eq!(ERROR_CODE.load(Ordering::Relaxed), -10);
        assert_eq!(LAST_ERROR_MSG.lock().as_str(), "vpn failure");
        assert_eq!(PROCESS_ADDED.load(Ordering::Relaxed), 1);
        assert_eq!(LAST_PROCESS_NAME.lock().as_str(), "RobloxPlayerBeta.exe");
        assert_eq!(AUTO_ROUTING_HIT.load(Ordering::Relaxed), 1);
        assert_eq!(
            LAST_AUTO_ROUTING_EVENT.lock().as_str(),
            "{\"type\":\"relay_switched\"}"
        );

        register_state_callback(None, ptr::null_mut());
        register_error_callback(None, ptr::null_mut());
        register_process_callback(None, ptr::null_mut());
        register_auto_routing_callback(None, ptr::null_mut());

        fire_state_change(2);
        fire_error(-1, "ignored");
        fire_process_detected("ignored.exe", false);
        fire_auto_routing_event("{\"type\":\"ignored\"}");

        assert_eq!(STATE_CODE.load(Ordering::Relaxed), 4);
        assert_eq!(ERROR_CODE.load(Ordering::Relaxed), -10);
        assert_eq!(PROCESS_ADDED.load(Ordering::Relaxed), 1);
        assert_eq!(AUTO_ROUTING_HIT.load(Ordering::Relaxed), 1);
    }
}
