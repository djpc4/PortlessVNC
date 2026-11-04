//! Bridge to MainActivity.java: calls into the activity (keyboard, file
//! picker, clipboard, Downloads, full screen) and events coming back from it.

use jni::objects::{JByteArray, JClass, JObject, JString, JValue};
use jni::sys::jint;
use jni::JNIEnv;
use parking_lot::Mutex;

#[derive(Debug, Clone)]
pub enum Event {
    /// text typed on the on-screen keyboard
    Text(String),
    /// a key from the on-screen keyboard (Android KEYCODE_*), with its character
    Key { code: i32, down: bool, ch: Option<char> },
    /// a file picked in the picker, or opened with this app
    File { name: String, data: Vec<u8> },
    /// the phone's clipboard text (read when the app gets focus)
    Clipboard(String),
    Back,
    /// the on-screen keyboard was closed by the user
    KeyboardHidden,
}

static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());
/// MainActivity (a global JNI reference owned by NativeActivity)
static ACTIVITY: std::sync::atomic::AtomicPtr<std::ffi::c_void> = std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

pub fn set_activity(ptr: *mut std::ffi::c_void) {
    ACTIVITY.store(ptr, std::sync::atomic::Ordering::Relaxed);
}

pub fn take_events() -> Vec<Event> {
    std::mem::take(&mut *EVENTS.lock())
}

fn push(e: Event) {
    EVENTS.lock().push(e);
    crate::util::request_repaint();
}

/// `static native void nativeEvent(int kind, int code, String text, byte[] data)`
#[no_mangle]
pub extern "system" fn Java_com_portlessvnc_app_MainActivity_nativeEvent<'l>(mut env: JNIEnv<'l>, _class: JClass<'l>, kind: jint, code: jint, text: JString<'l>, data: JByteArray<'l>) {
    let text: String = if text.is_null() { String::new() } else { env.get_string(&text).map(|s| s.into()).unwrap_or_default() };
    let data: Vec<u8> = if data.is_null() { Vec::new() } else { env.convert_byte_array(&data).unwrap_or_default() };
    let ch = text.chars().next();
    push(match kind {
        1 => Event::Text(text),
        2 => Event::Key { code, down: true, ch },
        3 => Event::Key { code, down: false, ch },
        4 => Event::File { name: text, data },
        5 => Event::Clipboard(text),
        6 => Event::Back,
        7 => Event::KeyboardHidden,
        _ => return,
    });
}

/// Run `f` with the JNI environment and the activity object.
fn with_activity<R>(f: impl FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<R>) -> Option<R> {
    let ctx = ndk_context::android_context();
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) }.ok()?;
    let mut env = vm.attach_current_thread().ok()?;
    let ptr = ACTIVITY.load(std::sync::atomic::Ordering::Relaxed);
    if ptr.is_null() {
        return None;
    }
    let activity = unsafe { JObject::from_raw(ptr.cast()) };
    match f(&mut env, &activity) {
        Ok(r) => Some(r),
        Err(e) => {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
            log::warn!("Android call failed: {e}");
            None
        }
    }
}

fn call_void(name: &str, sig: &str, args: &[JValue]) {
    with_activity(|env, a| env.call_method(a, name, sig, args).map(|_| ()));
}

pub fn show_keyboard(show: bool) {
    call_void("showKeyboard", "(Z)V", &[JValue::Bool(show as u8)]);
}

pub fn pick_file() {
    call_void("pickFile", "()V", &[]);
}

pub fn set_clipboard(text: &str) {
    with_activity(|env, a| {
        let s = env.new_string(text)?;
        env.call_method(a, "setClipboard", "(Ljava/lang/String;)V", &[JValue::Object(&s)]).map(|_| ())
    });
}

/// Full screen (system bars hidden) and screen kept on while viewing.
pub fn set_viewing(on: bool) {
    call_void("setViewing", "(Z)V", &[JValue::Bool(on as u8)]);
}

pub fn move_to_back() {
    call_void("moveToBack", "()V", &[]);
}

pub fn toast(text: &str) {
    with_activity(|env, a| {
        let s = env.new_string(text)?;
        env.call_method(a, "toast", "(Ljava/lang/String;)V", &[JValue::Object(&s)]).map(|_| ())
    });
}

/// Copy a received file into the phone's Downloads/PortlessVNC folder.
/// Returns where it went (for the user), or None.
pub fn save_to_downloads(path: &std::path::Path, name: &str) -> Option<String> {
    with_activity(|env, a| {
        let p = env.new_string(path.to_string_lossy())?;
        let n = env.new_string(name)?;
        let r = env.call_method(a, "saveToDownloads", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", &[JValue::Object(&p), JValue::Object(&n)])?.l()?;
        if r.is_null() {
            return Ok(None);
        }
        let s: String = env.get_string(&JString::from(r))?.into();
        Ok(Some(s))
    })
    .flatten()
}

/// Show the last crash's report (Copy / Try again) instead of the app.
pub fn show_crash_report(text: &str) {
    with_activity(|env, a| {
        let s = env.new_string(text)?;
        env.call_method(a, "showCrashReport", "(Ljava/lang/String;)V", &[JValue::Object(&s)]).map(|_| ())
    });
}
/// Screen edges covered by system bars / cutout, and the keyboard height
/// (pixels): top, bottom, left, right, keyboard.
pub fn insets() -> [i32; 5] {
    with_activity(|env, a| {
        let arr = env.call_method(a, "getInsets", "()[I", &[])?.l()?;
        let arr = jni::objects::JIntArray::from(arr);
        let mut r = [0i32; 5];
        env.get_int_array_region(&arr, 0, &mut r)?;
        Ok(r)
    })
    .unwrap_or_default()
}
/// 0 follow the phone, 1 landscape, 2 portrait.
pub fn set_orientation(o: u8) {
    call_void("setOrientation", "(I)V", &[JValue::Int(o as i32)]);
}