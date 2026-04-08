use core::ffi::c_void;

mod ffi;

pub use ffi::RfLsplantMethodDispatchFn;

pub fn init(vm: *mut c_void) -> bool {
    unsafe { ffi::rf_lsplant_init(vm) }
}

pub fn hook(target_art_method: u64, hook_art_method: u64, backup_art_method: u64) -> bool {
    unsafe {
        ffi::rf_lsplant_hook(
            target_art_method as *mut c_void,
            hook_art_method as *mut c_void,
            backup_art_method as *mut c_void,
        )
    }
}

pub fn unhook(target_art_method: u64) -> bool {
    unsafe { ffi::rf_lsplant_unhook(target_art_method as *mut c_void) }
}

pub fn deopt(target_art_method: u64) -> bool {
    unsafe { ffi::rf_lsplant_deopt(target_art_method as *mut c_void) }
}

pub fn is_hooked(target_art_method: u64) -> bool {
    unsafe { ffi::rf_lsplant_is_hooked(target_art_method as *mut c_void) }
}

pub fn hook_method(
    target_method: *mut c_void,
    hooker_object: *mut c_void,
    callback_method: *mut c_void,
) -> *mut c_void {
    unsafe { ffi::rf_lsplant_hook_method(target_method, hooker_object, callback_method) }
}

pub fn unhook_method(target_method: *mut c_void) -> bool {
    unsafe { ffi::rf_lsplant_unhook_method(target_method) }
}

pub fn deopt_method(target_method: *mut c_void) -> bool {
    unsafe { ffi::rf_lsplant_deopt_method(target_method) }
}

pub fn is_method_hooked(target_method: *mut c_void) -> bool {
    unsafe { ffi::rf_lsplant_is_method_hooked(target_method) }
}

pub fn prepare_callback_host() -> bool {
    unsafe { ffi::rf_lsplant_prepare_callback_host() }
}

pub fn hook_method_with_callback(
    target_method: *mut c_void,
    user_data: *mut c_void,
    dispatch: ffi::RfLsplantMethodDispatchFn,
) -> *mut c_void {
    unsafe { ffi::rf_lsplant_hook_method_with_callback(target_method, user_data, Some(dispatch)) }
}

pub fn release_callback_hook(target_method: *mut c_void) -> bool {
    unsafe { ffi::rf_lsplant_release_callback_hook(target_method) }
}
