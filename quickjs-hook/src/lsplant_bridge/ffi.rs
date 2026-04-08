use core::ffi::c_void;

pub type RfLsplantMethodDispatchFn = unsafe extern "C" fn(
    env: *mut c_void,
    hooker: *mut c_void,
    args: *mut c_void,
    user_data: *mut c_void,
    backup_method: *mut c_void,
) -> *mut c_void;

unsafe extern "C" {
    pub fn rf_lsplant_init(vm: *mut c_void) -> bool;
    pub fn rf_lsplant_hook(
        target_art_method: *mut c_void,
        hook_art_method: *mut c_void,
        backup_art_method: *mut c_void,
    ) -> bool;
    pub fn rf_lsplant_unhook(target_art_method: *mut c_void) -> bool;
    pub fn rf_lsplant_deopt(target_art_method: *mut c_void) -> bool;
    pub fn rf_lsplant_is_hooked(target_art_method: *mut c_void) -> bool;
    pub fn rf_lsplant_hook_method(
        target_method: *mut c_void,
        hooker_object: *mut c_void,
        callback_method: *mut c_void,
    ) -> *mut c_void;
    pub fn rf_lsplant_unhook_method(target_method: *mut c_void) -> bool;
    pub fn rf_lsplant_deopt_method(target_method: *mut c_void) -> bool;
    pub fn rf_lsplant_is_method_hooked(target_method: *mut c_void) -> bool;
    pub fn rf_lsplant_prepare_callback_host() -> bool;
    pub fn rf_lsplant_hook_method_with_callback(
        target_method: *mut c_void,
        user_data: *mut c_void,
        dispatch: Option<RfLsplantMethodDispatchFn>,
    ) -> *mut c_void;
    pub fn rf_lsplant_release_callback_hook(target_method: *mut c_void) -> bool;
}
