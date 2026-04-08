#pragma once

#include <stdbool.h>
#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef jobject (*rf_lsplant_method_dispatch_fn)(
    JNIEnv *env,
    jobject hooker,
    jobjectArray args,
    void *user_data,
    jobject backup_method);

bool rf_lsplant_init(JavaVM *vm);
bool rf_lsplant_hook(void *target_art_method, void *hook_art_method, void *backup_art_method);
bool rf_lsplant_unhook(void *target_art_method);
bool rf_lsplant_deopt(void *target_art_method);
bool rf_lsplant_is_hooked(void *target_art_method);
jobject rf_lsplant_hook_method(jobject target_method, jobject hooker_object, jobject callback_method);
bool rf_lsplant_unhook_method(jobject target_method);
bool rf_lsplant_deopt_method(jobject target_method);
bool rf_lsplant_is_method_hooked(jobject target_method);
bool rf_lsplant_prepare_callback_host(void);
jobject rf_lsplant_hook_method_with_callback(
    jobject target_method,
    void *user_data,
    rf_lsplant_method_dispatch_fn dispatch);
bool rf_lsplant_release_callback_hook(jobject target_method);

#ifdef __cplusplus
}
#endif
