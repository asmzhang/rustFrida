#include "rf_lsplant.h"

#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include <sys/system_properties.h>

#include "aliuhook.h"
#include "dex_builder.h"
#include "include/lsplant.hpp"
#include "log.h"

namespace {
JavaVM *g_vm = nullptr;

struct CallbackHookEntry {
    jobject target_method_global = nullptr;
    jobject hooker_global = nullptr;
    jobject backup_method_global = nullptr;
    void *user_data = nullptr;
    rf_lsplant_method_dispatch_fn dispatch = nullptr;
};

std::mutex g_callback_hooks_lock;
std::vector<CallbackHookEntry> g_callback_hooks;

jclass g_callback_host_class = nullptr;
jobject g_callback_host_method = nullptr;
jmethodID g_callback_host_ctor = nullptr;

JNIEnv *GetEnv() {
    if (g_vm == nullptr) {
        return nullptr;
    }

    JNIEnv *env = nullptr;
    if (g_vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK || env == nullptr) {
        return nullptr;
    }

    return env;
}

jbyteArray BuildCallbackDex(JNIEnv *env) {
    using namespace startop::dex;

    DexBuilder dex;
    auto callback_class = dex.MakeClass("rustfrida.CallbackHost");

    const auto object_type = TypeDescriptor::FromClassname("java.lang.Object");
    callback_class.setSuperClass(object_type);

    auto ctor = callback_class.CreateMethod("<init>", Prototype{TypeDescriptor::Void});
    ctor.access_flags(::dex::kAccPublic | ::dex::kAccConstructor);
    const auto super_init = dex.GetOrDeclareMethod(object_type, "<init>", Prototype{TypeDescriptor::Void});
    ctor.AddInstruction(Instruction::InvokeDirect(super_init.id, {}, Value::Parameter(0)));
    ctor.BuildReturn();
    ctor.Encode();

    const auto object_array_type = object_type.ToArray();
    auto callback = callback_class.CreateMethod("callback", Prototype{object_type, object_array_type});
    callback.access_flags(::dex::kAccPublic | ::dex::kAccNative);
    callback.Encode();

    auto image = dex.CreateImage();
    const auto *data = reinterpret_cast<const jbyte *>(image.ptr());
    const auto size = static_cast<jsize>(image.size());

    auto result = env->NewByteArray(size);
    if (result == nullptr) {
        return nullptr;
    }
    env->SetByteArrayRegion(result, 0, size, data);
    return result;
}

jclass LoadCallbackHostClass(JNIEnv *env, jbyteArray dex_bytes) {
    auto byte_buffer_class = env->FindClass("java/nio/ByteBuffer");
    auto byte_buffer_wrap = env->GetStaticMethodID(
        byte_buffer_class, "wrap", "([B)Ljava/nio/ByteBuffer;");
    auto byte_buffer = env->CallStaticObjectMethod(byte_buffer_class, byte_buffer_wrap, dex_bytes);
    if (env->ExceptionCheck() || byte_buffer == nullptr) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        LOGE("LoadCallbackHostClass: ByteBuffer.wrap failed");
        return nullptr;
    }

    auto class_loader_class = env->FindClass("java/lang/ClassLoader");
    auto get_system_loader = env->GetStaticMethodID(
        class_loader_class, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    auto system_loader = env->CallStaticObjectMethod(class_loader_class, get_system_loader);
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        LOGE("LoadCallbackHostClass: getSystemClassLoader failed");
        return nullptr;
    }

    auto dex_loader_class = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    auto dex_loader_ctor = env->GetMethodID(
        dex_loader_class, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    auto dex_loader = env->NewObject(dex_loader_class, dex_loader_ctor, byte_buffer, system_loader);
    if (env->ExceptionCheck() || dex_loader == nullptr) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        LOGE("LoadCallbackHostClass: InMemoryDexClassLoader ctor failed");
        return nullptr;
    }

    auto load_class = env->GetMethodID(
        class_loader_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    auto class_name = env->NewStringUTF("rustfrida.CallbackHost");
    auto callback_class =
        static_cast<jclass>(env->CallObjectMethod(dex_loader, load_class, class_name));
    if (env->ExceptionCheck() || callback_class == nullptr) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        LOGE("LoadCallbackHostClass: loadClass failed");
        return nullptr;
    }

    return callback_class;
}

jobject FindCallbackMethod(JNIEnv *env, jclass callback_class) {
    auto class_class = env->FindClass("java/lang/Class");
    auto get_declared_method = env->GetMethodID(
        class_class, "getDeclaredMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");
    auto method_name = env->NewStringUTF("callback");
    auto object_array_class = env->FindClass("[Ljava/lang/Object;");
    auto param_types = env->NewObjectArray(1, class_class, nullptr);
    env->SetObjectArrayElement(param_types, 0, object_array_class);
    auto method =
        env->CallObjectMethod(callback_class, get_declared_method, method_name, param_types);
    if (env->ExceptionCheck() || method == nullptr) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        LOGE("FindCallbackMethod: getDeclaredMethod failed");
        return nullptr;
    }
    return method;
}

void DestroyCallbackHookEntry(JNIEnv *env, CallbackHookEntry &entry) {
    if (entry.target_method_global != nullptr) {
        env->DeleteGlobalRef(entry.target_method_global);
        entry.target_method_global = nullptr;
    }
    if (entry.hooker_global != nullptr) {
        env->DeleteGlobalRef(entry.hooker_global);
        entry.hooker_global = nullptr;
    }
    if (entry.backup_method_global != nullptr) {
        env->DeleteGlobalRef(entry.backup_method_global);
        entry.backup_method_global = nullptr;
    }
    entry.user_data = nullptr;
    entry.dispatch = nullptr;
}

jobject JNICALL CallbackHostNativeCallback(JNIEnv *env, jobject hooker, jobjectArray args) {
    rf_lsplant_method_dispatch_fn dispatch = nullptr;
    void *user_data = nullptr;
    jobject backup_method = nullptr;
    jsize arg_count = args != nullptr ? env->GetArrayLength(args) : -1;

    {
        std::lock_guard lk(g_callback_hooks_lock);
        for (const auto &entry : g_callback_hooks) {
            if (entry.hooker_global != nullptr && env->IsSameObject(entry.hooker_global, hooker)) {
                dispatch = entry.dispatch;
                user_data = entry.user_data;
                backup_method = entry.backup_method_global != nullptr
                                    ? env->NewLocalRef(entry.backup_method_global)
                                    : nullptr;
                break;
            }
        }
    }

    if (dispatch == nullptr) {
        LOGE("CallbackHostNativeCallback: hooker not found");
        return nullptr;
    }

    LOGI("CallbackHostNativeCallback: hooker=%p user_data=%p argc=%d",
         hooker, user_data, static_cast<int>(arg_count));

    auto result = dispatch(env, hooker, args, user_data, backup_method);
    if (backup_method != nullptr) {
        env->DeleteLocalRef(backup_method);
    }
    return result;
}

bool EnsureCallbackHostReady(JNIEnv *env) {
    if (g_callback_host_class != nullptr && g_callback_host_method != nullptr && g_callback_host_ctor != nullptr) {
        return true;
    }

    auto dex_bytes = BuildCallbackDex(env);
    if (dex_bytes == nullptr) {
        LOGE("EnsureCallbackHostReady: BuildCallbackDex failed");
        return false;
    }

    auto callback_class_local = LoadCallbackHostClass(env, dex_bytes);
    if (callback_class_local == nullptr) {
        return false;
    }

    g_callback_host_ctor = env->GetMethodID(callback_class_local, "<init>", "()V");
    if (g_callback_host_ctor == nullptr || env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        LOGE("EnsureCallbackHostReady: <init> lookup failed");
        return false;
    }

    auto callback_method_local = FindCallbackMethod(env, callback_class_local);
    if (callback_method_local == nullptr) {
        return false;
    }

    const JNINativeMethod methods[] = {
        {
            const_cast<char *>("callback"),
            const_cast<char *>("([Ljava/lang/Object;)Ljava/lang/Object;"),
            reinterpret_cast<void *>(CallbackHostNativeCallback),
        },
    };
    if (env->RegisterNatives(callback_class_local, methods, 1) != JNI_OK || env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        LOGE("EnsureCallbackHostReady: RegisterNatives failed");
        return false;
    }

    g_callback_host_class = static_cast<jclass>(env->NewGlobalRef(callback_class_local));
    g_callback_host_method = env->NewGlobalRef(callback_method_local);
    if (g_callback_host_class == nullptr || g_callback_host_method == nullptr) {
        LOGE("EnsureCallbackHostReady: global ref creation failed");
        return false;
    }

    LOGI("LSPlant callback host prepared");
    return true;
}
}  // namespace

bool rf_lsplant_init(JavaVM *vm) {
    if (vm == nullptr) {
        LOGE("rf_lsplant_init: vm is null");
        return false;
    }

    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK || env == nullptr) {
        LOGE("rf_lsplant_init: GetEnv failed");
        return false;
    }

    g_vm = vm;

    int api_level = android_get_device_api_level();
    if (api_level <= 0) {
        LOGE("rf_lsplant_init: invalid SDK int %d", api_level);
        return false;
    }

    AliuHook::init(api_level);

    lsplant::InitInfo init_info{
        .inline_hooker = InlineHooker,
        .inline_unhooker = InlineUnhooker,
        .art_symbol_resolver = [](std::string_view symbol) -> void * {
            return AliuHook::elf_img.GetSymbolAddress(symbol, false, false);
        },
        .art_symbol_prefix_resolver = [](std::string_view symbol) -> void * {
            return AliuHook::elf_img.GetSymbolAddress(symbol, false, true);
        },
    };

    int res = lsplant::Init(env, init_info);
    if (res == lsplant::INIT_FAILED) {
        LOGE("rf_lsplant_init: lsplant init failed");
        return false;
    }

    return true;
}

bool rf_lsplant_hook(void *target_art_method, void *hook_art_method, void *backup_art_method) {
    if (GetEnv() == nullptr) {
        LOGE("rf_lsplant_hook: env unavailable");
        return false;
    }

    return lsplant::HookRaw(target_art_method, hook_art_method, backup_art_method);
}

bool rf_lsplant_unhook(void *target_art_method) {
    if (GetEnv() == nullptr) {
        LOGE("rf_lsplant_unhook: env unavailable");
        return false;
    }

    return lsplant::UnHookRaw(target_art_method);
}

bool rf_lsplant_deopt(void *target_art_method) {
    if (GetEnv() == nullptr) {
        LOGE("rf_lsplant_deopt: env unavailable");
        return false;
    }

    return lsplant::DeoptimizeRaw(target_art_method);
}

bool rf_lsplant_is_hooked(void *target_art_method) {
    if (GetEnv() == nullptr) {
        return false;
    }

    return lsplant::IsHookedRaw(target_art_method);
}

jobject rf_lsplant_hook_method(jobject target_method, jobject hooker_object, jobject callback_method) {
    JNIEnv *env = GetEnv();
    if (env == nullptr) {
        LOGE("rf_lsplant_hook_method: env unavailable");
        return nullptr;
    }

    return lsplant::Hook(env, target_method, hooker_object, callback_method);
}

bool rf_lsplant_unhook_method(jobject target_method) {
    JNIEnv *env = GetEnv();
    if (env == nullptr) {
        LOGE("rf_lsplant_unhook_method: env unavailable");
        return false;
    }

    return lsplant::UnHook(env, target_method);
}

bool rf_lsplant_deopt_method(jobject target_method) {
    JNIEnv *env = GetEnv();
    if (env == nullptr) {
        LOGE("rf_lsplant_deopt_method: env unavailable");
        return false;
    }

    return lsplant::Deoptimize(env, target_method);
}

bool rf_lsplant_is_method_hooked(jobject target_method) {
    JNIEnv *env = GetEnv();
    if (env == nullptr) {
        return false;
    }

    return lsplant::IsHooked(env, target_method);
}

bool rf_lsplant_prepare_callback_host(void) {
    JNIEnv *env = GetEnv();
    if (env == nullptr) {
        LOGE("rf_lsplant_prepare_callback_host: env unavailable");
        return false;
    }

    return EnsureCallbackHostReady(env);
}

jobject rf_lsplant_hook_method_with_callback(
    jobject target_method,
    void *user_data,
    rf_lsplant_method_dispatch_fn dispatch) {
    JNIEnv *env = GetEnv();
    if (env == nullptr) {
        LOGE("rf_lsplant_hook_method_with_callback: env unavailable");
        return nullptr;
    }
    if (dispatch == nullptr) {
        LOGE("rf_lsplant_hook_method_with_callback: dispatch is null");
        return nullptr;
    }
    if (!EnsureCallbackHostReady(env)) {
        return nullptr;
    }

    auto hooker_local = env->NewObject(g_callback_host_class, g_callback_host_ctor);
    if (hooker_local == nullptr || env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        LOGE("rf_lsplant_hook_method_with_callback: callback host object creation failed");
        return nullptr;
    }

    auto hooker_global = env->NewGlobalRef(hooker_local);
    auto target_global = env->NewGlobalRef(target_method);
    if (hooker_global == nullptr || target_global == nullptr) {
        LOGE("rf_lsplant_hook_method_with_callback: global ref creation failed");
        if (hooker_global != nullptr) {
            env->DeleteGlobalRef(hooker_global);
        }
        if (target_global != nullptr) {
            env->DeleteGlobalRef(target_global);
        }
        return nullptr;
    }

    auto backup_local = lsplant::Hook(env, target_method, hooker_global, g_callback_host_method);
    if (backup_local == nullptr) {
        LOGE("rf_lsplant_hook_method_with_callback: lsplant::Hook failed");
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        env->DeleteGlobalRef(hooker_global);
        env->DeleteGlobalRef(target_global);
        return nullptr;
    }

    LOGI("rf_lsplant_hook_method_with_callback: target=%p hooker=%p backup=%p",
         target_method, hooker_global, backup_local);

    auto backup_global = env->NewGlobalRef(backup_local);
    if (backup_global == nullptr) {
        LOGE("rf_lsplant_hook_method_with_callback: backup global ref creation failed");
        env->DeleteGlobalRef(hooker_global);
        env->DeleteGlobalRef(target_global);
        lsplant::UnHook(env, target_method);
        return nullptr;
    }

    {
        std::lock_guard lk(g_callback_hooks_lock);
        g_callback_hooks.push_back(CallbackHookEntry{
            .target_method_global = target_global,
            .hooker_global = hooker_global,
            .backup_method_global = backup_global,
            .user_data = user_data,
            .dispatch = dispatch,
        });
    }

    return backup_local;
}

bool rf_lsplant_release_callback_hook(jobject target_method) {
    JNIEnv *env = GetEnv();
    if (env == nullptr) {
        LOGE("rf_lsplant_release_callback_hook: env unavailable");
        return false;
    }

    CallbackHookEntry removed;
    bool found = false;
    {
        std::lock_guard lk(g_callback_hooks_lock);
        for (auto it = g_callback_hooks.begin(); it != g_callback_hooks.end(); ++it) {
            if (it->target_method_global != nullptr && env->IsSameObject(it->target_method_global, target_method)) {
                removed = *it;
                g_callback_hooks.erase(it);
                found = true;
                break;
            }
        }
    }

    if (!found) {
        LOGE("rf_lsplant_release_callback_hook: target hook not found");
        return false;
    }

    DestroyCallbackHookEntry(env, removed);
    return true;
}
