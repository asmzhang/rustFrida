// ============================================================================
// Standard LSPlant callback host path
// ============================================================================

unsafe fn marshal_js_to_java_object_for_lsplant(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    value: JSValue,
    type_sig: &str,
) -> *mut std::ffi::c_void {
    if value.is_null() || value.is_undefined() {
        return std::ptr::null_mut();
    }

    match type_sig.as_bytes().first().copied().unwrap_or(b'V') {
        b'V' => std::ptr::null_mut(),
        b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' => {
            autobox_primitive_to_jobject(ctx, env, value, type_sig)
                .map(|ptr| ptr as *mut std::ffi::c_void)
                .unwrap_or(std::ptr::null_mut())
        }
        _ => marshal_js_to_jvalue(ctx, env, value, Some(type_sig)) as *mut std::ffi::c_void,
    }
}

unsafe fn build_lsplant_invoke_args(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    original_args: *mut std::ffi::c_void,
    argc: i32,
    argv: *mut ffi::JSValue,
    is_static: bool,
    param_types: &[String],
) -> Result<(*mut std::ffi::c_void, *mut std::ffi::c_void), String> {
    let get_array_length: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);
    let get_object_array_element: GetObjectArrayElementFn =
        jni_fn!(env, GetObjectArrayElementFn, JNI_GET_OBJECT_ARRAY_ELEMENT);
    let new_object_array: NewObjectArrayFn = jni_fn!(env, NewObjectArrayFn, JNI_NEW_OBJECT_ARRAY);
    let set_object_array_element: SetObjectArrayElementFn =
        jni_fn!(env, SetObjectArrayElementFn, JNI_SET_OBJECT_ARRAY_ELEMENT);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);
    let reflect_ids = crate::jsapi::java::reflect::REFLECT_IDS.get();
    let cached_object_class = reflect_ids
        .map(|r| r.object_class)
        .unwrap_or(std::ptr::null_mut());
    let object_class = if cached_object_class.is_null() {
        std::ptr::null_mut()
    } else {
        new_local_ref(env, cached_object_class)
    };
    if object_class.is_null() {
        return Err("failed to resolve java/lang/Object".to_string());
    }

    let param_array = new_object_array(env, param_types.len() as i32, object_class, std::ptr::null_mut());
    delete_local_ref(env, object_class);
    if param_array.is_null() || jni_check_exc(env) {
        return Err("failed to allocate Object[] for LSPlant orig".to_string());
    }

    let receiver = if is_static {
        std::ptr::null_mut()
    } else {
        let receiver = get_object_array_element(env, original_args, 0);
        if receiver.is_null() && jni_check_exc(env) {
            delete_local_ref(env, param_array);
            return Err("failed to read LSPlant receiver".to_string());
        }
        receiver
    };

    let original_len = get_array_length(env, original_args);
    if jni_check_exc(env) {
        if !receiver.is_null() {
            delete_local_ref(env, receiver);
        }
        delete_local_ref(env, param_array);
        return Err("failed to read LSPlant original args length".to_string());
    }

    for (index, type_sig) in param_types.iter().enumerate() {
        let value = if index < argc.max(0) as usize {
            marshal_js_to_java_object_for_lsplant(ctx, env, JSValue(*argv.add(index)), type_sig)
        } else {
            let source_index = if is_static { index } else { index + 1 };
            if source_index < original_len as usize {
                get_object_array_element(env, original_args, source_index as i32)
            } else {
                std::ptr::null_mut()
            }
        };

        if jni_check_exc(env) {
            if !receiver.is_null() {
                delete_local_ref(env, receiver);
            }
            delete_local_ref(env, param_array);
            return Err(format!("failed to build LSPlant arg {}", index));
        }

        set_object_array_element(env, param_array, index as i32, value);
        if !value.is_null() {
            delete_local_ref(env, value);
        }
        if jni_check_exc(env) {
            if !receiver.is_null() {
                delete_local_ref(env, receiver);
            }
            delete_local_ref(env, param_array);
            return Err(format!("failed to set LSPlant arg {}", index));
        }
    }

    Ok((receiver, param_array))
}

unsafe fn invoke_lsplant_backup_method(
    env: JniEnv,
    backup_method: *mut std::ffi::c_void,
    receiver: *mut std::ffi::c_void,
    invoke_args: *mut std::ffi::c_void,
) -> Result<*mut std::ffi::c_void, String> {
    let call_object_method_a: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);

    let get_object_class: GetObjectClassFn = jni_fn!(env, GetObjectClassFn, JNI_GET_OBJECT_CLASS);
    let method_class = get_object_class(env, backup_method);
    if method_class.is_null() {
        return Err("failed to resolve java/lang/reflect/Method".to_string());
    }
    let invoke_name = CString::new("invoke").unwrap();
    let invoke_sig = CString::new("(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;").unwrap();
    let get_method_id: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let invoke_mid = get_method_id(env, method_class, invoke_name.as_ptr(), invoke_sig.as_ptr());
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    delete_local_ref(env, method_class);
    if invoke_mid.is_null() || jni_check_exc(env) {
        return Err("failed to resolve Method.invoke".to_string());
    }

    let invoke_jargs = [receiver as u64, invoke_args as u64];
    let result = call_object_method_a(
        env,
        backup_method,
        invoke_mid,
        invoke_jargs.as_ptr() as *const std::ffi::c_void,
    );
    if jni_check_exc(env) {
        return Err("Method.invoke on LSPlant backup failed".to_string());
    }
    Ok(result)
}

unsafe fn js_call_original_lsplant(
    ctx: *mut ffi::JSContext,
    this_val: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
    art_method_addr: u64,
    backup_method: *mut std::ffi::c_void,
    original_args: *mut std::ffi::c_void,
) -> ffi::JSValue {
    let env = get_js_u64_property(ctx, this_val, "__lsplantEnv") as JniEnv;
    if env.is_null() || backup_method.is_null() || original_args.is_null() {
        return ffi::JS_ThrowInternalError(ctx, b"orig: LSPlant callback context is invalid\0".as_ptr() as *const _);
    }

    let (return_type_sig, is_static, param_types) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => {
                return ffi::JS_ThrowInternalError(ctx, b"orig: hook registry not initialized\0".as_ptr() as *const _);
            }
        };
        let data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => {
                return ffi::JS_ThrowInternalError(ctx, b"orig: hook data not found\0".as_ptr() as *const _);
            }
        };
        (data.return_type_sig.clone(), data.is_static, data.param_types.clone())
    };

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let (receiver, invoke_args) = match build_lsplant_invoke_args(ctx, env, original_args, argc, argv, is_static, &param_types)
    {
        Ok(v) => v,
        Err(msg) => {
            let c_msg = CString::new(msg).unwrap_or_default();
            return ffi::JS_ThrowInternalError(ctx, c_msg.as_ptr());
        }
    };

    let result = invoke_lsplant_backup_method(env, backup_method, receiver, invoke_args);
    if !receiver.is_null() {
        delete_local_ref(env, receiver);
    }
    if !invoke_args.is_null() {
        delete_local_ref(env, invoke_args);
    }

    let result = match result {
        Ok(v) => v,
        Err(msg) => {
            let c_msg = CString::new(msg).unwrap_or_default();
            return ffi::JS_ThrowInternalError(ctx, c_msg.as_ptr());
        }
    };

    if result.is_null() {
        return ffi::qjs_null();
    }
    marshal_local_java_object_to_js(ctx, env, result, Some(&return_type_sig))
}

pub(super) unsafe extern "C" fn java_lsplant_callback(
    env: *mut std::ffi::c_void,
    hooker: *mut std::ffi::c_void,
    args: *mut std::ffi::c_void,
    user_data: *mut std::ffi::c_void,
    backup_method: *mut std::ffi::c_void,
) -> *mut std::ffi::c_void {
    if env.is_null() || args.is_null() || user_data.is_null() {
        return std::ptr::null_mut();
    }

    let _in_flight_guard = InFlightJavaHookGuard::enter();
    let _callback_scope = JavaHookCallbackScope::enter();

    let art_method_addr = user_data as u64;
    let env = env as JniEnv;
    let args_array = args;

    let (ctx_usize, callback_bytes, is_static, return_type_sig, param_types) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(_) => return std::ptr::null_mut(),
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => return std::ptr::null_mut(),
        };
        let hook_data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => return std::ptr::null_mut(),
        };
        (
            hook_data.ctx,
            hook_data.callback_bytes,
            hook_data.is_static,
            hook_data.return_type_sig.clone(),
            hook_data.param_types.clone(),
        )
    };

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let get_array_length: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);
    let get_object_array_element: GetObjectArrayElementFn =
        jni_fn!(env, GetObjectArrayElementFn, JNI_GET_OBJECT_ARRAY_ELEMENT);

    let mut result_obj: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut result_was_set = false;

    invoke_hook_callback_common(
        ctx_usize,
        &callback_bytes,
        "java hook (lsplant)",
        art_method_addr,
        |ctx| {
            let js_ctx = ffi::JS_NewObject(ctx);
            let len = get_array_length(env, args_array);
            if !is_static && len > 0 {
                let receiver = get_object_array_element(env, args_array, 0);
                let receiver_js = if receiver.is_null() {
                    ffi::qjs_null()
                } else {
                    marshal_local_java_object_to_js(ctx, env, receiver, None)
                };
                JSValue(js_ctx).set_property(ctx, "thisObj", JSValue(receiver_js));
            }

            let js_args = ffi::JS_NewArray(ctx);
            let start = if is_static { 0 } else { 1 };
            for index in start..len.max(0) {
                let arg = get_object_array_element(env, args_array, index);
                let type_sig = param_types.get((index - start) as usize).map(|s| s.as_str());
                let js_value = if arg.is_null() {
                    ffi::qjs_null()
                } else {
                    marshal_local_java_object_to_js(ctx, env, arg, type_sig)
                };
                ffi::JS_SetPropertyUint32(ctx, js_args, (index - start) as u32, js_value);
            }
            JSValue(js_ctx).set_property(ctx, "args", JSValue(js_args));

            set_js_u64_property(ctx, js_ctx, "env", env as usize as u64);
            set_js_u64_property(ctx, js_ctx, "__hookArtMethod", art_method_addr);
            set_js_u64_property(ctx, js_ctx, "__lsplantEnv", env as usize as u64);
            set_js_u64_property(ctx, js_ctx, "__lsplantHooker", hooker as usize as u64);
            set_js_u64_property(ctx, js_ctx, "__lsplantArgs", args_array as usize as u64);
            set_js_u64_property(ctx, js_ctx, "__lsplantBackupMethod", backup_method as usize as u64);
            set_js_cfunction_property(ctx, js_ctx, "orig", js_call_original, 0);

            js_ctx
        },
        |ctx, _js_ctx, result| {
            result_was_set = true;
            result_obj = marshal_js_to_java_object_for_lsplant(ctx, env, JSValue(result), &return_type_sig);
        },
    );

    if result_was_set {
        return result_obj;
    }

    let (receiver, invoke_args) = match build_lsplant_invoke_args(
        std::ptr::null_mut(),
        env,
        args_array,
        0,
        std::ptr::null_mut(),
        is_static,
        &param_types,
    ) {
        Ok(v) => v,
        Err(_) => return std::ptr::null_mut(),
    };

    let fallback = invoke_lsplant_backup_method(env, backup_method, receiver, invoke_args);
    if !receiver.is_null() {
        delete_local_ref(env, receiver);
    }
    if !invoke_args.is_null() {
        delete_local_ref(env, invoke_args);
    }

    match fallback {
        Ok(v) => v,
        Err(_) => std::ptr::null_mut(),
    }
}
