#include <jni.h>
#include <android/log.h>
#include <string>

#define LOG_TAG "TestAppNative"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C" JNIEXPORT jstring JNICALL
Java_com_asmzhang_testapp_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    ALOGI("stringFromJNI enter");
    std::string hello = "Hello from C++";
    ALOGI("stringFromJNI return: %s", hello.c_str());
    return env->NewStringUTF(hello.c_str());
}
