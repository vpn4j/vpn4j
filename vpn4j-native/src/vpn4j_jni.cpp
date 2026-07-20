#include "vpn4j/tun_device.hpp"

#include <jni.h>

#include <memory>
#include <new>
#include <string>

namespace {

constexpr const char* kVersion = "vpn4j-native/1.0.0-SNAPSHOT";

jlong to_handle(vpn4j::TunDevice* ptr) {
    return reinterpret_cast<jlong>(ptr);
}

vpn4j::TunDevice* from_handle(jlong handle) {
    return reinterpret_cast<vpn4j::TunDevice*>(handle);
}

void throw_illegal_state(JNIEnv* env, const char* message) {
    jclass cls = env->FindClass("java/lang/IllegalStateException");
    if (cls != nullptr) {
        env->ThrowNew(cls, message);
    }
}

void throw_illegal_argument(JNIEnv* env, const char* message) {
    jclass cls = env->FindClass("java/lang/IllegalArgumentException");
    if (cls != nullptr) {
        env->ThrowNew(cls, message);
    }
}

}  // namespace

extern "C" JNIEXPORT jlong JNICALL
Java_com_github_vpn4j_nativeapi_TunNative_open(JNIEnv* env, jclass, jstring interfaceName) {
    if (env == nullptr) {
        return 0;
    }
    if (interfaceName == nullptr) {
        throw_illegal_argument(env, "interfaceName is null");
        return 0;
    }
    const char* chars = env->GetStringUTFChars(interfaceName, nullptr);
    if (chars == nullptr) {
        return 0;
    }
    std::string name{chars};
    env->ReleaseStringUTFChars(interfaceName, chars);

    auto device = std::make_unique<vpn4j::TunDevice>(std::move(name));
    vpn4j::Status st = device->open_device();
    if (!st.ok()) {
        throw_illegal_state(env, st.message.c_str());
        return 0;
    }
    return to_handle(device.release());
}

extern "C" JNIEXPORT void JNICALL
Java_com_github_vpn4j_nativeapi_TunNative_close(JNIEnv*, jclass, jlong handle) {
    vpn4j::TunDevice* device = from_handle(handle);
    delete device;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_github_vpn4j_nativeapi_TunNative_read(
        JNIEnv* env, jclass, jlong handle, jbyteArray dst, jint offset, jint length) {
    vpn4j::TunDevice* device = from_handle(handle);
    if (device == nullptr) {
        throw_illegal_state(env, "null tun handle");
        return -1;
    }
    if (dst == nullptr) {
        throw_illegal_argument(env, "dst is null");
        return -1;
    }
    const jsize capacity = env->GetArrayLength(dst);
    if (offset < 0 || length < 0 || offset > capacity || length > capacity - offset) {
        throw_illegal_argument(env, "dst range invalid");
        return -1;
    }

    // Own a temporary host buffer — no GetPrimitiveArrayCritical on the I/O path.
    auto buf = std::make_unique<std::uint8_t[]>(static_cast<std::size_t>(length));
    int out_n = 0;
    vpn4j::Status st = device->read(buf.get(), 0, length, out_n);
    if (!st.ok()) {
        throw_illegal_state(env, st.message.c_str());
        return -1;
    }
    if (out_n > 0) {
        env->SetByteArrayRegion(dst, offset, out_n, reinterpret_cast<const jbyte*>(buf.get()));
    }
    return out_n;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_github_vpn4j_nativeapi_TunNative_write(
        JNIEnv* env, jclass, jlong handle, jbyteArray src, jint offset, jint length) {
    vpn4j::TunDevice* device = from_handle(handle);
    if (device == nullptr) {
        throw_illegal_state(env, "null tun handle");
        return -1;
    }
    if (src == nullptr) {
        throw_illegal_argument(env, "src is null");
        return -1;
    }
    const jsize capacity = env->GetArrayLength(src);
    if (offset < 0 || length < 0 || offset > capacity || length > capacity - offset) {
        throw_illegal_argument(env, "src range invalid");
        return -1;
    }

    auto buf = std::make_unique<std::uint8_t[]>(static_cast<std::size_t>(length));
    env->GetByteArrayRegion(src, offset, length, reinterpret_cast<jbyte*>(buf.get()));
    int out_n = 0;
    vpn4j::Status st = device->write(buf.get(), 0, length, out_n);
    if (!st.ok()) {
        throw_illegal_state(env, st.message.c_str());
        return -1;
    }
    return out_n;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_github_vpn4j_nativeapi_TunNative_version(JNIEnv* env, jclass) {
    return env->NewStringUTF(kVersion);
}
