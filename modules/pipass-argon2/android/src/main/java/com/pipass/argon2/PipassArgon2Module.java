package com.pipass.argon2;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;

import com.lambdapioneer.argon2kt.Argon2Kt;
import com.lambdapioneer.argon2kt.Argon2KtResult;
import com.lambdapioneer.argon2kt.Argon2Mode;

/**
 * First-party Argon2id bridge. JS still sees NativeModules.RNArgon2.
 *
 * Salt MUST be exactly 64 lowercase/uppercase hex chars (32 bytes).
 * Wrong-length salts are rejected — never padded or truncated — so a
 * JS bug cannot silently derive a different master key.
 */
public class PipassArgon2Module extends ReactContextBaseJavaModule {
    public PipassArgon2Module(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "RNArgon2";
    }

    static byte[] hexToExactly32Bytes(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("salt hex is null");
        }
        String h = hex.trim();
        if (h.startsWith("0x") || h.startsWith("0X")) {
            h = h.substring(2);
        }
        if (!h.matches("(?i)[0-9a-f]{64}")) {
            throw new IllegalArgumentException(
                "salt must be exactly 64 hex characters (32 bytes)"
            );
        }
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) {
            int hi = Character.digit(h.charAt(i * 2), 16);
            int lo = Character.digit(h.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("invalid hex digit in salt at byte " + i);
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    @ReactMethod
    public void argon2(String password, String salt, ReadableMap config, Promise promise) {
        try {
            if (password == null) {
                promise.reject("EINVAL", "password is null");
                return;
            }
            if (salt == null) {
                promise.reject("EINVAL", "salt is null");
                return;
            }

            final byte[] passwordBytes = password.getBytes("UTF-8");
            final byte[] saltBytes = hexToExactly32Bytes(salt);

            int iterations = config != null && config.hasKey("iterations") ? config.getInt("iterations") : 2;
            int memory = config != null && config.hasKey("memory") ? config.getInt("memory") : (32 * 1024);
            int parallelism = config != null && config.hasKey("parallelism") ? config.getInt("parallelism") : 1;
            int hashLength = config != null && config.hasKey("hashLength") ? config.getInt("hashLength") : 32;
            String modeStr = config != null && config.hasKey("mode") ? config.getString("mode") : "argon2id";

            if (iterations < 1) iterations = 1;
            if (memory < 8) memory = 8;
            if (parallelism < 1) parallelism = 1;
            if (hashLength < 16) hashLength = 16;
            if (hashLength > 64) hashLength = 64;

            final Argon2Kt argon2Kt = new Argon2Kt();
            final Argon2KtResult hashResult = argon2Kt.hash(
                    getArgon2Mode(modeStr),
                    passwordBytes,
                    saltBytes,
                    iterations,
                    memory,
                    parallelism,
                    hashLength);

            WritableMap resultMap = new WritableNativeMap();
            resultMap.putString("rawHash", hashResult.rawHashAsHexadecimal(false));
            resultMap.putString("encodedHash", hashResult.encodedOutputAsString());
            promise.resolve(resultMap);
        } catch (Exception exception) {
            promise.reject("E_ARGON2", "Failed to generate argon2 hash", exception);
        }
    }

    public Argon2Mode getArgon2Mode(String mode) {
        if (mode == null) {
            return Argon2Mode.ARGON2_ID;
        }
        switch (mode) {
            case "argon2d":
                return Argon2Mode.ARGON2_D;
            case "argon2i":
                return Argon2Mode.ARGON2_I;
            case "argon2id":
            default:
                return Argon2Mode.ARGON2_ID;
        }
    }
}
