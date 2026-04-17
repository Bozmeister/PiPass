package com.pipass.app.autofill

import android.util.Log
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod

/**
 * React Native bridge module for the PiPass Autofill subsystem.
 *
 * This module is the JS ⇄ Kotlin plumbing layer. It exposes two methods to
 * JavaScript:
 *
 *   - getVaultEntriesForAutofill() : Promise<String>
 *       Returns a JSON-encoded array of vault entries, each shaped like:
 *       { "id": "...", "name": "...", "username": "...",
 *         "password": "...", "url": "..." }
 *       Returns "[]" when the vault is locked, empty, or not yet wired.
 *
 *   - isVaultUnlocked() : Boolean
 *       Synchronous query for the lock state.
 *
 * NOTE: This is plumbing only. No real vault data is read or persisted yet —
 * actual integration with the encrypted vault will be added in a follow-up
 * step. The companion object keeps a static reference so the
 * [PiPassAutofillService] (which runs in a different lifecycle than the RN
 * app) can later read the cached snapshot without going through the JS
 * bridge synchronously.
 */
class PiPassAutofillModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    companion object {
        const val NAME = "PiPassAutofillModule"
        private const val TAG = "PiPassAutofillModule"

        // In-memory snapshot the autofill service can read. Volatile because
        // it may be read from the autofill service thread while being written
        // from the RN JS thread.
        @Volatile
        private var cachedVaultJson: String = "[]"

        @Volatile
        private var unlocked: Boolean = false

        /** Read-only accessor for the autofill service. */
        @JvmStatic
        fun snapshotVaultJson(): String = cachedVaultJson

        /** Read-only accessor for the autofill service. */
        @JvmStatic
        fun snapshotUnlocked(): Boolean = unlocked
    }

    override fun getName(): String = NAME

    /**
     * Returns a JSON array of vault entries to the JS caller.
     *
     * Plumbing-only stub: always resolves with the cached snapshot, which
     * starts as "[]". When the vault is reported as locked, resolves with
     * "[]" instead of rejecting — callers should check [isVaultUnlocked]
     * if they need to distinguish "locked" from "empty".
     */
    @ReactMethod
    fun getVaultEntriesForAutofill(promise: Promise) {
        try {
            if (!unlocked) {
                Log.d(TAG, "getVaultEntriesForAutofill: vault locked, returning []")
                promise.resolve("[]")
                return
            }
            Log.d(TAG, "getVaultEntriesForAutofill: returning cached snapshot")
            promise.resolve(cachedVaultJson)
        } catch (t: Throwable) {
            Log.e(TAG, "getVaultEntriesForAutofill: unexpected error", t)
            promise.reject("E_AUTOFILL_BRIDGE", t.message ?: "unknown error", t)
        }
    }

    /**
     * Synchronous check of the vault lock state. Marked as a blocking
     * synchronous method so JS can `const ok = NativeModules....isVaultUnlocked()`
     * without awaiting a Promise.
     */
    @ReactMethod(isBlockingSynchronousMethod = true)
    fun isVaultUnlocked(): Boolean = unlocked
}
