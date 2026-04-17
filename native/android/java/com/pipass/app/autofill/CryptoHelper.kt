package com.pipass.app.autofill

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

object CryptoHelper {

    fun hmacSHA256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    fun aesDecrypt(cipherData: ByteArray, key: ByteArray, iv: ByteArray): ByteArray? {
        return try {
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            cipher.doFinal(cipherData)
        } catch (e: Exception) {
            null
        }
    }

    fun sha256Hex(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray(Charsets.UTF_8))
        return hash.joinToString("") { "%02x".format(it) }
    }

    fun deriveHmacKey(encKeyHex: String): ByteArray {
        val keyData = hexToBytes(encKeyHex)
        val message = "hmac-subkey".toByteArray(Charsets.UTF_8)
        return hmacSHA256(keyData, message)
    }

    fun hkdfExtract(saltHex: String, ikmHex: String): String {
        val saltData = hexToBytes(saltHex)
        val ikmData = hexToBytes(ikmHex)
        val prk = hmacSHA256(saltData, ikmData)
        return prk.joinToString("") { "%02x".format(it) }
    }

    fun hkdfExpand(prkHex: String, info: String, length: Int): String {
        val hashLen = 32
        val n = (length + hashLen - 1) / hashLen
        val okm = StringBuilder()
        var prev = ByteArray(0)
        val infoData = info.toByteArray(Charsets.UTF_8)

        for (i in 1..n) {
            val input = prev + infoData + byteArrayOf(i.toByte())
            val prkData = hexToBytes(prkHex)
            prev = hmacSHA256(prkData, input)
            okm.append(prev.joinToString("") { "%02x".format(it) })
        }

        return okm.substring(0, minOf(length * 2, okm.length))
    }

    fun deriveEntryKey(masterKeyHex: String, entryId: String, entrySaltHex: String): String {
        val prk = hkdfExtract(entrySaltHex, masterKeyHex)
        val context = "pipass-entry-key:$entryId"
        return hkdfExpand(prk, context, 32)
    }

    fun verifyAndDecrypt(ciphertext: String, keyHex: String): String? {
        val bytes = verifyAndDecryptBytes(ciphertext, keyHex) ?: return null
        val result = String(bytes, Charsets.UTF_8)
        wipeBytes(bytes)
        return result
    }

    fun verifyAndDecryptBytes(ciphertext: String, keyHex: String): ByteArray? {
        val parts = ciphertext.split(":")

        if (parts.size == 2) {
            var ivData = hexToBytes(parts[0])
            var cipherData = hexToBytes(parts[1])
            var keyData = hexToBytes(keyHex)
            try {
                return aesDecrypt(cipherData, keyData, ivData)
            } finally {
                wipeBytes(ivData)
                wipeBytes(cipherData)
                wipeBytes(keyData)
            }
        }

        if (parts.size != 3) return null

        val ivHex = parts[0]
        val encHex = parts[1]
        val macHex = parts[2]

        var hmacKey = deriveHmacKey(keyHex)
        val macInput = (ivHex + encHex).toByteArray(Charsets.UTF_8)
        var expectedMac = hmacSHA256(hmacKey, macInput)
        var providedMac = hexToBytes(macHex)

        val macValid = constantTimeEqual(expectedMac, providedMac)

        wipeBytes(hmacKey)
        wipeBytes(expectedMac)
        wipeBytes(providedMac)

        if (!macValid) return null

        var ivData = hexToBytes(ivHex)
        var cipherData = hexToBytes(encHex)
        var keyData = hexToBytes(keyHex)

        try {
            return aesDecrypt(cipherData, keyData, ivData)
        } finally {
            wipeBytes(ivData)
            wipeBytes(cipherData)
            wipeBytes(keyData)
        }
    }

    fun constantTimeEqual(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) {
            diff = diff or (a[i].toInt() xor b[i].toInt())
        }
        return diff == 0
    }

    fun hexToBytes(hex: String): ByteArray {
        val result = ByteArray(hex.length / 2)
        for (i in result.indices) {
            result[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return result
    }

    fun wipeBytes(data: ByteArray) {
        data.fill(0)
    }
}
