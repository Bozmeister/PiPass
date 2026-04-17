package com.pipass.app.autofill

import android.app.assist.AssistStructure
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.service.autofill.AutofillService
import android.service.autofill.AutofillValue
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.util.Log
import android.view.autofill.AutofillId
import android.widget.RemoteViews
import com.pipass.app.R
import androidx.biometric.BiometricManager
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject

private const val TAG = "PiPassAutofill"
private const val SESSION_TIMEOUT_MS = 30_000L
private const val SHARED_PREFS_NAME = "group.com.pipass.shared"
private const val VAULT_KEY = "pipass_shared_vault"
private const val MASTER_KEY_KEY = "pipass_master_key"
private const val MAX_RESULTS = 3

class PiPassAutofillService : AutofillService() {

    private var sessionStartMs: Long = 0L
    private val handler = Handler(Looper.getMainLooper())
    private val sessionWipeRunnable = Runnable { wipeSession() }

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        Log.d(TAG, "onFillRequest: received fill request")
        try {
            handleFillRequest(request, cancellationSignal, callback)
        } catch (e: Exception) {
            Log.e(TAG, "onFillRequest: unhandled exception", e)
            try {
                callback.onSuccess(null)
            } catch (cbErr: Exception) {
                Log.e(TAG, "onFillRequest: callback.onSuccess failed after error", cbErr)
            }
        }
    }

    private fun handleFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            Log.d(TAG, "handleFillRequest: no assist structure, returning null")
            callback.onSuccess(null)
            return
        }

        val requestDomain = extractDomain(structure)
        Log.d(TAG, "handleFillRequest: domain=$requestDomain")

        val autofillFields = extractAutofillFields(structure)

        if (autofillFields.usernameId == null && autofillFields.passwordId == null) {
            Log.d(TAG, "handleFillRequest: no username or password fields found")
            callback.onSuccess(null)
            return
        }

        Log.d(TAG, "handleFillRequest: usernameField=${autofillFields.usernameId != null}, passwordField=${autofillFields.passwordId != null}")

        if (!canAuthenticate()) {
            Log.d(TAG, "handleFillRequest: biometric not available")
            callback.onSuccess(null)
            return
        }

        val masterKeyHex = readMasterKey()

        if (masterKeyHex == null) {
            Log.d(TAG, "handleFillRequest: master key not found in shared storage")
            callback.onSuccess(null)
            return
        }

        startSession()

        var masterKeyBytes = CryptoHelper.hexToBytes(masterKeyHex)

        try {
            val vaultJson = readSharedVault()
            if (vaultJson == null) {
                Log.d(TAG, "handleFillRequest: vault not found in shared storage")
                CryptoHelper.wipeBytes(masterKeyBytes)
                wipeSession()
                callback.onSuccess(null)
                return
            }

            val entries = parseVault(vaultJson)
            if (entries.isEmpty()) {
                Log.d(TAG, "handleFillRequest: vault is empty, no entries")
                CryptoHelper.wipeBytes(masterKeyBytes)
                wipeSession()
                callback.onSuccess(null)
                return
            }

            Log.d(TAG, "handleFillRequest: vault has ${entries.size} entries")

            val normalizedRequestDomain = normalizeDomain(requestDomain)

            data class ScoredEntry(
                val entry: VaultEntry,
                val domain: String,
                val score: Int
            )

            val seenKeys = mutableSetOf<String>()
            var scoredEntries = mutableListOf<ScoredEntry>()

            for (entry in entries) {
                val entryDomain = normalizeDomain(entry.url.ifEmpty { entry.title })
                val dedupeKey = "${entry.username}:$entryDomain"
                if (seenKeys.contains(dedupeKey)) continue

                var entryScore = 0

                if (normalizedRequestDomain.isNotEmpty()) {
                    if (entryDomain == normalizedRequestDomain) {
                        entryScore = maxOf(entryScore, 100)
                    } else if (entryDomain.endsWith(".$normalizedRequestDomain") ||
                        normalizedRequestDomain.endsWith(".$entryDomain")) {
                        entryScore = maxOf(entryScore, 50)
                    }
                }

                if (entryScore == 0 && normalizedRequestDomain.isNotEmpty()) continue

                if (entry.updatedAt > 0) {
                    entryScore += 20
                }

                if (entryDomain.isNotEmpty() && normalizedRequestDomain.isNotEmpty()) {
                    val distance = Math.abs(entryDomain.length - normalizedRequestDomain.length)
                    if (distance < 5) {
                        entryScore += 10
                    }
                }

                seenKeys.add(dedupeKey)
                scoredEntries.add(ScoredEntry(entry, entryDomain, entryScore))
            }

            if (scoredEntries.isEmpty() && entries.isNotEmpty()) {
                for (entry in entries) {
                    val entryDomain = normalizeDomain(entry.url.ifEmpty { entry.title })
                    val dedupeKey = "${entry.username}:$entryDomain"
                    if (seenKeys.contains(dedupeKey)) continue
                    seenKeys.add(dedupeKey)
                    scoredEntries.add(ScoredEntry(entry, entryDomain, 0))
                }
                scoredEntries.sortByDescending { it.entry.updatedAt }
            } else {
                scoredEntries.sortByDescending { it.score }
            }

            val topEntries = scoredEntries.take(MAX_RESULTS)
            Log.d(TAG, "handleFillRequest: ${topEntries.size} matching entries after scoring")

            val responseBuilder = FillResponse.Builder()
            var datasetCount = 0

            for (scored in topEntries) {
                val entry = scored.entry

                var entryKeyHex = CryptoHelper.deriveEntryKey(
                    masterKeyHex, entry.id, entry.salt
                )
                var entryKeyBytes = CryptoHelper.hexToBytes(entryKeyHex)

                var decryptedPassword: String? = null
                var decryptedBytes: ByteArray? = null
                try {
                    decryptedBytes = CryptoHelper.verifyAndDecryptBytes(
                        entry.encryptedPassword, entryKeyHex
                    )
                    if (decryptedBytes != null) {
                        decryptedPassword = String(decryptedBytes, Charsets.UTF_8)
                    }
                } catch (decryptErr: Exception) {
                    Log.e(TAG, "handleFillRequest: decryption failed for entry=${entry.id}", decryptErr)
                } finally {
                    CryptoHelper.wipeBytes(entryKeyBytes)
                    entryKeyHex = ""
                    if (decryptedBytes != null) {
                        CryptoHelper.wipeBytes(decryptedBytes)
                    }
                }

                if (decryptedPassword == null) {
                    Log.d(TAG, "handleFillRequest: skipping entry=${entry.id}, decryption returned null")
                    continue
                }

                val displayTitle = entry.title.ifEmpty { scored.domain }

                val dataset = buildDataset(
                    autofillFields,
                    entry.username,
                    decryptedPassword,
                    displayTitle
                )

                decryptedPassword = ""

                if (dataset != null) {
                    responseBuilder.addDataset(dataset)
                    datasetCount++
                }
            }

            CryptoHelper.wipeBytes(masterKeyBytes)

            if (datasetCount > 0) {
                val saveIds = mutableListOf<AutofillId>()
                if (autofillFields.usernameId != null) saveIds.add(autofillFields.usernameId!!)
                if (autofillFields.passwordId != null) saveIds.add(autofillFields.passwordId!!)

                if (saveIds.isNotEmpty()) {
                    try {
                        responseBuilder.setSaveInfo(
                            SaveInfo.Builder(
                                SaveInfo.SAVE_DATA_TYPE_USERNAME or SaveInfo.SAVE_DATA_TYPE_PASSWORD,
                                saveIds.toTypedArray()
                            ).build()
                        )
                    } catch (saveErr: Exception) {
                        Log.e(TAG, "handleFillRequest: error setting SaveInfo", saveErr)
                    }
                }

                Log.d(TAG, "handleFillRequest: returning $datasetCount datasets")
                callback.onSuccess(responseBuilder.build())
            } else {
                Log.d(TAG, "handleFillRequest: no datasets built, returning null")
                callback.onSuccess(null)
            }
        } catch (e: Exception) {
            Log.e(TAG, "handleFillRequest: error during vault processing", e)
            CryptoHelper.wipeBytes(masterKeyBytes)
            wipeSession()
            callback.onSuccess(null)
        }
    }

    override fun onSaveRequest(
        request: SaveRequest,
        callback: SaveCallback
    ) {
        Log.d(TAG, "onSaveRequest: received save request")
        try {
            val structure = request.fillContexts.lastOrNull()?.structure
            if (structure != null) {
                val savedFields = extractSaveFields(structure)
                val domain = extractDomain(structure)
                val maskedUser = savedFields.username?.let {
                    if (it.length > 3) "${it.take(3)}***" else "***"
                } ?: "null"
                val hasPass = if (savedFields.password != null) "yes(${savedFields.password!!.length}chars)" else "null"
                Log.d(TAG, "onSaveRequest: domain=$domain, username=$maskedUser, password=$hasPass")
            } else {
                Log.d(TAG, "onSaveRequest: no assist structure available")
            }
            callback.onSuccess()
        } catch (e: Exception) {
            Log.e(TAG, "onSaveRequest: error", e)
            try {
                callback.onSuccess()
            } catch (cbErr: Exception) {
                Log.e(TAG, "onSaveRequest: callback.onSuccess failed after error", cbErr)
            }
        }
    }

    override fun onConnected() {
        Log.d(TAG, "onConnected: service connected")
        super.onConnected()
    }

    override fun onDisconnected() {
        Log.d(TAG, "onDisconnected: service disconnected, wiping session")
        wipeSession()
        super.onDisconnected()
    }

    override fun onDestroy() {
        Log.d(TAG, "onDestroy: service destroyed, wiping session")
        wipeSession()
        super.onDestroy()
    }

    private fun canAuthenticate(): Boolean {
        return try {
            val biometricManager = BiometricManager.from(this)
            biometricManager.canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG
            ) == BiometricManager.BIOMETRIC_SUCCESS
        } catch (e: Exception) {
            Log.e(TAG, "canAuthenticate: error checking biometric status", e)
            false
        }
    }

    private fun readMasterKey(): String? {
        return try {
            val masterKey = MasterKey.Builder(this)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            val prefs = EncryptedSharedPreferences.create(
                this,
                SHARED_PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )

            val value = prefs.getString(MASTER_KEY_KEY, null)
            if (value == null) {
                Log.d(TAG, "readMasterKey: key not present in prefs")
            }
            value
        } catch (e: Exception) {
            Log.e(TAG, "readMasterKey: error reading master key", e)
            null
        }
    }

    private fun readSharedVault(): String? {
        return try {
            val masterKey = MasterKey.Builder(this)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            val prefs = EncryptedSharedPreferences.create(
                this,
                SHARED_PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )

            val value = prefs.getString(VAULT_KEY, null)
            if (value == null) {
                Log.d(TAG, "readSharedVault: vault not present in prefs")
            }
            value
        } catch (e: Exception) {
            Log.e(TAG, "readSharedVault: error reading vault", e)
            null
        }
    }

    private data class VaultEntry(
        val id: String,
        val title: String,
        val username: String,
        val encryptedPassword: String,
        val url: String,
        val salt: String,
        val updatedAt: Double
    )

    private fun parseVault(vaultJson: String): List<VaultEntry> {
        val entries = mutableListOf<VaultEntry>()
        try {
            val outer = JSONObject(vaultJson)
            val encryptedBlob = outer.optString("encryptedBlob", "")
            if (encryptedBlob.isEmpty()) {
                Log.d(TAG, "parseVault: encryptedBlob is empty")
                return entries
            }

            val entriesArray = JSONArray(encryptedBlob)

            for (i in 0 until entriesArray.length()) {
                try {
                    val obj = entriesArray.getJSONObject(i)
                    val id = obj.optString("id", "")
                    val title = obj.optString("title", "").trim()
                    val username = obj.optString("username", "").trim()
                    val encPass = obj.optString("encryptedPassword", "")
                    val url = obj.optString("url", "").trim()
                    val salt = obj.optString("salt", "")
                    val updatedAt = obj.optDouble("updatedAt", 0.0)

                    if (id.isNotEmpty() && encPass.isNotEmpty() && salt.isNotEmpty()) {
                        entries.add(VaultEntry(id, title, username, encPass, url, salt, updatedAt))
                    }
                } catch (entryErr: Exception) {
                    Log.e(TAG, "parseVault: error parsing entry at index $i", entryErr)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "parseVault: error parsing vault JSON", e)
        }
        return entries
    }

    private data class AutofillFields(
        val usernameId: AutofillId?,
        val passwordId: AutofillId?
    )

    private data class SaveFields(
        val username: String?,
        val password: String?
    )

    private fun extractAutofillFields(structure: AssistStructure): AutofillFields {
        var usernameId: AutofillId? = null
        var passwordId: AutofillId? = null

        try {
            for (i in 0 until structure.windowNodeCount) {
                val windowNode = structure.getWindowNodeAt(i)
                traverseNode(windowNode.rootViewNode) { node ->
                    val autofillHints = node.autofillHints
                    val autofillId = node.autofillId ?: return@traverseNode

                    if (autofillHints != null) {
                        for (hint in autofillHints) {
                            val lowerHint = hint.lowercase()
                            when {
                                lowerHint.contains("username") ||
                                lowerHint.contains("email") ||
                                lowerHint == "emailAddress" -> {
                                    if (usernameId == null) {
                                        usernameId = autofillId
                                        Log.d(TAG, "extractAutofillFields: found username via hint='$hint'")
                                    }
                                }
                                lowerHint.contains("password") -> {
                                    if (passwordId == null) {
                                        passwordId = autofillId
                                        Log.d(TAG, "extractAutofillFields: found password via hint='$hint'")
                                    }
                                }
                            }
                        }
                    }

                    if (node.inputType != 0) {
                        val inputType = node.inputType
                        val maskedVariation = inputType and 0x00000FF0
                        val isPassword = maskedVariation == android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                            maskedVariation == android.text.InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
                            maskedVariation == android.text.InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                        val isEmail = maskedVariation == android.text.InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
                            maskedVariation == android.text.InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS

                        if (isPassword && passwordId == null) {
                            passwordId = autofillId
                            Log.d(TAG, "extractAutofillFields: found password via inputType=0x${Integer.toHexString(inputType)}")
                        } else if (isEmail && usernameId == null) {
                            usernameId = autofillId
                            Log.d(TAG, "extractAutofillFields: found username via inputType=0x${Integer.toHexString(inputType)}")
                        }
                    }

                    if (usernameId == null || passwordId == null) {
                        val viewId = node.idEntry?.lowercase() ?: ""
                        val hintText = node.hint?.lowercase() ?: ""

                        if (viewId.isNotEmpty() || hintText.isNotEmpty()) {
                            val combinedText = "$viewId $hintText"

                            if (passwordId == null && (
                                combinedText.contains("password") ||
                                combinedText.contains("passwd") ||
                                combinedText.contains("pass_word")
                            )) {
                                passwordId = autofillId
                                Log.d(TAG, "extractAutofillFields: found password via viewId/hint viewId='$viewId' hint='$hintText'")
                            } else if (usernameId == null && (
                                combinedText.contains("username") ||
                                combinedText.contains("user_name") ||
                                combinedText.contains("email") ||
                                combinedText.contains("login") ||
                                combinedText.contains("userid") ||
                                combinedText.contains("user_id")
                            )) {
                                usernameId = autofillId
                                Log.d(TAG, "extractAutofillFields: found username via viewId/hint viewId='$viewId' hint='$hintText'")
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "extractAutofillFields: error traversing structure", e)
        }

        Log.d(TAG, "extractAutofillFields: result usernameId=${usernameId != null}, passwordId=${passwordId != null}")
        return AutofillFields(usernameId, passwordId)
    }

    private fun extractSaveFields(structure: AssistStructure): SaveFields {
        var username: String? = null
        var password: String? = null

        try {
            for (i in 0 until structure.windowNodeCount) {
                val windowNode = structure.getWindowNodeAt(i)
                traverseNode(windowNode.rootViewNode) { node ->
                    val autofillValue = node.autofillValue ?: return@traverseNode
                    if (!autofillValue.isText) return@traverseNode
                    val textValue = autofillValue.textValue?.toString() ?: return@traverseNode
                    if (textValue.isEmpty()) return@traverseNode

                    var isUsername = false
                    var isPassword = false

                    val autofillHints = node.autofillHints
                    if (autofillHints != null) {
                        for (hint in autofillHints) {
                            val lowerHint = hint.lowercase()
                            if (lowerHint.contains("username") || lowerHint.contains("email")) {
                                isUsername = true
                            }
                            if (lowerHint.contains("password")) {
                                isPassword = true
                            }
                        }
                    }

                    if (!isUsername && !isPassword && node.inputType != 0) {
                        val maskedVariation = node.inputType and 0x00000FF0
                        isPassword = maskedVariation == android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                            maskedVariation == android.text.InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
                            maskedVariation == android.text.InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                        isUsername = !isPassword && (
                            maskedVariation == android.text.InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
                            maskedVariation == android.text.InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS
                        )
                    }

                    if (!isUsername && !isPassword) {
                        val viewId = node.idEntry?.lowercase() ?: ""
                        val hintText = node.hint?.lowercase() ?: ""
                        val combinedText = "$viewId $hintText"

                        if (combinedText.contains("password") || combinedText.contains("passwd")) {
                            isPassword = true
                        } else if (combinedText.contains("username") || combinedText.contains("email") ||
                            combinedText.contains("login") || combinedText.contains("userid")) {
                            isUsername = true
                        }
                    }

                    if (isPassword && password == null) {
                        password = textValue
                    } else if (isUsername && username == null) {
                        username = textValue
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "extractSaveFields: error", e)
        }

        return SaveFields(username, password)
    }

    private fun traverseNode(
        node: AssistStructure.ViewNode,
        callback: (AssistStructure.ViewNode) -> Unit
    ) {
        try {
            callback(node)
            for (i in 0 until node.childCount) {
                traverseNode(node.getChildAt(i), callback)
            }
        } catch (e: Exception) {
            Log.e(TAG, "traverseNode: error visiting node", e)
        }
    }

    private fun extractDomain(structure: AssistStructure): String {
        try {
            for (i in 0 until structure.windowNodeCount) {
                val windowNode = structure.getWindowNodeAt(i)
                val domain = extractDomainFromNode(windowNode.rootViewNode)
                if (domain.isNotEmpty()) return domain
            }
        } catch (e: Exception) {
            Log.e(TAG, "extractDomain: error", e)
        }
        return ""
    }

    private fun extractDomainFromNode(node: AssistStructure.ViewNode): String {
        try {
            val webDomain = node.webDomain
            if (!webDomain.isNullOrEmpty()) return webDomain

            val idPackage = node.idPackage
            if (!idPackage.isNullOrEmpty()) return idPackage

            for (i in 0 until node.childCount) {
                val result = extractDomainFromNode(node.getChildAt(i))
                if (result.isNotEmpty()) return result
            }
        } catch (e: Exception) {
            Log.e(TAG, "extractDomainFromNode: error", e)
        }
        return ""
    }

    private fun buildDataset(
        fields: AutofillFields,
        username: String,
        password: String,
        title: String
    ): Dataset? {
        return try {
            val presentation = try {
                val customView = RemoteViews(packageName, R.layout.autofill_item)
                customView.setTextViewText(R.id.autofill_title, title.ifEmpty { "PiPass" })
                customView.setTextViewText(R.id.autofill_subtitle, username.ifEmpty { "Tap to fill" })
                customView
            } catch (e: Exception) {
                Log.d(TAG, "buildDataset: custom layout not available, using fallback")
                RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
                    setTextViewText(android.R.id.text1, "PiPass \u2014 $title")
                }
            }

            val builder = Dataset.Builder(presentation)
            var hasField = false

            if (fields.usernameId != null) {
                builder.setValue(fields.usernameId!!, AutofillValue.forText(username))
                hasField = true
            }

            if (fields.passwordId != null) {
                builder.setValue(fields.passwordId!!, AutofillValue.forText(password))
                hasField = true
            }

            if (hasField) {
                Log.d(TAG, "buildDataset: built dataset for '$title' with username='${username.take(3)}***'")
                builder.build()
            } else {
                Log.d(TAG, "buildDataset: no fields to fill for '$title'")
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "buildDataset: error building dataset for '$title'", e)
            null
        }
    }

    fun normalizeDomain(input: String): String {
        var url = input.trim().lowercase()

        if (url.startsWith("http://")) {
            url = url.removePrefix("http://")
        } else if (url.startsWith("https://")) {
            url = url.removePrefix("https://")
        }

        url = url.split("/")[0]
        url = url.replace("www.", "")

        val parts = url.split(".")
        return if (parts.size <= 2) {
            url
        } else {
            parts.takeLast(2).joinToString(".")
        }
    }

    private fun isSessionValid(): Boolean {
        if (sessionStartMs == 0L) return false
        return System.currentTimeMillis() - sessionStartMs < SESSION_TIMEOUT_MS
    }

    private fun startSession() {
        sessionStartMs = System.currentTimeMillis()
        handler.removeCallbacks(sessionWipeRunnable)
        handler.postDelayed(sessionWipeRunnable, SESSION_TIMEOUT_MS)
    }

    private fun wipeSession() {
        handler.removeCallbacks(sessionWipeRunnable)
        sessionStartMs = 0L
    }
}
