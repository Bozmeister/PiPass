package com.pipass.app.autofill

import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.util.Log
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import com.pipass.app.R
import org.json.JSONArray
import org.json.JSONException

class PiPassAutofillService : AutofillService() {

    companion object {
        private const val TAG = "PiPassAutofill"
        // Android's autofill UI typically truncates after a handful of items;
        // keeping this small keeps the dropdown usable even with a large vault.
        private const val MAX_DATASETS = 5
    }

    override fun onConnected() {
        super.onConnected()
        Log.d(TAG, "onConnected: autofill session started")
    }

    override fun onDisconnected() {
        super.onDisconnected()
        Log.d(TAG, "onDisconnected: autofill session ended")
    }

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        Log.d(TAG, "onFillRequest: received fill request")

        try {
            val context = request.fillContexts.lastOrNull()
            if (context == null) {
                Log.w(TAG, "onFillRequest: no fill context")
                callback.onSuccess(null)
                return
            }

            val parsed = PiPassAutofillParser.parse(context.structure)
            Log.d(
                TAG,
                "onFillRequest: parsed package=${parsed.packageName}, " +
                    "webDomain=${parsed.webDomain}, " +
                    "usernameId=${parsed.usernameId}, " +
                    "passwordId=${parsed.passwordId}"
            )

            if (parsed.identifierId == null && parsed.passwordId == null) {
                Log.d(TAG, "onFillRequest: no fillable fields detected")
                callback.onSuccess(null)
                return
            }

            val responseBuilder = FillResponse.Builder()
            var datasetCount = 0

            if (PiPassAutofillModule.snapshotUnlocked()) {
                val records = parseVaultSnapshot(PiPassAutofillModule.snapshotVaultJson())
                val matches = PiPassDomainMatcher.match(
                    records = records,
                    webDomain = parsed.webDomain,
                    packageName = parsed.packageName
                )
                Log.d(TAG, "onFillRequest: vault unlocked, ${matches.size} matches")

                for (match in matches.take(MAX_DATASETS)) {
                    val dataset = buildDatasetForRecord(parsed, match) ?: continue
                    responseBuilder.addDataset(dataset)
                    datasetCount++
                }
            } else {
                Log.d(TAG, "onFillRequest: vault locked; no datasets emitted")
            }

            if (datasetCount == 0) {
                Log.d(TAG, "onFillRequest: no matches, returning empty response")
                callback.onSuccess(null)
                return
            }

            val saveTypes = computeSaveTypes(parsed)
            val saveIds = computeSaveIds(parsed)
            if (saveIds.isNotEmpty() && saveTypes != 0) {
                responseBuilder.setSaveInfo(
                    SaveInfo.Builder(saveTypes, saveIds.toTypedArray()).build()
                )
            }

            callback.onSuccess(responseBuilder.build())
        } catch (t: Throwable) {
            Log.e(TAG, "onFillRequest: unexpected error", t)
            // Never call onFailure — it surfaces a system error popup. onSuccess(null)
            // simply tells Android we have nothing to offer.
            callback.onSuccess(null)
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        Log.d(TAG, "onSaveRequest: received save request")
        try {
            val context = request.fillContexts.lastOrNull()
            if (context != null) {
                val parsed = PiPassAutofillParser.parse(context.structure)
                Log.d(
                    TAG,
                    "onSaveRequest: package=${parsed.packageName}, " +
                        "webDomain=${parsed.webDomain}, " +
                        "hasUsernameField=${parsed.usernameId != null}, " +
                        "hasPasswordField=${parsed.passwordId != null}"
                )
            }
            callback.onSuccess()
        } catch (t: Throwable) {
            Log.e(TAG, "onSaveRequest: unexpected error", t)
            callback.onSuccess()
        }
    }

    /**
     * Builds one [Dataset] for a single matched vault record, filling the
     * identifier (username or email) field and the password field with the
     * presentation rendered using the PiPass icon and the entry name as
     * label. Returns null when neither field can be filled.
     */
    private fun buildDatasetForRecord(
        parsed: PiPassAutofillParser.ParsedStructure,
        match: PiPassDomainMatcher.Match
    ): Dataset? {
        val builder = Dataset.Builder()
        var added = false

        val record = match.record
        val label = record.name.ifBlank { record.url.ifBlank { "PiPass" } }
        val subtitle = buildSubtitle(record, match.kind)

        // Use a fresh RemoteViews instance per setValue call. Sharing the
        // same RemoteViews across multiple setValue calls within one Dataset
        // can cause Android to render only the last presentation; per-field
        // instances are the safe pattern.
        parsed.identifierId?.let { id ->
            builder.setValue(
                id,
                AutofillValue.forText(record.username),
                buildPresentation(label, subtitle)
            )
            added = true
        }

        parsed.passwordId?.let { id ->
            builder.setValue(
                id,
                AutofillValue.forText(record.password),
                buildPresentation(label, subtitle)
            )
            added = true
        }

        return if (added) builder.build() else null
    }

    private fun buildSubtitle(
        record: PiPassDomainMatcher.VaultRecord,
        kind: PiPassDomainMatcher.MatchKind
    ): String {
        val identity = record.username.ifBlank { record.url }
        val tag = when (kind) {
            PiPassDomainMatcher.MatchKind.EXACT -> ""
            PiPassDomainMatcher.MatchKind.SUBDOMAIN -> " · related"
            PiPassDomainMatcher.MatchKind.FUZZY -> " · similar"
        }
        return identity + tag
    }

    private fun buildPresentation(title: String, subtitle: String): RemoteViews {
        return try {
            val rv = RemoteViews(packageName, R.layout.autofill_item)
            rv.setTextViewText(R.id.autofill_title, title)
            rv.setTextViewText(R.id.autofill_subtitle, subtitle)
            // Use the launcher icon as the PiPass branding mark — it's the
            // user-recognizable PiPass logo and is guaranteed to exist.
            rv.setImageViewResource(R.id.autofill_icon, R.mipmap.ic_launcher)
            rv
        } catch (t: Throwable) {
            Log.w(TAG, "buildPresentation: custom layout unavailable, using fallback", t)
            val fallback = RemoteViews(packageName, android.R.layout.simple_list_item_1)
            fallback.setTextViewText(android.R.id.text1, "$title — $subtitle")
            fallback
        }
    }

    /**
     * Defensive JSON parser. Skips entries that are missing required fields
     * (id, username, password) or that aren't objects. A single bad entry
     * never throws — it is logged and skipped.
     */
    private fun parseVaultSnapshot(json: String): List<PiPassDomainMatcher.VaultRecord> {
        if (json.isBlank() || json == "[]") return emptyList()
        return try {
            val arr = JSONArray(json)
            val out = ArrayList<PiPassDomainMatcher.VaultRecord>(arr.length())
            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i) ?: continue
                val id = obj.optString("id", "").takeIf { it.isNotBlank() } ?: continue
                val username = obj.optString("username", "")
                val password = obj.optString("password", "")
                if (username.isBlank() && password.isBlank()) continue
                out += PiPassDomainMatcher.VaultRecord(
                    id = id,
                    name = obj.optString("name", ""),
                    username = username,
                    password = password,
                    url = obj.optString("url", "")
                )
            }
            out
        } catch (e: JSONException) {
            Log.w(TAG, "parseVaultSnapshot: malformed JSON, returning empty list", e)
            emptyList()
        }
    }

    private fun computeSaveTypes(parsed: PiPassAutofillParser.ParsedStructure): Int {
        var types = 0
        if (parsed.usernameId != null) types = types or SaveInfo.SAVE_DATA_TYPE_USERNAME
        if (parsed.emailId != null) types = types or SaveInfo.SAVE_DATA_TYPE_EMAIL_ADDRESS
        if (parsed.passwordId != null) types = types or SaveInfo.SAVE_DATA_TYPE_PASSWORD
        return types
    }

    private fun computeSaveIds(parsed: PiPassAutofillParser.ParsedStructure): List<AutofillId> =
        listOfNotNull(parsed.usernameId, parsed.emailId, parsed.passwordId)
}
