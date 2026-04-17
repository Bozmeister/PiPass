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
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import com.pipass.app.R

class PiPassAutofillService : AutofillService() {

    companion object {
        private const val TAG = "PiPassAutofill"
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

            // Hardcoded demo dataset (no React Native / vault wiring yet).
            val dataset = buildDemoDataset(parsed) ?: run {
                Log.d(TAG, "onFillRequest: failed to build dataset")
                callback.onSuccess(null)
                return
            }

            val saveTypes = computeSaveTypes(parsed)
            val saveIds = computeSaveIds(parsed)

            val responseBuilder = FillResponse.Builder().addDataset(dataset)
            if (saveIds.isNotEmpty() && saveTypes != 0) {
                responseBuilder.setSaveInfo(SaveInfo.Builder(saveTypes, saveIds.toTypedArray()).build())
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

    private fun buildDemoDataset(parsed: PiPassAutofillParser.ParsedStructure): Dataset? {
        val builder = Dataset.Builder()
        var added = false

        // Fill the identifier field, whether it was detected as a username or
        // an email-only field.
        parsed.identifierId?.let { id ->
            val presentation = buildPresentation("PiPass demo", "demo@pipass.app")
            builder.setValue(id, AutofillValue.forText("demo@pipass.app"), presentation)
            added = true
        }

        parsed.passwordId?.let { id ->
            val presentation = buildPresentation("PiPass demo", "••••••••")
            builder.setValue(id, AutofillValue.forText("demo-password"), presentation)
            added = true
        }

        return if (added) builder.build() else null
    }

    private fun buildPresentation(title: String, subtitle: String): RemoteViews {
        return try {
            val rv = RemoteViews(packageName, R.layout.autofill_item)
            rv.setTextViewText(R.id.autofill_title, title)
            rv.setTextViewText(R.id.autofill_subtitle, subtitle)
            rv
        } catch (t: Throwable) {
            Log.w(TAG, "buildPresentation: custom layout unavailable, using fallback", t)
            val fallback = RemoteViews(packageName, android.R.layout.simple_list_item_1)
            fallback.setTextViewText(android.R.id.text1, "$title — $subtitle")
            fallback
        }
    }

    private fun computeSaveTypes(parsed: PiPassAutofillParser.ParsedStructure): Int {
        var types = 0
        if (parsed.usernameId != null) types = types or SaveInfo.SAVE_DATA_TYPE_USERNAME
        if (parsed.emailId != null) types = types or SaveInfo.SAVE_DATA_TYPE_EMAIL_ADDRESS
        if (parsed.passwordId != null) types = types or SaveInfo.SAVE_DATA_TYPE_PASSWORD
        return types
    }

    private fun computeSaveIds(parsed: PiPassAutofillParser.ParsedStructure) =
        listOfNotNull(parsed.usernameId, parsed.emailId, parsed.passwordId)
}
