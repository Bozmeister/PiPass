package com.pipass.app.autofill

import android.app.assist.AssistStructure
import android.text.InputType
import android.util.Log
import android.view.View
import android.view.autofill.AutofillId

/**
 * Parses an [AssistStructure] from an Android Autofill request and identifies
 * username, email, and password fields using four detection strategies in
 * priority order:
 *
 *   1. `autofillHints` (the modern, app-declared hints — most reliable)
 *   2. `inputType` (variation flags such as TYPE_TEXT_VARIATION_PASSWORD)
 *   3. HTML attributes (`type`, `name`, `id`, `autocomplete`) for WebView nodes
 *   4. View id / hint text heuristics (last-resort keyword matching)
 *
 * The parser does not depend on the React Native layer, the vault, or any
 * crypto code — it is a pure structure analyzer that returns a
 * [ParsedStructure] description.
 */
object PiPassAutofillParser {

    private const val TAG = "PiPassParser"

    // InputType variation mask. The lower 8 bits of inputType encode the
    // variation; the next 4 bits encode flags, and higher bits encode the
    // base class. Mask is `0x00000FF0`.
    private const val TYPE_VARIATION_MASK = InputType.TYPE_MASK_VARIATION

    private val USERNAME_KEYWORDS = listOf(
        "username", "user_name", "user-name", "userid", "user_id", "user-id",
        "loginid", "login_id", "login-id", "login", "account", "handle"
    )

    private val EMAIL_KEYWORDS = listOf("email", "e-mail", "e_mail", "emailaddress")

    private val PASSWORD_KEYWORDS = listOf(
        "password", "passwd", "pwd", "pass", "secret", "passcode"
    )

    data class ParsedStructure(
        val packageName: String?,
        val webDomain: String?,
        val usernameId: AutofillId?,
        val emailId: AutofillId?,
        val passwordId: AutofillId?
    ) {
        /** Single-field convenience: prefer the explicit username, fall back to email. */
        val identifierId: AutofillId? get() = usernameId ?: emailId
    }

    fun parse(structure: AssistStructure): ParsedStructure {
        var usernameId: AutofillId? = null
        var emailId: AutofillId? = null
        var passwordId: AutofillId? = null
        var packageName: String? = null
        var webDomain: String? = null

        val windowCount = structure.windowNodeCount
        for (w in 0 until windowCount) {
            val window = structure.getWindowNodeAt(w) ?: continue
            val root = window.rootViewNode ?: continue

            if (packageName == null) packageName = root.idPackage

            val visitor = object {
                fun visit(node: AssistStructure.ViewNode) {
                    if (webDomain == null) {
                        node.webDomain?.takeIf { it.isNotBlank() }?.let { webDomain = it }
                    }

                    when (detect(node)) {
                        FieldKind.USERNAME -> if (usernameId == null) {
                            usernameId = node.autofillId
                            Log.d(TAG, "matched USERNAME via ${lastReason}: id=${node.idEntry}")
                        }
                        FieldKind.EMAIL -> if (emailId == null) {
                            emailId = node.autofillId
                            Log.d(TAG, "matched EMAIL via ${lastReason}: id=${node.idEntry}")
                        }
                        FieldKind.PASSWORD -> if (passwordId == null) {
                            passwordId = node.autofillId
                            Log.d(TAG, "matched PASSWORD via ${lastReason}: id=${node.idEntry}")
                        }
                        FieldKind.NONE -> Unit
                    }

                    val childCount = node.childCount
                    for (c in 0 until childCount) {
                        node.getChildAt(c)?.let { visit(it) }
                    }
                }
            }
            visitor.visit(root)
        }

        return ParsedStructure(
            packageName = packageName,
            webDomain = webDomain,
            usernameId = usernameId,
            emailId = emailId,
            passwordId = passwordId
        )
    }

    private enum class FieldKind { NONE, USERNAME, EMAIL, PASSWORD }

    // Tracks which detection strategy fired most recently so logs can attribute
    // a match to its tier. Not thread-safe, but parsing is single-threaded per
    // request inside [parse].
    @Volatile
    private var lastReason: String = "unknown"

    private fun detect(node: AssistStructure.ViewNode): FieldKind {
        // Skip nodes that aren't editable / focusable text inputs. We rely on
        // className == EditText OR htmlInfo == <input> when present, but to be
        // permissive we also accept nodes with a non-null autofill type of TEXT.
        if (!isPlausibleTextInput(node)) return FieldKind.NONE

        // Tier 1: autofillHints (declared by the app)
        node.autofillHints?.let { hints ->
            for (hint in hints) {
                when (hint?.lowercase()) {
                    View.AUTOFILL_HINT_PASSWORD,
                    "newpassword", "new-password", "current-password" -> {
                        lastReason = "autofillHints($hint)"
                        return FieldKind.PASSWORD
                    }
                    View.AUTOFILL_HINT_USERNAME -> {
                        lastReason = "autofillHints($hint)"
                        return FieldKind.USERNAME
                    }
                    View.AUTOFILL_HINT_EMAIL_ADDRESS, "email" -> {
                        lastReason = "autofillHints($hint)"
                        return FieldKind.EMAIL
                    }
                }
            }
        }

        // Tier 2: inputType variation flags
        val variation = node.inputType and TYPE_VARIATION_MASK
        when (variation) {
            InputType.TYPE_TEXT_VARIATION_PASSWORD,
            InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
            InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD,
            InputType.TYPE_NUMBER_VARIATION_PASSWORD -> {
                lastReason = "inputType(password)"
                return FieldKind.PASSWORD
            }
            InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS,
            InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS -> {
                lastReason = "inputType(email)"
                return FieldKind.EMAIL
            }
        }

        // Tier 3: HTML attributes (WebView <input> nodes)
        node.htmlInfo?.let { html ->
            if (html.tag.equals("input", ignoreCase = true)) {
                val attrs = html.attributes ?: emptyList()
                var typeAttr: String? = null
                var nameAttr: String? = null
                var idAttr: String? = null
                var autocompleteAttr: String? = null
                for (pair in attrs) {
                    when (pair.first.lowercase()) {
                        "type" -> typeAttr = pair.second?.lowercase()
                        "name" -> nameAttr = pair.second?.lowercase()
                        "id" -> idAttr = pair.second?.lowercase()
                        "autocomplete" -> autocompleteAttr = pair.second?.lowercase()
                    }
                }

                if (typeAttr == "password" || autocompleteAttr?.contains("password") == true) {
                    lastReason = "htmlAttr(type/autocomplete=password)"
                    return FieldKind.PASSWORD
                }
                if (typeAttr == "email" || autocompleteAttr == "email") {
                    lastReason = "htmlAttr(type/autocomplete=email)"
                    return FieldKind.EMAIL
                }
                if (autocompleteAttr == "username") {
                    lastReason = "htmlAttr(autocomplete=username)"
                    return FieldKind.USERNAME
                }

                val combined = listOfNotNull(nameAttr, idAttr, autocompleteAttr).joinToString(" ")
                if (combined.isNotEmpty()) {
                    if (containsAny(combined, PASSWORD_KEYWORDS)) {
                        lastReason = "htmlAttr(name/id matches password)"
                        return FieldKind.PASSWORD
                    }
                    if (containsAny(combined, EMAIL_KEYWORDS)) {
                        lastReason = "htmlAttr(name/id matches email)"
                        return FieldKind.EMAIL
                    }
                    if (containsAny(combined, USERNAME_KEYWORDS)) {
                        lastReason = "htmlAttr(name/id matches username)"
                        return FieldKind.USERNAME
                    }
                }
            }
        }

        // Tier 4: viewId / hint text heuristics
        val haystack = listOfNotNull(node.idEntry, node.hint?.toString(), node.text?.toString())
            .joinToString(" ")
            .lowercase()
        if (haystack.isNotEmpty()) {
            if (containsAny(haystack, PASSWORD_KEYWORDS)) {
                lastReason = "viewId/hint matches password"
                return FieldKind.PASSWORD
            }
            if (containsAny(haystack, EMAIL_KEYWORDS)) {
                lastReason = "viewId/hint matches email"
                return FieldKind.EMAIL
            }
            if (containsAny(haystack, USERNAME_KEYWORDS)) {
                lastReason = "viewId/hint matches username"
                return FieldKind.USERNAME
            }
        }

        return FieldKind.NONE
    }

    private fun isPlausibleTextInput(node: AssistStructure.ViewNode): Boolean {
        // autofillType TEXT means Android believes this node accepts text input.
        if (node.autofillType == View.AUTOFILL_TYPE_TEXT) return true
        // Fall back to className inspection for older targets / non-standard widgets.
        val className = node.className ?: return false
        return className.contains("EditText", ignoreCase = true) ||
            className.contains("AutoCompleteTextView", ignoreCase = true) ||
            (node.htmlInfo?.tag?.equals("input", ignoreCase = true) == true)
    }

    private fun containsAny(haystack: String, needles: List<String>): Boolean {
        for (n in needles) if (haystack.contains(n)) return true
        return false
    }
}
