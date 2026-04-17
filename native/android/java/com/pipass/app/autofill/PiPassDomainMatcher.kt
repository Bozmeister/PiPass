package com.pipass.app.autofill

import android.util.Log

/**
 * Matches vault entries against an Android Autofill request target.
 *
 * Matching has three tiers, returned in priority order:
 *
 *   1. EXACT       — registrable host equals target host (or the request
 *                    is for a native app and a vault entry's URL contains
 *                    the *exact* package name e.g. `androidapp://com.x.y`
 *                    or just `com.x.y`)
 *   2. SUBDOMAIN   — registrable host matches as a parent/child relation
 *                    (e.g. vault `accounts.google.com` ↔ target `mail.google.com`)
 *   3. FUZZY       — token overlap on host labels with the public suffix
 *                    stripped (e.g. `myacme-app.io` ↔ `acme.io`)
 *
 * SECURITY NOTE — package name handling:
 * This matcher does NOT convert an app's package name into a guessed web
 * domain (e.g. `com.spotify.music` → `spotify.com`). Doing so would let any
 * malicious app named `com.spotify.evil` harvest the user's real Spotify
 * credentials. Native-app matching is opt-in: the user must store the exact
 * package name in the vault entry's URL (raw `com.spotify.music` or
 * `androidapp://com.spotify.music`). A future Digital Asset Links verifier
 * can lift this restriction safely; until then we err on the side of false
 * negatives over credential disclosure.
 *
 * The matcher is intentionally dependency-free — no `okhttp`, no `Uri`
 * registry lookups, no PSL — so it runs fast inside the autofill service
 * lifecycle and has no surprise classloads. The "registrable domain" we
 * compute is a heuristic: hostname minus its first label when the host has
 * 3+ labels and the second label is a known multi-part suffix; otherwise
 * the last two labels. Good enough for the common case; not meant to be a
 * full PSL implementation.
 */
object PiPassDomainMatcher {

    private const val TAG = "PiPassDomainMatcher"

    enum class MatchKind { EXACT, SUBDOMAIN, FUZZY }

    data class VaultRecord(
        val id: String,
        val name: String,
        val username: String,
        val password: String,
        val url: String
    )

    data class Match(val record: VaultRecord, val kind: MatchKind)

    /** Common second-level public suffixes — small allow-list, not exhaustive. */
    private val MULTI_PART_SUFFIXES = setOf(
        "co.uk", "ac.uk", "gov.uk", "org.uk", "co.jp", "co.kr", "co.nz",
        "com.au", "com.br", "com.mx", "com.cn", "com.tr", "com.sg", "com.hk",
        "co.in", "co.za", "co.il"
    )

    /**
     * Run all three tiers against the given vault. Returns matches ordered
     * by tier (EXACT first, then SUBDOMAIN, then FUZZY), de-duplicated by
     * vault entry id.
     *
     * - `webDomain` (when present, browser case): runs full host matching.
     * - `packageName` (always present, native-app case): runs ONLY exact
     *   opt-in package matching against vault URL field. We never derive a
     *   web domain from the package name — see the security note in the
     *   class doc.
     */
    fun match(
        records: List<VaultRecord>,
        webDomain: String?,
        packageName: String?
    ): List<Match> {
        if (records.isEmpty()) return emptyList()

        val targetHost = normalizeHost(webDomain)
        val normalizedPackage = packageName?.trim()?.lowercase()?.takeIf { it.isNotBlank() }

        val seen = mutableSetOf<String>()
        val exact = mutableListOf<Match>()
        val sub = mutableListOf<Match>()
        val fuzzy = mutableListOf<Match>()

        // Native-app matching: opt-in only. The vault URL must literally
        // contain the package name (raw or `androidapp://` scheme).
        if (normalizedPackage != null) {
            for (record in records) {
                if (matchesPackage(record.url, normalizedPackage)) {
                    if (seen.add(record.id)) exact += Match(record, MatchKind.EXACT)
                }
            }
        }

        // Web-domain matching: full three-tier flow.
        if (targetHost != null) {
            val targetReg = registrableDomain(targetHost)
            val targetTokens = hostTokens(targetHost)

            for (record in records) {
                if (record.id in seen) continue
                val recordHost = normalizeHost(record.url) ?: continue
                val recordReg = registrableDomain(recordHost)

                if (recordHost == targetHost) {
                    if (seen.add(record.id)) exact += Match(record, MatchKind.EXACT)
                    continue
                }

                if (recordReg.isNotEmpty() && recordReg == targetReg) {
                    if (seen.add(record.id)) sub += Match(record, MatchKind.SUBDOMAIN)
                    continue
                }

                val recordTokens = hostTokens(recordHost)
                if (hasSignificantOverlap(targetTokens, recordTokens)) {
                    if (seen.add(record.id)) fuzzy += Match(record, MatchKind.FUZZY)
                }
            }
        }

        if (targetHost == null && normalizedPackage != null) {
            Log.d(TAG, "match: native-app only (pkg=$normalizedPackage), exact=${exact.size}")
        } else {
            Log.d(
                TAG,
                "match: webDomain=$targetHost pkg=$normalizedPackage " +
                    "exact=${exact.size} sub=${sub.size} fuzzy=${fuzzy.size}"
            )
        }
        return exact + sub + fuzzy
    }

    /**
     * Opt-in native-app matching. Returns true when the vault URL field
     * literally contains the package name (case-insensitive), as either:
     *   - raw:           `com.spotify.music`
     *   - schemed:       `androidapp://com.spotify.music`
     *   - or appearing as a path/query token in any URL.
     *
     * The vault entry's URL must be set by the user — we never infer it
     * from the request's package name alone.
     */
    private fun matchesPackage(vaultUrl: String?, packageName: String): Boolean {
        if (vaultUrl.isNullOrBlank()) return false
        val v = vaultUrl.trim().lowercase()
        if (v == packageName) return true
        if (v == "androidapp://$packageName") return true
        // Allow the package name to appear as an isolated token in the URL,
        // bracketed by non-alphanumeric chars (so `com.foo.bar` doesn't match
        // `com.foo.barxyz`).
        val idx = v.indexOf(packageName)
        if (idx < 0) return false
        val before = if (idx == 0) ' ' else v[idx - 1]
        val afterIdx = idx + packageName.length
        val after = if (afterIdx >= v.length) ' ' else v[afterIdx]
        return !before.isLetterOrDigit() && !after.isLetterOrDigit()
    }

    /**
     * Lowercase, strip scheme, drop port/path/query, strip leading `www.`.
     * Returns null for blank input or values that yield an empty host.
     */
    fun normalizeHost(value: String?): String? {
        if (value.isNullOrBlank()) return null
        var s = value.trim().lowercase()

        val schemeIdx = s.indexOf("://")
        if (schemeIdx >= 0) s = s.substring(schemeIdx + 3)

        // Strip userinfo (user:pass@host)
        val atIdx = s.indexOf('@')
        if (atIdx >= 0) s = s.substring(atIdx + 1)

        // Cut at first path/query/fragment delimiter
        val cutIdx = s.indexOfAny(charArrayOf('/', '?', '#'))
        if (cutIdx >= 0) s = s.substring(0, cutIdx)

        // Strip port
        val colonIdx = s.lastIndexOf(':')
        if (colonIdx >= 0 && s.indexOf(':') == colonIdx) s = s.substring(0, colonIdx)

        if (s.startsWith("www.")) s = s.substring(4)

        return s.takeIf { it.isNotBlank() && it.contains('.') }
    }

    /**
     * Returns the registrable ("eTLD+1") portion of [host] using the
     * MULTI_PART_SUFFIXES allow-list. If [host] only has two labels it is
     * returned as-is. Empty string for nulls or single-label hosts.
     */
    fun registrableDomain(host: String?): String {
        if (host.isNullOrBlank()) return ""
        val labels = host.split('.').filter { it.isNotEmpty() }
        if (labels.size < 2) return ""
        if (labels.size == 2) return labels.joinToString(".")

        val lastTwo = "${labels[labels.size - 2]}.${labels[labels.size - 1]}"
        if (lastTwo in MULTI_PART_SUFFIXES && labels.size >= 3) {
            // Take last three labels (e.g. example.co.uk).
            return labels.subList(labels.size - 3, labels.size).joinToString(".")
        }
        return lastTwo
    }

    /** Drop the public suffix and any single-character labels. */
    private fun hostTokens(host: String?): Set<String> {
        if (host.isNullOrBlank()) return emptySet()
        val reg = registrableDomain(host)
        if (reg.isEmpty()) return emptySet()
        val regLabels = reg.split('.')
        // Drop the final TLD label (and the second-to-last for multi-part suffixes).
        val tldDrop = if (reg in MULTI_PART_SUFFIXES) regLabels.size else 1
        val keepFromReg = regLabels.dropLast(tldDrop)

        val hostLabels = host.split('.').filter { it.isNotEmpty() && it.length > 1 }
        // Keep all labels except the suffix portion, plus any subdomain labels.
        val tokens = mutableSetOf<String>()
        tokens += keepFromReg
        if (hostLabels.size > regLabels.size) {
            tokens += hostLabels.dropLast(regLabels.size)
        }
        return tokens.filter { it.length >= 3 }.toSet()
    }

    /**
     * Fuzzy overlap with intentionally conservative thresholds to avoid the
     * `microsoft` ↔ `microstrategy` class of false positive:
     *   - exact token equality always wins
     *   - substring match requires the shorter token to be ≥5 chars AND
     *     to comprise ≥60% of the longer token's length (so `acme` is
     *     allowed to match inside `myacme` but `micro` won't match
     *     `microstrategy`).
     */
    private fun hasSignificantOverlap(a: Set<String>, b: Set<String>): Boolean {
        if (a.isEmpty() || b.isEmpty()) return false
        for (token in a) {
            if (b.contains(token)) return true
            for (other in b) {
                val shorter = if (token.length <= other.length) token else other
                val longer = if (token.length <= other.length) other else token
                if (shorter.length < 5) continue
                if (!longer.contains(shorter)) continue
                if (shorter.length * 5 >= longer.length * 3) return true
            }
        }
        return false
    }
}
