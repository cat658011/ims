//SPDX-License-Identifier: GPL-2.0
package me.phh.sip

import android.telephony.Rlog

data class SipSecurityServerSelection(
    val type: String,
    val params: Map<String, String>,
)

object SipSecurityServerSelector {
    private const val TAG = "PHH SipSecurityServerSelector"

    private val supportedAlgorithms = listOf("hmac-sha-1-96", "hmac-md5-96")
    private val supportedEncryptionAlgorithms = listOf("aes-cbc", "null")

    private fun normalizeParams(rawParams: Map<String, String?>): Map<String, String> =
        rawParams.mapNotNull { (key, value) ->
            val normalizedValue = value?.trim()?.lowercase()
            if (normalizedValue.isNullOrEmpty()) {
                null
            } else {
                key.trim().lowercase() to normalizedValue
            }
        }.toMap()

    fun select(securityServerHeaders: List<String>): SipSecurityServerSelection {
        val candidates = securityServerHeaders
            .map { header ->
                val (rawType, rawParams) = header.getParams()
                rawType.trim().lowercase() to normalizeParams(rawParams)
            }

        val supported = candidates
            .filter { (type, params) ->
                val ealg = params["ealg"] ?: "null"
                val alg = params["alg"]
                val isSupported = type == "ipsec-3gpp" &&
                    supportedEncryptionAlgorithms.contains(ealg) &&
                    supportedAlgorithms.contains(alg)
                if (isSupported) {
                    Rlog.d(TAG, "Accepted Security-Server: type=$type alg=$alg ealg=$ealg q=${params["q"]}")
                } else {
                    Rlog.d(TAG, "Rejected Security-Server: type=$type alg=$alg ealg=$ealg" +
                        " (supportedType=${type == "ipsec-3gpp"}" +
                        " supportedEalg=${supportedEncryptionAlgorithms.contains(ealg)}" +
                        " supportedAlg=${supportedAlgorithms.contains(alg)})")
                }
                isSupported
            }
            .sortedByDescending { (_, params) ->
                params["q"]?.toFloatOrNull() ?: 0f
            }

        if (supported.isEmpty()) {
            val offeredAlgs = candidates.map { (type, params) -> "$type alg=${params["alg"]} ealg=${params["ealg"] ?: "null"}" }
            throw IllegalStateException(
                "No supported Security-Server header. " +
                "Offered: ${offeredAlgs.joinToString(" | ")}. " +
                "Supported integrity: $supportedAlgorithms, encryption: $supportedEncryptionAlgorithms"
            )
        }

        val (type, params) = supported[0]
        Rlog.d(TAG, "Selected Security-Server: type=$type alg=${params["alg"]} ealg=${params["ealg"]} q=${params["q"]}")
        return SipSecurityServerSelection(type = type, params = params)
    }
}

