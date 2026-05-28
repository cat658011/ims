//SPDX-License-Identifier: GPL-2.0
package me.phh.sip

import android.content.Context
import android.net.IpSecAlgorithm
import android.net.IpSecManager
import android.net.IpSecTransform
import android.telephony.Rlog
import java.net.InetAddress

data class SipIpsecTransforms(
    val builder: IpSecTransform.Builder,
    val serverInTransform: IpSecTransform,
    val serverOutTransform: IpSecTransform,
)

object SipIpsecTransformBuilder {
    private const val TAG = "PHH SipIpsecTransformBuilder"

    /**
     * Map a carrier-negotiated integrity algorithm name to the platform
     * [IpSecAlgorithm] constant and the correctly-sized HMAC key.
     *
     * Only `hmac-sha-1-96` and `hmac-md5-96` are supported by the Android
     * user-space IPsec API on all vendor API levels.  If the carrier somehow
     * negotiates something else (e.g. `aes-xcbc`), we fall back to HMAC-MD5
     * with a warning — this matches the Samsung One UI fallback behaviour.
     */
    private fun resolveIntegrityAlgorithm(
        negotiatedAlg: String?,
        integrityKey: ByteArray,
    ): Pair<String, ByteArray> {
        return when (negotiatedAlg) {
            "hmac-sha-1-96" -> {
                // SHA-1-96 MAC key must be 160 bits (20 bytes); IK from AKA is
                // 128 bits (16 bytes), so pad with 4 zero bytes.
                Rlog.d(TAG, "Integrity: hmac-sha-1-96 -> AUTH_HMAC_SHA1, IK=${integrityKey.size}B padded to ${integrityKey.size + 4}B")
                IpSecAlgorithm.AUTH_HMAC_SHA1 to integrityKey + ByteArray(4)
            }
            "hmac-md5-96" -> {
                // MD5-96 MAC key is 128 bits (16 bytes), matching IK directly.
                Rlog.d(TAG, "Integrity: hmac-md5-96 -> AUTH_HMAC_MD5, IK=${integrityKey.size}B")
                IpSecAlgorithm.AUTH_HMAC_MD5 to integrityKey
            }
            else -> {
                // Unsupported or unrecognized algorithm string from the carrier.
                // Fall back to HMAC-MD5 which is universally supported.
                Rlog.w(TAG, "Integrity: unrecognized algorithm '$negotiatedAlg'; falling back to AUTH_HMAC_MD5, IK=${integrityKey.size}B")
                IpSecAlgorithm.AUTH_HMAC_MD5 to integrityKey
            }
        }
    }

    fun build(
        ctxt: Context,
        pcscfAddr: InetAddress,
        localAddr: InetAddress,
        clientSpiS: IpSecManager.SecurityParameterIndex,
        serverSpiC: IpSecManager.SecurityParameterIndex,
        securityServerParams: Map<String, String>,
        integrityKey: ByteArray,
        cipherKey: ByteArray,
    ): SipIpsecTransforms {
        val negotiatedEalg = securityServerParams["ealg"] ?: "null"
        val negotiatedAlg = securityServerParams["alg"]

        val (authenticationAlgorithm, hmacKey) = resolveIntegrityAlgorithm(negotiatedAlg, integrityKey)

        Rlog.d(TAG, "Building IPsec transforms: ealg=$negotiatedEalg alg=$negotiatedAlg auth=$authenticationAlgorithm hmacKeyLen=${hmacKey.size} cipherKeyLen=${cipherKey.size}")

        val builder = IpSecTransform.Builder(ctxt)
            .setAuthentication(IpSecAlgorithm(authenticationAlgorithm, hmacKey, 96))
            .also {
                if (negotiatedEalg == "aes-cbc") {
                    if (cipherKey.size != 16) {
                        Rlog.w(TAG, "Cipher key length ${cipherKey.size} unexpected for AES-128-CBC (expected 16); skipping encryption")
                    } else {
                        Rlog.d(TAG, "Encryption: aes-cbc with ${cipherKey.size}B key")
                        it.setEncryption(IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, cipherKey))
                    }
                } else {
                    Rlog.d(TAG, "Encryption: null (no cipher)")
                }
            }

        return SipIpsecTransforms(
            builder = builder,
            serverInTransform = builder.buildTransportModeTransform(pcscfAddr, clientSpiS),
            serverOutTransform = builder.buildTransportModeTransform(localAddr, serverSpiC),
        )
    }
}
