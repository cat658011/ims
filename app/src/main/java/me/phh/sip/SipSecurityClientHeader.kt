//SPDX-License-Identifier: GPL-2.0
package me.phh.sip

object SipSecurityClientHeader {
    fun build(
        ipsecSettings: SipIpsecSettings,
        clientPort: Int,
        serverPort: Int,
    ): String {
        fun secClient(alg: String, ealg: String): String {
            val q = if (alg == "hmac-sha-1-96") "0.2" else "0.1"
            return "ipsec-3gpp;prot=esp;mod=trans;spi-c=${ipsecSettings.clientSpiC.spi};spi-s=${ipsecSettings.clientSpiS.spi};port-c=$clientPort;port-s=$serverPort;ealg=$ealg;alg=$alg;q=$q"
        }

        val algs = listOf("hmac-sha-1-96", "hmac-md5-96")
        val ealgs = listOf("null", "aes-cbc")
        val secClients = algs.flatMap { alg -> ealgs.map { ealg -> secClient(alg, ealg) } }
        return "Security-Client: ${secClients.joinToString(", ")}"
    }
}
