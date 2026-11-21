package org.amnezia.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.SecureRandom
import org.json.JSONObject

/**
 * Mayak (5.1.0.27): is the Xray tunnel restarted after an app update alive? The service asks the
 * exit agent inside the tunnel (TEST-NET-2 address 198.51.100.1:80, routed by our exit's Xray to its
 * local agent; never a third-party site). The socket is bound to the VPN network that owns the
 * Xray tunnel address. Only our exit can answer inside its own Reality tunnel, so any well-formed
 * answer with our nonce proves the tunnel; the app re-proves the exact exit when it starts.
 * Blocking: call off the main thread.
 */
object MayakExitAgentCheck {
    private const val AGENT_HOST = "198.51.100.1"
    private const val AGENT_PORT = 80
    private const val MAX_RESPONSE = 4096

    fun answers(context: Context, tunnelAddress: String, timeoutMs: Int): Boolean {
        val network = vpnNetwork(context, tunnelAddress) ?: return false
        val nonce = ByteArray(16).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        return try {
            network.socketFactory.createSocket().use { socket ->
                socket.soTimeout = timeoutMs
                socket.connect(InetSocketAddress(InetAddress.getByName(AGENT_HOST), AGENT_PORT), timeoutMs)
                socket.getOutputStream().write(
                    ("GET /mayak-proof?n=$nonce HTTP/1.1\r\nHost: $AGENT_HOST\r\n" +
                        "Connection: close\r\nAccept-Encoding: identity\r\n\r\n").toByteArray(Charsets.US_ASCII)
                )
                val wire = ByteArray(MAX_RESPONSE)
                var size = 0
                val input = socket.getInputStream()
                while (size < MAX_RESPONSE) {
                    val read = input.read(wire, size, MAX_RESPONSE - size)
                    if (read < 0) break
                    size += read
                    // Xray on the exit keeps the connection ~2 s after the agent closed: stop as soon
                    // as the declared body is complete (owner 21.11, variant 1).
                    if (complete(String(wire, 0, size, Charsets.UTF_8))) break
                }
                val text = String(wire, 0, size, Charsets.UTF_8)
                val split = text.indexOf("\r\n\r\n")
                if (split < 0 || !text.startsWith("HTTP/1.1 200")) return false
                val body = JSONObject(text.substring(split + 4).trim())
                body.length() == 3 && body.optInt("v", 0) == 1 && body.optString("nonce") == nonce &&
                    body.optString("exit").isNotEmpty()
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun complete(text: String): Boolean {
        val split = text.indexOf("\r\n\r\n")
        if (split < 0) return false
        val length = text.substring(0, split).split("\r\n").drop(1)
            .firstOrNull { it.substringBefore(':').trim().equals("content-length", ignoreCase = true) }
            ?.substringAfter(':')?.trim()?.toIntOrNull() ?: return false
        return text.toByteArray(Charsets.UTF_8).size - (split + 4) >= length
    }

    private fun vpnNetwork(context: Context, tunnelAddress: String) = run {
        val local = runCatching { InetAddress.getByName(tunnelAddress) }.getOrNull() as? Inet4Address ?: return@run null
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return@run null
        cm.allNetworks.singleOrNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@singleOrNull false
            val lp = cm.getLinkProperties(network) ?: return@singleOrNull false
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) && lp.linkAddresses.any { it.address == local }
        }
    }
}
