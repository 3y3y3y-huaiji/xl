package io.github.ryf5584.wxdbdump.data

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.os.Process
import io.github.ryf5584.wxdbdump.payload.Log
import io.github.ryf5584.wxdbdump.payload.proto.Channel
import io.github.ryf5584.wxdbdump.payload.proto.Handshake
import io.github.ryf5584.wxdbdump.xposed.PeerAuth
import java.io.Closeable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Binder ContentProvider brokering kernel {@code AF_UNIX} SocketPair descriptors with WeChat.
 *
 * <p>How a session is established without opening any TCP or LocalServerSocket port:
 * <ol>
 *   <li>[requestSession] registers a single-use [requestId] and 256-bit [sessionToken] in
 *       memory, grants temporary URI visibility to WeChat, and sends an explicit foreground
 *       broadcast ([Channel.ACTION_CONNECT]) to WeChat.</li>
 *   <li>The Xposed module inside WeChat verifies this app's APK signing certificate (SHA-256),
 *       creates a kernel {@code AF_UNIX} stream socket pair via
 *       [ParcelFileDescriptor.createSocketPair], and calls [call] with the client descriptor.</li>
 *   <li>[call] verifies [Binder.getCallingUid] (enforced by the Linux kernel Binder driver)
 *       belongs to [Channel.WECHAT_PACKAGE], wakes the waiting client thread with the
 *       duplicated [ParcelFileDescriptor], and returns the single-use [sessionToken].</li>
 * </ol>
 */
class SocketBridgeProvider : ContentProvider() {

    data class ClientSession(
        val pfd: ParcelFileDescriptor,
        val sessionToken: String,
    ) : Closeable {
        override fun close() {
            runCatching { pfd.close() }
        }
    }

    private class PendingRequest(
        val sessionToken: String,
    ) {
        val latch = CountDownLatch(1)
        @Volatile
        var attachedPfd: ParcelFileDescriptor? = null
    }

    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        if (method != Channel.BRIDGE_METHOD_ATTACH) {
            return null
        }
        val callingUid = Binder.getCallingUid()
        if (!isAuthorizedWeChatCaller(callingUid)) {
            Log.w("auth", "拒绝未授权 UID 投递 AF_UNIX 套接字: uid=$callingUid")
            throw SecurityException("Caller UID $callingUid is not ${Channel.WECHAT_PACKAGE}")
        }

        val requestId = arg?.trim().orEmpty()
        val pending = pendingRequests.remove(requestId)
        val pfd = extractPfd(extras)
        if (pending == null || pfd == null) {
            Log.w("auth", "无效或已超时的套接字挂载请求: requestId=$requestId hasFd=${pfd != null}")
            runCatching { pfd?.close() }
            return null
        }

        pending.attachedPfd = pfd
        pending.latch.countDown()
        Log.i("auth", "已接收微信进程 (uid=$callingUid) 的 AF_UNIX SocketPair 并签发一次性握手 Token")
        return Bundle().apply {
            putString(Channel.BRIDGE_KEY_TOKEN, pending.sessionToken)
        }
    }

    @Suppress("DEPRECATION")
    private fun extractPfd(extras: Bundle?): ParcelFileDescriptor? {
        if (extras == null) return null
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            extras.getParcelable(Channel.BRIDGE_KEY_FD, ParcelFileDescriptor::class.java)
        } else {
            extras.getParcelable(Channel.BRIDGE_KEY_FD)
        }
    }

    private fun isAuthorizedWeChatCaller(callingUid: Int): Boolean {
        if (callingUid == Process.myUid()) return true
        val ctx = context ?: return false
        return try {
            val pm = ctx.packageManager
            val pkgs = pm.getPackagesForUid(callingUid) ?: return false
            if (Channel.WECHAT_PACKAGE !in pkgs) return false
            val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pm.getPackageInfo(Channel.WECHAT_PACKAGE, PackageManager.GET_SIGNING_CERTIFICATES)
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(Channel.WECHAT_PACKAGE, PackageManager.GET_SIGNATURES)
            }
            val appUid = info.applicationInfo?.uid ?: return false
            appUid == callingUid && !PeerAuth.extractCertSha256(info).isNullOrEmpty()
        } catch (t: Throwable) {
            Log.w("auth", "校验微信调用方 UID/签名异常: uid=$callingUid", t)
            false
        }
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0

    companion object {
        private val pendingRequests = ConcurrentHashMap<String, PendingRequest>()

        /**
         * Requests a fresh kernel {@code AF_UNIX} SocketPair session from the Xposed module
         * inside WeChat and blocks up to [timeoutMs] for the Binder attachment.
         */
        fun requestSession(context: Context?, timeoutMs: Long): ClientSession? {
            if (context == null) {
                Log.w("net", "requestSession failed: Context is null")
                return null
            }
            val requestId = Handshake.newNonce()
            val sessionToken = Handshake.newToken()
            val pending = PendingRequest(sessionToken)
            pendingRequests[requestId] = pending

            try {
                runCatching {
                    context.grantUriPermission(
                        Channel.WECHAT_PACKAGE,
                        Uri.parse(Channel.BRIDGE_URI),
                        Intent.FLAG_GRANT_READ_URI_PERMISSION,
                    )
                }

                val intent = Intent(Channel.ACTION_CONNECT).apply {
                    setPackage(Channel.WECHAT_PACKAGE)
                    addFlags(Intent.FLAG_RECEIVER_FOREGROUND)
                    putExtra(Channel.EXTRA_REQUEST_ID, requestId)
                }
                context.sendBroadcast(intent)

                val waitMs = timeoutMs.coerceAtLeast(300L)
                val ok = pending.latch.await(waitMs, TimeUnit.MILLISECONDS)
                val pfd = pending.attachedPfd
                if (!ok || pfd == null) {
                    runCatching { pfd?.close() }
                    return null
                }
                return ClientSession(pfd, sessionToken)
            } catch (t: Throwable) {
                Log.w("net", "requestSession interrupted or failed: $t")
                runCatching { pending.attachedPfd?.close() }
                return null
            } finally {
                val leftover = pendingRequests.remove(requestId)
                if (leftover != null && leftover.attachedPfd != null && pending.latch.count > 0) {
                    runCatching { leftover.attachedPfd?.close() }
                }
            }
        }
    }
}
