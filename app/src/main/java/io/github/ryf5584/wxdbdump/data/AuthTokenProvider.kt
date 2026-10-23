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
import android.os.Process
import io.github.ryf5584.wxdbdump.payload.Log
import io.github.ryf5584.wxdbdump.payload.proto.Channel
import io.github.ryf5584.wxdbdump.payload.proto.TokenStore
import io.github.ryf5584.wxdbdump.xposed.PeerAuth

/**
 * Binder ContentProvider that delivers single-use 256-bit handshake tokens to WeChat.
 *
 * <p>Security model:
 * <ul>
 *   <li><b>Kernel UID authentication:</b> {@link Binder#getCallingUid()} is supplied by the
 *       Linux kernel Binder driver and cannot be forged by user-space processes. Only
 *       {@link Channel#WECHAT_PACKAGE} (and this app's own UID for self-testing) may consume
 *       a token; any other app receives a {@link SecurityException}.</li>
 *   <li><b>Burn-on-read (阅后即焚):</b> Each token is bound to a single {@code HELLO} client
 *       nonce in {@link TokenStore}, lives solely in memory with a 15-second TTL, and is
 *       atomically erased on the first {@link Channel#AUTH_METHOD_CONSUME} call.</li>
 * </ul>
 */
class AuthTokenProvider : ContentProvider() {

    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        if (method != Channel.AUTH_METHOD_CONSUME) {
            return null
        }
        val callingUid = Binder.getCallingUid()
        if (!isAuthorizedWeChatCaller(callingUid)) {
            Log.w("auth", "拒绝未授权 UID 获取一次性握手 Token: uid=$callingUid")
            throw SecurityException("Caller UID $callingUid is not ${Channel.WECHAT_PACKAGE}")
        }
        val nonce = arg?.trim().orEmpty()
        val token = store.consume(nonce)
        if (token == null) {
            Log.w("auth", "一次性 Token 不存在或已过期/已焚毁 (callingUid=$callingUid)")
            return Bundle()
        }
        Log.i("auth", "已向微信进程 (uid=$callingUid) 投递并焚毁一次性握手 Token")
        return Bundle().apply {
            putString(Channel.AUTH_KEY_TOKEN, token)
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
            Log.w("auth", "校验调用方微信 UID/签名异常: uid=$callingUid", t)
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
        private val store = TokenStore()

        /**
         * Issues a single-use 256-bit token bound to [clientNonceHex] and ensures WeChat has
         * package visibility to this provider on Android 11+ via [Context.grantUriPermission].
         */
        fun issueToken(context: Context?, clientNonceHex: String): String {
            if (context != null) {
                runCatching {
                    context.grantUriPermission(
                        Channel.WECHAT_PACKAGE,
                        Uri.parse(Channel.AUTH_URI),
                        Intent.FLAG_GRANT_READ_URI_PERMISSION,
                    )
                }.onFailure { t ->
                    Log.d("auth", "grantUriPermission failed (WeChat may not be installed): $t")
                }
            }
            return store.issue(clientNonceHex)
        }

        /** Revokes an unconsumed token when a connection attempt fails before handshake. */
        fun revokeToken(clientNonceHex: String?) {
            if (!clientNonceHex.isNullOrEmpty()) {
                store.revoke(clientNonceHex)
            }
        }
    }
}
