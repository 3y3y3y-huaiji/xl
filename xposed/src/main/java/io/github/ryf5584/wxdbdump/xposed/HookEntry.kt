package androidx.sqlite.db.framework

import android.app.Application
import android.content.Context
import androidx.annotation.Keep
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import io.github.ryf5584.wxdbdump.payload.Log
import io.github.ryf5584.wxdbdump.payload.proto.Channel
import io.github.ryf5584.wxdbdump.xposed.LoopbackServer
import io.github.ryf5584.wxdbdump.xposed.PeerAuth
import io.github.ryf5584.wxdbdump.xposed.WxDbEngine
import io.github.ryf5584.wxdbdump.xposed.XposedHost
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Pure IXposedHookLoadPackage entry point with zero third-party hook framework (no YukiHookAPI,
 * no KavaRef, no parasitic ActivityManager/Instrumentation/Handler proxies, no BroadcastReceiver).
 */
@Keep
class CompatOpenHelper : IXposedHookLoadPackage {

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName != WECHAT_PKG) return
        Log.setSilentExternal(true)
        installOnWeChat(lpparam)
    }

    private fun installOnWeChat(lpparam: XC_LoadPackage.LoadPackageParam) {
        val process = lpparam.processName ?: WECHAT_PKG
        val isMain = process == WECHAT_PKG

        try {
            XposedHelpers.findAndHookMethod(
                Application::class.java,
                "attach",
                Context::class.java,
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val app = param.thisObject as? Application ?: return
                        val base = param.args.firstOrNull() as? Context ?: app
                        val effectiveLoader = base.classLoader ?: app.classLoader ?: lpparam.classLoader
                        onWeChatReady(app, effectiveLoader, process, isMain)
                    }
                },
            )
        } catch (_: Throwable) {
        }

        try {
            XposedHelpers.findAndHookMethod(
                Application::class.java,
                "onCreate",
                object : XC_MethodHook() {
                    override fun afterHookedMethod(param: MethodHookParam) {
                        val app = param.thisObject as? Application ?: return
                        onWeChatReady(app, app.classLoader ?: lpparam.classLoader, process, isMain)
                    }
                },
            )
        } catch (_: Throwable) {
        }
    }

    private fun onWeChatReady(
        app: Application,
        loader: ClassLoader,
        process: String,
        isMain: Boolean,
    ) {
        if (!started.compareAndSet(false, true)) return

        try {
            val host = XposedHost(app, loader, process)
            val eng = WxDbEngine(host)
            engine = eng

            eng.installHooks()

            if (isMain) {
                val peerAuth = PeerAuth(app)
                val s = LoopbackServer(eng, Channel.PORT, peerAuth)
                s.start()
                server = s
            }
        } catch (_: Throwable) {
        }
    }

    companion object {
        const val WECHAT_PKG = "com.tencent.mm"
        private val started = AtomicBoolean(false)

        @Volatile
        private var engine: WxDbEngine? = null

        @Volatile
        private var server: LoopbackServer? = null

        @Suppress("unused")
        private val keepBridgeRef = XposedBridge::class.java
    }
}
