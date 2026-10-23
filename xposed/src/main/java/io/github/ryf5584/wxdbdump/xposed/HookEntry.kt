package io.github.ryf5584.wxdbdump.xposed

import android.app.Application
import android.content.Context
import android.os.Build
import com.highcapable.yukihookapi.annotation.xposed.InjectYukiHookWithXposed
import com.highcapable.yukihookapi.hook.factory.configs
import com.highcapable.yukihookapi.hook.factory.encase
import com.highcapable.yukihookapi.hook.type.android.ApplicationClass
import com.highcapable.yukihookapi.hook.xposed.proxy.IYukiHookXposedInit
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import io.github.ryf5584.wxdbdump.payload.Log
import io.github.ryf5584.wxdbdump.payload.proto.Channel
import java.util.concurrent.atomic.AtomicBoolean

@InjectYukiHookWithXposed(isUsingResourcesHook = false)
class HookEntry : IYukiHookXposedInit {

    override fun onInit() = configs {
        isDebug = false
        debugLog {
            tag = "zygote"
            isEnable = false
        }
    }

    override fun onHook() = encase {
        // Silent inside WeChat
    }

    override fun onXposedEvent() {
        com.highcapable.yukihookapi.hook.xposed.bridge.event.YukiXposedEvent.onHandleLoadPackage { lpparam ->
            if (lpparam.packageName != WECHAT_PKG) return@onHandleLoadPackage
            Log.setSilentExternal(true)
            installOnWeChat(lpparam)
        }
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
        } catch (t: Throwable) {
            // Silent
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
        } catch (t: Throwable) {
            // Silent
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

            val hookSummary = eng.installHooks()

            if (isMain) {
                val peerAuth = PeerAuth(app)
                val s = LoopbackServer(eng, Channel.PORT, peerAuth)
                s.start()
                server = s
            }
            Log.banner(
                "WECHAT READY",
                "proc=$process (isMain=$isMain) pid=${android.os.Process.myPid()}\n" +
                    "sdk=${Build.VERSION.SDK_INT} abi=${Build.SUPPORTED_ABIS.firstOrNull()}\n" +
                    "hooks=$hookSummary\n" +
                    "loopback=${if (isMain) "127.0.0.1:${Channel.PORT}" else "disabled"}",
            )
        } catch (t: Throwable) {
            // Never crash WeChat
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
