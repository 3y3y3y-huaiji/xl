package io.github.ryf5584.wxdbdump.xposed

import com.highcapable.yukihookapi.annotation.xposed.InjectYukiHookWithXposed
import com.highcapable.yukihookapi.hook.entity.YukiBaseHooker
import com.highcapable.yukihookapi.hook.factory.configs
import com.highcapable.yukihookapi.hook.factory.encase
import com.highcapable.yukihookapi.hook.xposed.proxy.IYukiHookXposedInit
import io.github.ryf5584.wxdbdump.payload.Log
import io.github.ryf5584.wxdbdump.payload.proto.Channel

/**
 * Stealth YukiHookAPI entry point.
 *
 * <p>Anti-detection measures inside the host process:
 * <ul>
 *   <li>External logcat and stdout output is silenced completely (`Log.setSilentExternal(true)`),
 *       so WeChat's in-process logcat scanner sees zero `WxDbExport` lines.</li>
 *   <li>`Thread.setDefaultUncaughtExceptionHandler` is never touched, preserving WeChat's own
 *       Matrix/crash handler chain untouched.</li>
 *   <li>No `onHandleLoadPackage` banner or extra Xposed event callbacks are registered.</li>
 * </ul>
 */
@InjectYukiHookWithXposed
object HookEntry : IYukiHookXposedInit {

    override fun onInit() {
        Log.setSilentExternal(true)
        configs {
            isDebug = false
            isEnableModuleAppResourcesCache = false
            isEnableHookSharedPreferences = false
            isEnableDataChannel = false
        }
    }

    override fun onHook() = encase(WxDbExportHooker())
}

/** Runs once per WeChat process. */
class WxDbExportHooker : YukiBaseHooker() {

    override fun onHook() {
        onAppLifecycle {
            onCreate { startEngine() }
        }
    }

    private fun startEngine() {
        try {
            Log.setSilentExternal(true)
            val app = appContext ?: return
            val proc = XposedHost.currentProcessName(app)
            if (WECHAT_MAIN_PROCESS != proc) {
                return
            }

            val host = XposedHost(app, appClassLoader, proc)
            val engine = WxDbEngine(host)
            engine.installHooks()
            LoopbackServer(engine, Channel.PORT, Channel.TOKEN).start()
        } catch (ignored: Throwable) {
            // Never crash or log into WeChat
        }
    }

    private companion object {
        const val WECHAT_MAIN_PROCESS = "com.tencent.mm"
    }
}
