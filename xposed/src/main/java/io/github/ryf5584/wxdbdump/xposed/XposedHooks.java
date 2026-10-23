package io.github.ryf5584.wxdbdump.xposed;

import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import io.github.ryf5584.wxdbdump.payload.platform.Hooks;

/**
 * Stealth Xposed implementation of {@link Hooks} on top of XC_MethodHook.
 *
 * <p>Deliberately avoids hooking {@code java.lang.ClassLoader.loadClass}: hooking core
 * {@code boot.oat} methods puts {@code LSPHooker_} frames on every class-load stack trace
 * and is a primary anti-Xposed detection vector in WeChat.
 */
public final class XposedHooks implements Hooks {

    @Override
    public AutoCloseable hookMethod(Class<?> clazz, String methodName, Class<?>[] paramTypes, MethodHook cb) {
        Member member = resolve(clazz, methodName, paramTypes);
        if (member == null) {
            throw new IllegalArgumentException("method not found: " + clazz.getName() + "." + methodName);
        }
        return hookMember(member, cb);
    }

    private AutoCloseable hookMember(Member member, MethodHook cb) {
        XC_MethodHook bridge = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                HookCtx ctx = new HookCtx();
                ctx.thiz = param.thisObject;
                ctx.args = param.args;
                try {
                    cb.before(ctx);
                } catch (Throwable ignored) {
                    return;
                }
                if (ctx.isReplace()) param.setResult(ctx.replacement());
            }

            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                HookCtx ctx = new HookCtx();
                ctx.thiz = param.thisObject;
                ctx.args = param.args;
                ctx.result = param.getResult();
                ctx.error = param.hasThrowable() ? param.getThrowable() : null;
                try {
                    cb.after(ctx);
                } catch (Throwable ignored) {
                    return;
                }
                if (ctx.isReplace()) {
                    param.setResult(ctx.replacement());
                    if (param.hasThrowable()) param.setThrowable(null);
                }
            }
        };
        final XC_MethodHook.Unhook unhook = XposedBridge.hookMethod(member, bridge);
        return () -> {
            try {
                unhook.unhook();
            } catch (Throwable ignored) {
            }
        };
    }

    @Override
    public AutoCloseable watchClassLoad(String className, Consumer<Class<?>> onLoaded) {
        // Intentional no-op: never hook java.lang.ClassLoader.loadClass in WeChat.
        // WcdbKeyHooks already resolves loaded classes via timer-scheduled Class.forName.
        return () -> {};
    }

    @Override
    public AutoCloseable hookAllConstructors(Class<?> clazz, MethodHook cb) {
        List<XC_MethodHook.Unhook> unhooks = new ArrayList<>();
        for (java.lang.reflect.Constructor<?> c : clazz.getDeclaredConstructors()) {
            try {
                XC_MethodHook bridge = new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        HookCtx ctx = new HookCtx();
                        ctx.thiz = param.thisObject;
                        ctx.args = param.args;
                        try {
                            cb.after(ctx);
                        } catch (Throwable ignored) {
                        }
                    }
                };
                unhooks.add(XposedBridge.hookMethod(c, bridge));
            } catch (Throwable ignored) {
            }
        }
        if (unhooks.isEmpty()) throw new IllegalStateException("no constructor to hook: " + clazz.getName());
        return () -> {
            for (XC_MethodHook.Unhook u : unhooks) {
                try {
                    u.unhook();
                } catch (Throwable ignored) {
                }
            }
        };
    }

    @Override
    public boolean postToMainThread(Runnable r) {
        try {
            Class<?> looperCls = Class.forName("android.os.Looper");
            Class<?> handlerCls = Class.forName("android.os.Handler");
            Object mainLooper = looperCls.getMethod("getMainLooper").invoke(null);
            Object handler = handlerCls.getConstructor(looperCls).newInstance(mainLooper);
            handlerCls.getMethod("post", Runnable.class).invoke(handler, r);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    @Override
    public boolean onMainThread() {
        try {
            Class<?> looperCls = Class.forName("android.os.Looper");
            Object main = looperCls.getMethod("getMainLooper").invoke(null);
            Object mine = looperCls.getMethod("myLooper").invoke(null);
            return main != null && main.equals(mine);
        } catch (Throwable t) {
            return false;
        }
    }

    @Override
    public String describe() {
        return "Xposed";
    }

    private static Member resolve(Class<?> clazz, String name, Class<?>[] paramTypes) {
        try {
            if (paramTypes == null) {
                for (Method m : clazz.getDeclaredMethods()) {
                    if (m.getName().equals(name)) return m;
                }
                return null;
            }
            return clazz.getDeclaredMethod(name, paramTypes);
        } catch (NoSuchMethodException e) {
            return null;
        }
    }
}
