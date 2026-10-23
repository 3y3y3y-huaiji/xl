package io.github.ryf5584.wxdbdump.payload.proto;

/**
 * Loopback channel constants shared by the app and the Xposed module.
 *
 * <p>No static token lives here anymore. Instead, before each loopback connection the app
 * issues a single-use 256-bit token bound to the client's HELLO nonce in {@link TokenStore},
 * and the module inside WeChat retrieves and burns that token through the app's Binder
 * ContentProvider ({@link #AUTH_AUTHORITY}).
 *
 * <p>Security properties:
 * <ul>
 *   <li>The app's ContentProvider checks {@code Binder.getCallingUid()} (enforced by the
 *       Linux kernel Binder driver) and only releases a token to WeChat's UID.</li>
 *   <li>The module inside WeChat checks that the installed {@link #APP_PACKAGE} APK carries
 *       the exact same signing certificate (SHA-256) as the module APK injected by LSPosed.</li>
 *   <li>Each token is bound to a single connection nonce, expires within 15 seconds, and is
 *       erased immediately on first read.</li>
 * </ul>
 */
public final class Channel {

    /** Loopback port. */
    public static final int PORT = 27183;

    /** Host application package name. */
    public static final String APP_PACKAGE = "io.github.ryf5584.wxdbdump";

    /** Target WeChat package name. */
    public static final String WECHAT_PACKAGE = "com.tencent.mm";

    /** Binder ContentProvider authority serving single-use handshake tokens to WeChat. */
    public static final String AUTH_AUTHORITY = APP_PACKAGE + ".auth";

    /** Content URI used for URI permission grants (Android 11+ package visibility) and Binder calls. */
    public static final String AUTH_URI = "content://" + AUTH_AUTHORITY + "/token";

    /** ContentProvider.call() method that atomically consumes the one-time token for a HELLO nonce. */
    public static final String AUTH_METHOD_CONSUME = "consume_token";

    /** Bundle key holding the consumed one-time token. */
    public static final String AUTH_KEY_TOKEN = "token";

    /** Client version, reported in HELLO. */
    public static final String CLIENT_VERSION = "1.0.0";

    private Channel() {
    }
}
