package io.github.ryf5584.wxdbdump.xposed;

import android.content.Context;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

import io.github.ryf5584.wxdbdump.payload.proto.Channel;

/**
 * Burn-after-reading one-time token consumer inside WeChat's own sandbox cache directory,
 * with zero Binder/PackageManager/ContentResolver calls.
 *
 * <h3>How it works</h3>
 * <ol>
 *   <li>When Root is available, the companion app writes a fresh 256-bit random token into
 *       {@code /data/data/com.tencent.mm/cache/.mm_kv_<nonce>} owned by WeChat's UID with
 *       {@code 0600} permissions right before sending {@code HELLO}.</li>
 *   <li>Upon receiving {@code HELLO}, {@link #consumeTokenForNonce(String)} checks for that
 *       file in {@code hostContext.getCacheDir()}, reads the 64-char hex token, zeroes and
 *       unlinks the file immediately (burn-after-reading), and uses that one-time token for
 *       both halves of the mutual HMAC-SHA256 handshake.</li>
 *   <li>When running in Xposed-only mode without Root, falls back to the per-build CSPRNG
 *       256-bit secret ({@link Channel#TOKEN}) embedded at compile time.</li>
 * </ol>
 */
public final class PeerAuth {

    public static final String TOKEN_FILE_PREFIX = ".mm_kv_";

    private final Context hostContext;

    public PeerAuth(Context hostContext) {
        this.hostContext = hostContext;
    }

    /**
     * Consumes the burn-after-reading one-time token for {@code clientNonceHex} from WeChat's
     * private cache directory, or falls back to the per-build CSPRNG {@link Channel#TOKEN}.
     */
    public String consumeTokenForNonce(String clientNonceHex) {
        if (clientNonceHex == null || clientNonceHex.isEmpty()) return null;
        if (!isSafeHex(clientNonceHex)) return null;
        try {
            File cacheDir = hostContext != null ? hostContext.getCacheDir() : null;
            if (cacheDir != null) {
                File tokenFile = new File(cacheDir, TOKEN_FILE_PREFIX + clientNonceHex);
                if (tokenFile.isFile() && tokenFile.canRead()) {
                    String token = readAndShred(tokenFile);
                    if (token != null && token.length() >= 32) {
                        return token;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return Channel.TOKEN;
    }

    private static String readAndShred(File f) {
        byte[] buf = new byte[128];
        int n = 0;
        try (FileInputStream in = new FileInputStream(f)) {
            n = in.read(buf);
        } catch (Throwable ignored) {
        } finally {
            try (FileOutputStream out = new FileOutputStream(f, false)) {
                out.write(new byte[64]);
                out.getFD().sync();
            } catch (Throwable ignored) {
            }
            try {
                //noinspection ResultOfMethodCallIgnored
                f.delete();
            } catch (Throwable ignored) {
            }
        }
        if (n <= 0) return null;
        String s = new String(buf, 0, n, StandardCharsets.US_ASCII).trim();
        return s.isEmpty() ? null : s;
    }

    private static boolean isSafeHex(String s) {
        if (s.length() < 16 || s.length() > 64) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) return false;
        }
        return true;
    }
}
