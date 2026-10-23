package io.github.ryf5584.wxdbdump.payload.engine;

import java.io.File;

import io.github.ryf5584.wxdbdump.payload.EngineHost;
import io.github.ryf5584.wxdbdump.payload.Log;
import io.github.ryf5584.wxdbdump.payload.crypto.SqlCipherPages;

/**
 * Pure-Java read-only key verifier.
 *
 * <p>Why this no longer calls {@code com.tencent.wcdb.core.Database.canOpen()}:
 * Constructing a second {@code Database} instance inside WeChat and probing page sizes
 * triggers native {@code libwcdb.so} error/telemetry callbacks (e.g. {@code SQLITE_NOTADB})
 * and re-enters our own hooks. Verifying the key against the first pages with
 * {@link SqlCipherPages#inspect(File, byte[])} uses only read-only {@code RandomAccessFile}
 * and {@code javax.crypto}, leaving zero trace in WeChat's WCDB layer.
 */
public final class WcdbVerifier {

    private WcdbVerifier() {
    }

    /** Result of one verification attempt. */
    public static final class Verdict {
        public final boolean ok;
        public final int pageSize;
        public final String detail;

        Verdict(boolean ok, int pageSize, String detail) {
            this.ok = ok;
            this.pageSize = pageSize;
            this.detail = detail;
        }
    }

    /**
     * Verifies {@code key} against {@code path} using pure-Java read-only page inspection.
     */
    public static Verdict verify(EngineHost host, String path, byte[] key, int pageSize) {
        if (key == null || key.length == 0) {
            return new Verdict(false, 0, "empty key");
        }
        if (path == null || path.isEmpty()) {
            return new Verdict(false, 0, "empty path");
        }
        File f = new File(path);
        if (!f.exists()) {
            String alt = altForm(path);
            if (alt != null) f = new File(alt);
        }
        SqlCipherPages.Inspection ins = SqlCipherPages.inspect(f, key);
        if (ins.ok) {
            Log.i("wcdb", "passive verify OK pageSize=" + ins.pageSize + " path=" + path);
            return new Verdict(true, ins.pageSize, "pages-ok");
        }
        int fallbackPs = pageSize > 0 ? pageSize : 1024;
        return new Verdict(false, fallbackPs, ins.reason != null ? ins.reason : "inspect failed");
    }

    private static String altForm(String p) {
        if (p == null) return null;
        if (p.startsWith("/data/user/0/")) return "/data/data/" + p.substring("/data/user/0/".length());
        if (p.startsWith("/data/data/")) return "/data/user/0/" + p.substring("/data/data/".length());
        return null;
    }
}
