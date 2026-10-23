package io.github.ryf5584.wxdbdump.xposed;

import java.io.File;

import io.github.ryf5584.wxdbdump.payload.crypto.SqlCipherPages;

/**
 * Pure-Java in-memory database decryptor for Xposed mode.
 *
 * <h3>Why this never calls WeChat's WCDB or writes staging files</h3>
 * <ol>
 *   <li>Calling {@code com.tencent.wcdb.database.SQLiteDatabase.openDatabase} and executing
 *       {@code ATTACH DATABASE ... AS plaintext} / {@code SELECT sqlcipher_export('plaintext')}
 *       inside WeChat runs straight through WeChat's global {@code libwcdb.so} SQL trace and
 *       error monitors.</li>
 *   <li>Writing temporary files into {@code /data/data/com.tencent.mm/cache/wxdump-plain/}
 *       exposes plaintext files and recognizable paths to WeChat's I/O monitors.</li>
 * </ol>
 *
 * <p>Instead, decryption reads the source database in read-only mode and streams decrypted
 * pages directly into the socket via {@link SqlCipherPages}, leaving zero files on disk and
 * zero trace in WCDB.
 */
public final class PlainDumper {

    public static final class Result {
        public final boolean ok;
        public final String reason;
        public final long size;
        public final int pageSize;
        public final int pages;
        public final File sourceFile;

        Result(boolean ok, String reason, long size, int pageSize, int pages, File sourceFile) {
            this.ok = ok;
            this.reason = reason;
            this.size = size;
            this.pageSize = pageSize;
            this.pages = pages;
            this.sourceFile = sourceFile;
        }

        public static Result fail(String r) {
            return new Result(false, r, 0, 0, 0, null);
        }

        public static Result good(long size, int pageSize, int pages, File sourceFile) {
            return new Result(true, null, size, pageSize, pages, sourceFile);
        }
    }

    private PlainDumper() {
    }

    /**
     * Verifies that {@code src} can be decrypted with {@code key} and computes the exact
     * plaintext byte size without writing anything to disk.
     */
    public static Result inspect(String src, byte[] key) {
        if (key == null || key.length == 0) return Result.fail("no key");
        File realSrc = firstExisting(src, altForm(src));
        if (realSrc == null) return Result.fail("source database not found");

        SqlCipherPages.Inspection ins = SqlCipherPages.inspect(realSrc, key);
        if (!ins.ok) {
            return Result.fail(ins.reason != null ? ins.reason : "page inspection failed");
        }
        return Result.good(ins.plainSize, ins.pageSize, ins.pages, realSrc);
    }

    /**
     * Streams the decrypted pages of {@code inspected.sourceFile} directly into {@code sink}
     * in memory, creating zero temporary files on disk.
     */
    public static long streamTo(Result inspected, byte[] key, SqlCipherPages.ChunkSink sink) throws Exception {
        return SqlCipherPages.streamDecrypted(
                inspected.sourceFile, key, inspected.pageSize, inspected.pages, sink);
    }

    private static File firstExisting(String... paths) {
        for (String p : paths) {
            if (p != null) {
                File f = new File(p);
                if (f.exists() && f.canRead()) return f;
            }
        }
        return null;
    }

    /** Converts between the /data/user/0 and /data/data path forms. */
    public static String altForm(String p) {
        if (p == null) return null;
        if (p.startsWith("/data/user/0/")) return "/data/data/" + p.substring("/data/user/0/".length());
        if (p.startsWith("/data/data/")) return "/data/user/0/" + p.substring("/data/data/".length());
        return p;
    }
}
