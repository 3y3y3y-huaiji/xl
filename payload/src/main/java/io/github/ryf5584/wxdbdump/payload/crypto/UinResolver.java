package io.github.ryf5584.wxdbdump.payload.crypto;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.github.ryf5584.wxdbdump.payload.EngineHost;
import io.github.ryf5584.wxdbdump.payload.Log;
import io.github.ryf5584.wxdbdump.payload.paths.WeChatPaths;

/**
 * Recovers an account's uin purely from on-disk files, with zero reflective calls into
 * WeChat's in-process {@code com.tencent.mmkv.MMKV}.
 *
 * <p>The account directory name is {@code md5hex("mm" + uin)}, which gives an exact
 * mathematical check for any candidate integer or string found in
 * {@code system_config_prefs.xml} or the unencrypted {@code mmkv_private/ConfigStorage1} file.
 */
public final class UinResolver {

    /** default_uin inside the preferences XML. */
    private static final Pattern INT_PREF =
            Pattern.compile("<int\\s+name=\"([^\"]+)\"\\s+value=\"(-?\\d+)\"");

    /** Printable wxid pattern inside unencrypted MMKV storage. */
    private static final Pattern WXID_PATTERN =
            Pattern.compile("wxid_[0-9a-zA-Z_]{6,32}");

    /** Printable numeric uin candidate inside unencrypted MMKV storage. */
    private static final Pattern DIGITS_PATTERN =
            Pattern.compile("(?<!\\d)(-?\\d{5,11})(?!\\d)");

    private UinResolver() {
    }

    /** Recovery result, carrying any identity read from the account MMKV store. */
    public static final class Result {
        public final int uin;
        public final String source;
        /** wxid recorded in the account's own MMKV store. */
        public String wxid = "";
        /** Nickname recorded in the account's own MMKV store, when present. */
        public String nickname = "";

        Result(int uin, String source) {
            this.uin = uin;
            this.source = source;
        }

        public boolean ok() {
            return uin != 0;
        }
    }

    /**
     * Tries to recover the uin for one account directory without calling into host classes.
     */
    public static Result resolve(EngineHost host, String accountDir, String dirName) {
        // ---- A. default_uin from system_config_prefs.xml ----
        Integer fromPrefs = readDefaultUin(host);
        if (fromPrefs != null && matches(fromPrefs, dirName)) {
            Result r = new Result(fromPrefs, "system_config_prefs");
            scanRawMmkvFile(host, accountDir, dirName, r);
            return r;
        }

        // ---- B. Raw byte scan of the account's unencrypted mmkv_private/ConfigStorage1 ----
        Result r = new Result(0, "");
        Integer fromMmkv = scanRawMmkvFile(host, accountDir, dirName, r);
        if (fromMmkv != null && fromMmkv != 0) {
            Result hit = new Result(fromMmkv, "mmkv_private");
            hit.wxid = r.wxid;
            hit.nickname = r.nickname;
            return hit;
        }

        return r;
    }

    /**
     * Scans the raw bytes of {@code mmkv_private/ConfigStorage1} directly from disk.
     *
     * <p>Avoids calling {@code com.tencent.mmkv.MMKV.mmkvWithID} reflectively inside WeChat,
     * which can contend on MMKV locks or trip host instrumentation. Because {@code ConfigStorage1}
     * is unencrypted, both the wxid and uin candidates can be verified directly against
     * {@code md5("mm" + uin) == dirName}.
     */
    private static Integer scanRawMmkvFile(
            EngineHost host, String accountDir, String dirName, Result out) {
        try {
            String path = host.mmkvOpenRoot(accountDir) + "/" + WeChatPaths.MMKV_CONFIG_STORAGE;
            byte[] raw = host.files().readAll(path);
            if (raw == null || raw.length == 0) return null;

            String latin = new String(raw, StandardCharsets.ISO_8859_1);
            if (out.wxid == null || out.wxid.isEmpty()) {
                Matcher wm = WXID_PATTERN.matcher(latin);
                if (wm.find()) {
                    out.wxid = wm.group();
                }
            }

            // 1. Check ASCII digit runs against md5("mm" + uin) == dirName
            Matcher dm = DIGITS_PATTERN.matcher(latin);
            while (dm.find()) {
                try {
                    int candidate = Integer.parseInt(dm.group(1));
                    if (candidate != 0 && matches(candidate, dirName)) {
                        return candidate;
                    }
                } catch (NumberFormatException ignored) {
                }
            }

            // 2. Check protobuf varints (MMKV encodes int32 values as varints)
            for (int i = 0; i < raw.length; i++) {
                int v = readVarint32(raw, i);
                if (v != 0) {
                    if (matches(v, dirName)) return v;
                    int zigzag = (v >>> 1) ^ -(v & 1);
                    if (zigzag != 0 && matches(zigzag, dirName)) return zigzag;
                }
            }
        } catch (Throwable t) {
            Log.d("uin", "raw MMKV scan skipped: " + t);
        }
        return null;
    }

    private static int readVarint32(byte[] buf, int offset) {
        int result = 0;
        int shift = 0;
        for (int i = offset; i < buf.length && i < offset + 5; i++) {
            byte b = buf[i];
            result |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                return result;
            }
            shift += 7;
        }
        return 0;
    }

    /** Identity check between a directory name and a uin. */
    public static boolean matches(int uin, String dirName) {
        return uin != 0 && WeChatPaths.accountDirName(uin).equals(dirName);
    }

    /** Reads default_uin from system_config_prefs.xml by plain text parsing. */
    public static Integer readDefaultUin(EngineHost host) {
        try {
            byte[] raw = host.files().readAll(WeChatPaths.SYSTEM_CONFIG_PREFS);
            if (raw == null || raw.length == 0) return null;
            String xml = new String(raw, StandardCharsets.UTF_8);
            Matcher m = INT_PREF.matcher(xml);
            while (m.find()) {
                if (WeChatPaths.KEY_DEFAULT_UIN.equals(m.group(1))) {
                    int v = Integer.parseInt(m.group(2));
                    return v == 0 ? null : v;
                }
            }
        } catch (Throwable t) {
            Log.e("uin", "failed to read system_config_prefs", t);
        }
        return null;
    }

    /** Display helper: renders the uin as a four-part wxid-style string. Not reversible. */
    public static String maskUin(int uin) {
        if (uin == 0) return "--";
        String s = Integer.toString(Math.abs(uin));
        if (s.length() <= 4) return "wxid_" + s;
        return "wxid_" + s.substring(0, 4) + "…" + s.substring(s.length() - 3);
    }
}
