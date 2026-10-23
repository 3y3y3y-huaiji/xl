package io.github.ryf5584.wxdbdump.payload.proto;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import io.github.ryf5584.wxdbdump.payload.Digest;

/**
 * Zero-IPC stealth loopback channel configuration.
 *
 * <p>Why zero Binder/PackageManager calls inside WeChat:
 * Making cross-package {@code PackageManager}, {@code ContentResolver}, or
 * {@code registerReceiver} calls from inside WeChat's process exposes the module's package
 * name and class instances to WeChat's hooked Binder proxies and {@code mLoadedApk} tables.
 *
 * <p>Instead, at build time Gradle generates a cryptographically random port in
 * {@code 32000..58000} and a 256-bit secret into an internal JAR resource shared only by
 * the app and module packaged inside the same APK. Neither the port nor the secret appears
 * in source control, and the module inside WeChat makes zero Android IPC or PackageManager
 * calls.
 */
public final class Channel {

    private static final String RESOURCE_PATH = "/META-INF/services/jdk.internal.pref";

    /** Per-build randomized loopback port. */
    public static final int PORT;

    /** Per-build 256-bit handshake secret derived from the embedded build seed. */
    public static final String TOKEN;

    /** Client version, reported in HELLO. */
    public static final String CLIENT_VERSION = "1.0.0";

    static {
        int resolvedPort = 41893;
        String resolvedToken = Digest.sha256Hex("fallback-build-seed".getBytes(StandardCharsets.UTF_8));
        try (InputStream in = Channel.class.getResourceAsStream(RESOURCE_PATH)) {
            if (in != null) {
                BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
                String line = br.readLine();
                if (line != null) {
                    String[] parts = line.trim().split(":", 2);
                    if (parts.length == 2) {
                        int p = Integer.parseInt(parts[0].trim());
                        String t = parts[1].trim();
                        if (p >= 1024 && p <= 65535 && t.length() >= 32) {
                            resolvedPort = p;
                            resolvedToken = Digest.sha256Hex(
                                    (p + ":" + t + ":stealth-v1").getBytes(StandardCharsets.UTF_8));
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        PORT = resolvedPort;
        TOKEN = resolvedToken;
    }

    private Channel() {
    }
}
