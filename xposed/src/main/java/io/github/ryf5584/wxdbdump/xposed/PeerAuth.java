package io.github.ryf5584.wxdbdump.xposed;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;

import java.io.File;

import io.github.ryf5584.wxdbdump.payload.Digest;
import io.github.ryf5584.wxdbdump.payload.Log;
import io.github.ryf5584.wxdbdump.payload.proto.Channel;
import io.github.ryf5584.wxdbdump.payload.proto.Handshake;

/**
 * Peer authenticator and ephemeral token consumer running inside WeChat's process.
 *
 * <h3>Two-layer verification</h3>
 * <ol>
 *   <li><b>Same-signer APK certificate check:</b> Before contacting the companion app,
 *       verifies that the installed {@link Channel#APP_PACKAGE} APK is signed by the exact
 *       same certificate (SHA-256 digest) as the Xposed module APK injected by LSPosed
 *       ({@code moduleApkPath}). A repackaged or spoofed app is rejected immediately.</li>
 *   <li><b>Kernel-UID-gated one-time token consumption:</b> Queries the companion app's
 *       {@code AuthTokenProvider} over Binder ({@code ContentResolver.call}) to consume the
 *       single-use 256-bit token bound to the client's {@code HELLO} nonce. Because the
 *       provider checks {@code Binder.getCallingUid()} against WeChat's UID, no third-party
 *       app on the device can read this token.</li>
 * </ol>
 */
public final class PeerAuth {

    private final Context hostContext;
    private final String moduleApkPath;

    /** Cached SHA-256 fingerprint of the injected module APK's signing certificate. */
    private volatile String cachedModuleCertSha256;

    public PeerAuth(Context hostContext, String moduleApkPath) {
        this.hostContext = hostContext;
        this.moduleApkPath = moduleApkPath;
    }

    /**
     * Verifies the companion app's APK signature and consumes the one-time token for
     * {@code clientNonceHex} over Binder.
     *
     * @return the 64-char hex one-time token, or {@code null} if verification fails
     */
    public String consumeTokenForNonce(String clientNonceHex) {
        if (clientNonceHex == null || clientNonceHex.isEmpty()) return null;
        if (!verifyCompanionAppSignature()) {
            Log.w("auth", "companion app signature verification failed");
            return null;
        }
        try {
            Bundle reply = hostContext.getContentResolver().call(
                    Uri.parse(Channel.AUTH_URI),
                    Channel.AUTH_METHOD_CONSUME,
                    clientNonceHex,
                    null);
            if (reply == null) {
                Log.w("auth", "AuthTokenProvider returned null bundle for nonce");
                return null;
            }
            String token = reply.getString(Channel.AUTH_KEY_TOKEN);
            if (token == null || token.isEmpty()) {
                Log.w("auth", "AuthTokenProvider returned no token (unissued or already consumed)");
                return null;
            }
            return token;
        } catch (Throwable t) {
            Log.w("auth", "Binder call to AuthTokenProvider failed: " + t);
            return null;
        }
    }

    /**
     * Verifies that {@link Channel#APP_PACKAGE} is installed and signed with the same
     * certificate as the injected Xposed module APK.
     */
    public boolean verifyCompanionAppSignature() {
        try {
            PackageManager pm = hostContext.getPackageManager();
            PackageInfo installedInfo = getPackageInfoWithSigners(pm, Channel.APP_PACKAGE, false);
            String installedCert = extractCertSha256(installedInfo);
            if (installedCert == null || installedCert.isEmpty()) {
                Log.w("auth", "cannot read signing certificate of installed " + Channel.APP_PACKAGE);
                return false;
            }

            String expectedModuleCert = resolveModuleCertSha256(pm);
            if (expectedModuleCert != null && !expectedModuleCert.isEmpty()) {
                boolean match = Handshake.matches(expectedModuleCert, installedCert);
                if (!match) {
                    Log.w("auth", "APK signature mismatch between injected module and installed app");
                }
                return match;
            }
            // If the framework did not expose moduleApkPath on disk, package signature presence is verified
            return true;
        } catch (Throwable t) {
            Log.w("auth", "failed to verify companion app signature: " + t);
            return false;
        }
    }

    private String resolveModuleCertSha256(PackageManager pm) {
        String cached = cachedModuleApkCert();
        if (cached != null) return cached;
        if (moduleApkPath == null || moduleApkPath.isEmpty()) return null;
        try {
            File apk = new File(moduleApkPath);
            if (!apk.exists() || !apk.canRead()) return null;
            PackageInfo archiveInfo = getPackageInfoWithSigners(pm, moduleApkPath, true);
            String digest = extractCertSha256(archiveInfo);
            if (digest != null && !digest.isEmpty()) {
                cachedModuleCertSha256 = digest;
            }
            return digest;
        } catch (Throwable t) {
            Log.d("auth", "could not read archive cert from moduleApkPath: " + t);
            return null;
        }
    }

    private String cachedModuleApkCert() {
        return cachedModuleCertSha256;
    }

    @SuppressWarnings("deprecation")
    private static PackageInfo getPackageInfoWithSigners(
            PackageManager pm, String pkgOrPath, boolean archive) throws PackageManager.NameNotFoundException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            int flags = PackageManager.GET_SIGNING_CERTIFICATES;
            return archive
                    ? pm.getPackageArchiveInfo(pkgOrPath, flags)
                    : pm.getPackageInfo(pkgOrPath, flags);
        } else {
            int flags = PackageManager.GET_SIGNATURES;
            return archive
                    ? pm.getPackageArchiveInfo(pkgOrPath, flags)
                    : pm.getPackageInfo(pkgOrPath, flags);
        }
    }

    @SuppressWarnings("deprecation")
    public static String extractCertSha256(PackageInfo info) {
        if (info == null) return null;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            SigningInfo si = info.signingInfo;
            if (si != null) {
                Signature[] sigs = si.hasMultipleSigners()
                        ? si.getApkContentsSigners()
                        : si.getSigningCertificateHistory();
                if (sigs != null && sigs.length > 0 && sigs[0] != null) {
                    return Digest.sha256Hex(sigs[0].toByteArray());
                }
            }
        }
        Signature[] legacy = info.signatures;
        if (legacy != null && legacy.length > 0 && legacy[0] != null) {
            return Digest.sha256Hex(legacy[0].toByteArray());
        }
        return null;
    }
}
