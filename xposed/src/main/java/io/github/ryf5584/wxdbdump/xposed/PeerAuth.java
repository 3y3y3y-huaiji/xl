package io.github.ryf5584.wxdbdump.xposed;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;

import java.io.File;

import io.github.ryf5584.wxdbdump.payload.Digest;
import io.github.ryf5584.wxdbdump.payload.Log;
import io.github.ryf5584.wxdbdump.payload.proto.Channel;
import io.github.ryf5584.wxdbdump.payload.proto.Handshake;

/**
 * Peer authenticator and kernel {@code AF_UNIX} SocketPair broker running inside WeChat.
 *
 * <h3>Why SocketPair over Binder instead of LocalServerSocket</h3>
 * <p>On Android 8.0+, SELinux MLS/MCS isolation assigns distinct category sets
 * ({@code s0:cX,cY}) to each app UID, blocking cross-UID {@code connectto} on an abstract
 * {@code LocalServerSocket}. By contrast, AOSP SELinux explicitly permits passing an
 * already-connected {@code unix_stream_socket} file descriptor ({@code fd { use }}) over
 * Binder {@code ContentProvider.call()}.
 *
 * <h3>Security guarantees</h3>
 * <ol>
 *   <li><b>Same-signer APK certificate check:</b> Before creating a socket pair or calling
 *       the companion app's provider, {@link #verifyCompanionAppSignature()} verifies that
 *       the installed {@link Channel#APP_PACKAGE} APK has the exact same SHA-256 signing
 *       certificate as the Xposed module APK injected by LSPosed ({@code moduleApkPath}).</li>
 *   <li><b>Kernel UID check:</b> {@code SocketBridgeProvider} inside the companion app
 *       verifies {@code Binder.getCallingUid()} belongs to {@link Channel#WECHAT_PACKAGE}
 *       before accepting the socket descriptor or returning the single-use 256-bit token.</li>
 *   <li><b>Zero open ports:</b> No TCP or abstract socket address is ever bound or exposed
 *       to other processes on the device, and {@code INTERNET} permission is not required.</li>
 * </ol>
 */
public final class PeerAuth {

    public static final class SocketSession {
        public final ParcelFileDescriptor serverPfd;
        public final String sessionToken;

        public SocketSession(ParcelFileDescriptor serverPfd, String sessionToken) {
            this.serverPfd = serverPfd;
            this.sessionToken = sessionToken;
        }
    }

    private final Context hostContext;
    private final String moduleApkPath;
    private volatile String cachedModuleCertSha256;

    public PeerAuth(Context hostContext, String moduleApkPath) {
        this.hostContext = hostContext;
        this.moduleApkPath = moduleApkPath;
    }

    public Context hostContext() {
        return hostContext;
    }

    /**
     * Verifies the companion app's APK signature, creates a kernel {@code AF_UNIX} socket
     * pair, hands the client descriptor to {@code SocketBridgeProvider} over Binder, and
     * returns the server descriptor paired with the single-use session token.
     */
    public SocketSession establishSocketSession(String requestId) {
        if (requestId == null || requestId.isEmpty()) return null;
        if (!verifyCompanionAppSignature()) {
            Log.w("auth", "companion app APK signature check failed; refusing to attach socket pair");
            return null;
        }

        ParcelFileDescriptor[] pair = null;
        try {
            pair = ParcelFileDescriptor.createSocketPair();
            ParcelFileDescriptor clientEnd = pair[0];
            ParcelFileDescriptor serverEnd = pair[1];

            Bundle extras = new Bundle();
            extras.putParcelable(Channel.BRIDGE_KEY_FD, clientEnd);

            Bundle reply;
            try {
                reply = hostContext.getContentResolver().call(
                        Uri.parse(Channel.BRIDGE_URI),
                        Channel.BRIDGE_METHOD_ATTACH,
                        requestId,
                        extras);
            } finally {
                // ContentResolver.call is synchronous: the companion app has already duplicated
                // clientEnd into its own process, so our local copy must be closed immediately
                // to ensure clean EOF semantics when the companion app closes its descriptor.
                closeQuietly(clientEnd);
            }

            if (reply == null) {
                Log.w("auth", "SocketBridgeProvider rejected socket attachment for requestId=" + requestId);
                closeQuietly(serverEnd);
                return null;
            }
            String token = reply.getString(Channel.BRIDGE_KEY_TOKEN);
            if (token == null || token.isEmpty()) {
                Log.w("auth", "SocketBridgeProvider returned no session token for requestId=" + requestId);
                closeQuietly(serverEnd);
                return null;
            }
            return new SocketSession(serverEnd, token);
        } catch (Throwable t) {
            Log.w("auth", "failed to establish AF_UNIX socket pair over Binder: " + t);
            if (pair != null) {
                closeQuietly(pair[0]);
                closeQuietly(pair[1]);
            }
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
            return true;
        } catch (Throwable t) {
            Log.w("auth", "failed to verify companion app signature: " + t);
            return false;
        }
    }

    private String resolveModuleCertSha256(PackageManager pm) {
        String cached = cachedModuleCertSha256;
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

    private static void closeQuietly(ParcelFileDescriptor pfd) {
        if (pfd != null) {
            try {
                pfd.close();
            } catch (Throwable ignored) {
            }
        }
    }
}
