package io.github.ryf5584.wxdbdump.xposed;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import io.github.ryf5584.wxdbdump.payload.Digest;
import io.github.ryf5584.wxdbdump.payload.Log;
import io.github.ryf5584.wxdbdump.payload.engine.KeyVault;
import io.github.ryf5584.wxdbdump.payload.discovery.DatabaseEnumerator;
import io.github.ryf5584.wxdbdump.payload.model.Account;
import io.github.ryf5584.wxdbdump.payload.model.DbFile;
import io.github.ryf5584.wxdbdump.payload.proto.Channel;
import io.github.ryf5584.wxdbdump.payload.proto.Handshake;
import io.github.ryf5584.wxdbdump.payload.proto.Wire;

/**
 * Unix domain SocketPair server inside WeChat's process.
 *
 * <p>No TCP port or {@code LocalServerSocket} is opened. Instead, when the companion app
 * requests a session via {@link Channel#ACTION_CONNECT}, {@link PeerAuth} verifies the
 * companion app's APK signing certificate (SHA-256), creates a kernel {@code AF_UNIX}
 * stream socket pair ({@link ParcelFileDescriptor#createSocketPair()}), and hands the
 * client descriptor to {@code SocketBridgeProvider} over Binder (which enforces
 * {@code Binder.getCallingUid() == wechatUid}).
 *
 * <p>Both sides then run the mutual HMAC handshake over the single-use 256-bit token
 * returned by the provider before any command is accepted.
 */
public final class LoopbackServer {

    private final WxDbEngine engine;
    private final PeerAuth peerAuth;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private BroadcastReceiver connectReceiver;

    public LoopbackServer(WxDbEngine engine, PeerAuth peerAuth) {
        this.engine = engine;
        this.peerAuth = peerAuth;
    }

    /** Registers the session-request receiver inside WeChat. Never crashes the host process. */
    @SuppressWarnings("UnspecifiedRegisterReceiverFlag")
    public void start() {
        if (!running.compareAndSet(false, true)) return;
        try {
            Context ctx = peerAuth.hostContext();
            IntentFilter filter = new IntentFilter(Channel.ACTION_CONNECT);
            connectReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    if (!running.get() || intent == null) return;
                    if (!Channel.ACTION_CONNECT.equals(intent.getAction())) return;
                    final String reqId = intent.getStringExtra(Channel.EXTRA_REQUEST_ID);
                    if (reqId == null || reqId.isEmpty()) return;
                    Thread h = new Thread(() -> connectAndHandle(reqId), "wxdump-unix-conn");
                    h.setDaemon(true);
                    h.start();
                }
            };
            if (Build.VERSION.SDK_INT >= 33) {
                // Context.RECEIVER_EXPORTED = 0x2
                ctx.registerReceiver(connectReceiver, filter, 0x2);
            } else {
                ctx.registerReceiver(connectReceiver, filter);
            }
            Log.i("net", "unix socketpair bridge registered on action=" + Channel.ACTION_CONNECT);
        } catch (Throwable t) {
            Log.e("net", "failed to register unix socketpair bridge receiver", t);
            running.set(false);
        }
    }

    public void stop() {
        running.set(false);
        try {
            if (connectReceiver != null) {
                peerAuth.hostContext().unregisterReceiver(connectReceiver);
                connectReceiver = null;
            }
        } catch (Throwable ignored) {
        }
    }

    private void connectAndHandle(String requestId) {
        PeerAuth.SocketSession session = peerAuth.establishSocketSession(requestId);
        if (session == null) {
            return;
        }
        handle(session.serverPfd, session.sessionToken);
    }

    private void handle(ParcelFileDescriptor pfd, String sessionToken) {
        long t0 = System.currentTimeMillis();
        try (DataInputStream in = new DataInputStream(new ParcelFileDescriptor.AutoCloseInputStream(pfd));
             BufferedOutputStream out = new BufferedOutputStream(new ParcelFileDescriptor.AutoCloseOutputStream(pfd))) {
            Log.i("net", "accepted AF_UNIX socketpair session");

            // ---- Handshake ----
            Wire.Frame f = Wire.read(in);
            String hello = f.text();
            if (f.type != Wire.TYPE_TEXT || !Handshake.isHello(hello)) {
                Log.w("net", "handshake failed, first frame is not HELLO (type=" + f.type + ", head=" + head(hello));
                Wire.writeText(out, Handshake.ackBad("BAD_HELLO"));
                return;
            }
            String nonce = Handshake.extractNonce(hello);
            if (nonce == null) {
                Log.w("net", "handshake failed, no nonce in HELLO (head=" + head(hello) + ")");
                Wire.writeText(out, Handshake.ackBad("NO_NONCE"));
                return;
            }
            Log.i("net", "received HELLO nonce=" + nonce);

            String moduleNonce = Handshake.newNonce();
            Wire.writeText(out, Handshake.ack(nonce, moduleNonce, sessionToken));

            Wire.Frame authFrame = Wire.read(in);
            String authLine = authFrame.text();
            if (authFrame.type != Wire.TYPE_TEXT || !Handshake.isAuth(authLine)) {
                Log.w("net", "handshake failed, expected AUTH (type=" + authFrame.type
                        + ", head=" + head(authLine) + ")");
                Wire.writeText(out, Handshake.ackBad("BAD_AUTH"));
                return;
            }
            if (!Handshake.matches(Handshake.proof(moduleNonce, sessionToken),
                    Handshake.extractProof(authLine))) {
                Log.w("net", "handshake failed, AUTH proof mismatch");
                Wire.writeText(out, Handshake.ackBad("BAD_TOKEN"));
                return;
            }
            Wire.writeText(out, Handshake.ready());
            Log.i("net", "handshake complete over AF_UNIX socketpair, commands accepted");

            // ---- Command loop ----
            while (running.get()) {
                Wire.Frame cmd = Wire.read(in);
                if (cmd.type != Wire.TYPE_TEXT) {
                    Log.d("net", "ignoring a non-text frame, type=" + cmd.type);
                    continue;
                }
                String line = cmd.text();
                if (line == null || line.isEmpty()) continue;
                if (!serve(line, out)) break;
            }
        } catch (Throwable t) {
            // Connection closed; a client-side close lands here and is normal
            Log.i("net", "session closed after " + (System.currentTimeMillis() - t0) + "ms: " + t);
        } finally {
            try {
                pfd.close();
            } catch (Throwable ignored) {
            }
        }
    }

    private static String head(String s) {
        if (s == null) return "null";
        return s.length() <= 80 ? s : s.substring(0, 80) + "…";
    }

    /**
     * Pushes enumeration progress to the app as {@code #P {...}} text frames.
     *
     * <p>The {@code #P } prefix separates progress from results: the app's read loop treats
     * it as a callback rather than a return value, so progress needs no extra channel.
     */
    private static io.github.ryf5584.wxdbdump.payload.Progress progressWriter(BufferedOutputStream out) {
        return (done, total, stage) -> {
            try {
                Wire.writeText(out, "#P {\"done\":" + done + ",\"total\":" + total
                        + ",\"stage\":\"" + esc(stage) + "\"}");
            } catch (Throwable ignored) {
                // A failed progress push must not affect enumeration
            }
        };
    }

    /** Streams a file back in chunks; shared by FETCH (ciphertext) and DUMP (plaintext). */
    private static long streamFile(File f, BufferedOutputStream out) throws Exception {
        long sent = 0;
        FileInputStream fin = new FileInputStream(f);
        try {
            byte[] buf = new byte[64 * 1024];
            int r;
            while ((r = fin.read(buf)) > 0) {
                byte[] chunk = new byte[r];
                System.arraycopy(buf, 0, chunk, 0, r);
                Wire.writeBytes(out, chunk);
                sent += r;
            }
        } finally {
            fin.close();
        }
        return sent;
    }

    private static String baseName(String p) {
        int i = p.lastIndexOf('/');
        return i >= 0 ? p.substring(i + 1) : p;
    }

    private static void deleteQuietly(File f) {
        try {
            if (f != null && f.exists()) f.delete();
        } catch (Throwable ignored) {
        }
    }

    /** @return false when the connection should end. */
    private boolean serve(String line, BufferedOutputStream out) throws Exception {
        String[] parts = line.split(" ", 2);
        String op = parts[0];
        String arg = parts.length > 1 ? parts[1].trim() : "";

        // Log only the op name and duration; arguments hold paths that need not be echoed
        long t0 = System.currentTimeMillis();
        Log.i("net", "recv op=" + op + (arg.isEmpty() ? "" : " argLen=" + arg.length()));

        switch (op) {
            case "PING":
                Wire.writeText(out, "PONG");
                return true;

            case "STATUS": {
                StringBuilder sb = new StringBuilder();
                sb.append("{\"ok\":true");
                sb.append(",\"proc\":\"").append(esc(engine.host().processName())).append('"');
                sb.append(",\"pid\":").append(engine.host().pid());
                sb.append(",\"captured\":").append(engine.capture().capturedCount());
                sb.append(",\"verified\":").append(engine.capture().verifiedCount());
                sb.append(",\"dropped\":").append(engine.capture().droppedCount());
                sb.append(",\"vault\":").append(engine.vault().size());
                sb.append(",\"accounts\":").append(engine.vault().accountCount());
                sb.append('}');
                Wire.writeText(out, sb.toString());
                return true;
            }

            case "ACCOUNTS": {
                List<Account> accounts = engine.listAccounts(progressWriter(out));
                StringBuilder sb = new StringBuilder("[");
                for (int i = 0; i < accounts.size(); i++) {
                    Account a = accounts.get(i);
                    if (i > 0) sb.append(',');
                    sb.append("{\"id\":\"").append(a.dirName).append('"');
                    sb.append(",\"dir\":\"").append(esc(a.dir)).append('"');
                    sb.append(",\"uin\":").append(a.uin);
                    sb.append(",\"uinSource\":\"").append(esc(a.uinSource)).append('"');
                    sb.append(",\"wxid\":\"").append(esc(a.wxid)).append('"');
                    // Identity: nickname, alias, bound phone and whether a local avatar exists
                    sb.append(",\"nickname\":\"").append(esc(a.nickname)).append('"');
                    sb.append(",\"alias\":\"").append(esc(a.alias)).append('"');
                    sb.append(",\"mobile\":\"").append(esc(a.mobile)).append('"');
                    sb.append(",\"hasAvatar\":").append(a.avatarPath != null && !a.avatarPath.isEmpty());
                    sb.append(",\"dbCount\":").append(a.dbCount);
                    sb.append(",\"totalBytes\":").append(a.totalBytes);
                    sb.append(",\"decryptable\":").append(a.decryptable);
                    sb.append(",\"note\":\"").append(esc(a.note)).append('"');
                    sb.append('}');
                }
                sb.append(']');
                Wire.writeText(out, sb.toString());
                return true;
            }

            /** Sends an account avatar PNG; the app cannot read WeChat's private directory. */
            case "AVATAR": {
                List<Account> accounts = engine.listAccounts();
                String path = null;
                for (Account a : accounts) {
                    if (a.dirName.equals(arg) && a.avatarPath != null && !a.avatarPath.isEmpty()) {
                        path = a.avatarPath;
                        break;
                    }
                }
                if (path == null) {
                    Wire.writeText(out, "{\"ok\":false,\"reason\":\"no local avatar for this account\"}");
                    return true;
                }
                File f = new File(path);
                if (!f.exists() || !f.canRead()) {
                    Log.w("net", "AVATAR not readable: " + path);
                    Wire.writeText(out, "{\"ok\":false,\"reason\":\"avatar file not readable\"}");
                    return true;
                }
                Log.i("net", "AVATAR " + arg + " -> " + f.length() + " bytes");
                Wire.writeText(out, "{\"ok\":true,\"size\":" + f.length() + "}");
                long sent = streamFile(f, out);
                Wire.writeText(out, "END");
                Log.i("net", "AVATAR done, " + sent + " bytes");
                return true;
            }

            case "DBS": {
                List<Account> accounts = engine.listAccounts(progressWriter(out));
                for (Account a : accounts) {
                    if (!a.dirName.equals(arg)) continue;
                    // The account list is only lightly enriched, so enumeration must happen here instead of
                    // reading the cached field, which is always empty.
                    List<DbFile> dbs = DatabaseEnumerator.enumerate(
                            engine.host(), a, progressWriter(out));
                    StringBuilder sb = new StringBuilder("[");
                    for (int i = 0; i < dbs.size(); i++) {
                        DbFile d = dbs.get(i);
                        if (i > 0) sb.append(',');
                        sb.append("{\"name\":\"").append(esc(d.name)).append('"');
                        sb.append(",\"path\":\"").append(esc(d.path)).append('"');
                        sb.append(",\"size\":").append(d.sizeBytes);
                        sb.append(",\"encrypted\":").append(d.encrypted);
                        sb.append(",\"wal\":").append(d.hasWal);
                        sb.append(",\"shm\":").append(d.hasShm);
                        sb.append(",\"category\":\"").append(d.category.name()).append('"');
                        sb.append(",\"categoryKey\":\"")
                                .append(d.categoryKey == null ? "OTHER" : d.categoryKey).append('"');
                        // Purpose text, so the user knows what each database holds
                        sb.append(",\"desc\":\"")
                                .append(esc(d.description == null ? "" : d.description)).append('"');
                        sb.append(",\"hasKey\":").append(engine.vault().has(d.path));
                        sb.append('}');
                    }
                    sb.append(']');
                    Wire.writeText(out, sb.toString());
                    return true;
                }
                Wire.writeText(out, "[]");
                return true;
            }

            case "KEY": {
                // Account-level reuse: exact match first, then any key already verified for the account.
                // Every database of an account shares one key, so opening any single one is enough to
                // decrypt all of them.
                KeyVault.DbKey k = engine.vault().getForPath(arg);
                if (k == null) {
                    // A miss is worth noting: no key was captured for this account yet
                    Log.w("net", "KEY miss, no verified key for this account, path=" + arg
                            + " · " + engine.vault().describe()
                            + " · captured=" + engine.capture().capturedCount()
                            + " · verified=" + engine.capture().verifiedCount());
                    Wire.writeText(out, "{\"ok\":false,\"reason\":\"key not captured or not verified\"}");
                } else {
                    boolean reuse = !engine.vault().hasExact(arg);
                    Log.i("net", "KEY hit " + (reuse ? "(account reuse)" : "(exact)")
                            + " path=" + arg + " pageSize=" + k.pageSize
                            + " source=" + k.source + " verified=" + k.verified);
                    Wire.writeText(out, "{\"ok\":true,\"pageSize\":" + k.pageSize
                            + ",\"verified\":" + k.verified
                            + ",\"source\":\"" + esc(k.source) + (reuse ? "/account-reuse" : "") + "\""
                            + ",\"hex\":\"" + k.keyHex() + "\"}");
                }
                return true;
            }

            case "MD5": {
                // Lets the app verify the md5("mm"+uin) identity
                Wire.writeText(out, Digest.md5Hex(arg));
                return true;
            }

            case "FETCH": {
                File f = new File(arg);
                if (!f.exists() || !f.canRead()) {
                    Log.w("net", "FETCH failed, not readable, path=" + arg
                            + " exists=" + f.exists() + " canRead=" + f.canRead());
                    Wire.writeText(out, "{\"ok\":false,\"reason\":\"not readable\"}");
                    return true;
                }
                Log.i("net", "FETCH start path=" + arg + " size=" + f.length());
                Wire.writeText(out, "{\"ok\":true,\"size\":" + f.length() + "}");
                long sent = streamFile(f, out);
                Wire.writeText(out, "END");
                Log.i("net", "FETCH done path=" + arg + " " + sent + " bytes");
                return true;
            }

            /**
             * VERIFY checks whether a database decrypts, without transferring data.
             * It confirms in one round trip that every encrypted database of an account is readable.
             */
            case "VERIFY": {
                String cache = engine.host().cacheDir();
                if (cache == null) {
                    Wire.writeText(out, "{\"ok\":false,\"reason\":\"cache directory unavailable\"}");
                    return true;
                }
                File vdir = new File(cache, "wxdump-plain");
                if (!vdir.exists() && !vdir.mkdirs()) {
                    Wire.writeText(out, "{\"ok\":false,\"reason\":\"cannot create the staging directory\"}");
                    return true;
                }
                File vtmp = new File(vdir, "verify.db");
                try {
                    PlainDumper.Result r = engine.dumpPlain(arg, vtmp.getAbsolutePath());
                    if (r.ok) {
                        Wire.writeText(out, "{\"ok\":true,\"size\":" + r.size + ",\"plaintext\":true}");
                    } else {
                        Wire.writeText(out, "{\"ok\":false,\"reason\":\"" + esc(String.valueOf(r.reason)) + "\"}");
                    }
                    return true;
                } finally {
                    deleteQuietly(vtmp);
                    deleteQuietly(new File(vtmp.getAbsolutePath() + "-journal"));
                    deleteQuietly(new File(vtmp.getAbsolutePath() + "-wal"));
                    deleteQuietly(new File(vtmp.getAbsolutePath() + "-shm"));
                }
            }

            /**
             * DUMP decrypts a database with WeChat's own SQLCipher and streams the plaintext back.
             *
             * <p>The response matches FETCH exactly, so the app reuses one streaming reader; only the
             * payload differs, with plaintext=true in the head.
             */
            case "DUMP": {
                String cache = engine.host().cacheDir();
                if (cache == null) {
                    Wire.writeText(out, "{\"ok\":false,\"reason\":\"cache directory unavailable\"}");
                    return true;
                }
                File dir = new File(cache, "wxdump-plain");
                if (!dir.exists() && !dir.mkdirs()) {
                    Wire.writeText(out, "{\"ok\":false,\"reason\":\"cannot create the staging directory\"}");
                    return true;
                }
                File tmp = new File(dir, Math.abs(arg.hashCode()) + "-" + baseName(arg));
                long dumpStarted = System.currentTimeMillis();
                try {
                    PlainDumper.Result r = engine.dumpPlain(arg, tmp.getAbsolutePath());
                    if (!r.ok) {
                        Wire.writeText(out, "{\"ok\":false,\"reason\":\"" + esc(String.valueOf(r.reason)) + "\"}");
                        return true;
                    }
                    Log.i("net", "DUMP ok path=" + arg + " plainSize=" + r.size
                            + " decryptMs=" + (System.currentTimeMillis() - dumpStarted));
                    Wire.writeText(out, "{\"ok\":true,\"size\":" + r.size + ",\"plaintext\":true}");
                    long sent = streamFile(tmp, out);
                    Wire.writeText(out, "END");
                    Log.i("net", "DUMP stream finished, " + sent + " bytes");
                    return true;
                } finally {
                    // The plaintext temp file must be deleted; it holds chat data
                    try {
                        if (tmp.exists() && !tmp.delete()) {
                            Log.w("net", "failed to delete the plaintext temp file: " + tmp.getAbsolutePath());
                        }
                    } catch (Throwable ignored) {
                    }
                    // sqlcipher_export can leave journal or wal files behind
                    deleteQuietly(new File(tmp.getAbsolutePath() + "-journal"));
                    deleteQuietly(new File(tmp.getAbsolutePath() + "-wal"));
                    deleteQuietly(new File(tmp.getAbsolutePath() + "-shm"));
                }
            }

            case "BYE":
                return false;

            default:
                Wire.writeText(out, "{\"ok\":false,\"reason\":\"unknown op\"}");
                return true;
        }
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
