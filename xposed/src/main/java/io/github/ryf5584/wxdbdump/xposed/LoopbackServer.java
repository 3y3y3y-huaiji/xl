package io.github.ryf5584.wxdbdump.xposed;

import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import io.github.ryf5584.wxdbdump.payload.Digest;
import io.github.ryf5584.wxdbdump.payload.Log;
import io.github.ryf5584.wxdbdump.payload.discovery.DatabaseEnumerator;
import io.github.ryf5584.wxdbdump.payload.engine.KeyVault;
import io.github.ryf5584.wxdbdump.payload.model.Account;
import io.github.ryf5584.wxdbdump.payload.model.DbFile;
import io.github.ryf5584.wxdbdump.payload.proto.Handshake;
import io.github.ryf5584.wxdbdump.payload.proto.Wire;

/**
 * Loopback server inside WeChat's process (Plan A: Root Sandbox Burn-After-Reading Token +
 * Per-Build Dynamic Port/Secret fallback, with 100% in-memory decryption and zero temp files).
 */
public final class LoopbackServer {

    private final WxDbEngine engine;
    private final int port;
    private final PeerAuth peerAuth;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private static final int HANDSHAKE_TIMEOUT_MS = 15_000;

    private ServerSocket server;

    public LoopbackServer(WxDbEngine engine, int port, PeerAuth peerAuth) {
        this.engine = engine;
        this.port = port;
        this.peerAuth = peerAuth;
    }

    public void start() {
        if (!running.compareAndSet(false, true)) return;
        Thread t = new Thread(this::acceptLoop, "ConnectivityThread");
        t.setDaemon(true);
        t.start();
    }

    public void stop() {
        running.set(false);
        try {
            if (server != null) server.close();
        } catch (Throwable ignored) {
        }
    }

    private void acceptLoop() {
        try {
            server = new ServerSocket(port, 8, InetAddress.getByName("127.0.0.1"));
        } catch (Throwable t) {
            running.set(false);
            return;
        }
        while (running.get()) {
            try {
                final Socket s = server.accept();
                Thread h = new Thread(() -> handle(s), "OkHttp TaskRunner");
                h.setDaemon(true);
                h.start();
            } catch (Throwable ignored) {
            }
        }
    }

    private void handle(Socket s) {
        try {
            s.setTcpNoDelay(true);
            s.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
            DataInputStream in = new DataInputStream(s.getInputStream());
            BufferedOutputStream out = new BufferedOutputStream(s.getOutputStream());

            // ---- Handshake ----
            Wire.Frame f = Wire.read(in);
            String hello = f.text();
            if (f.type != Wire.TYPE_TEXT || !Handshake.isHello(hello)) {
                Wire.writeText(out, Handshake.ackBad("BAD_HELLO"));
                return;
            }
            String nonce = Handshake.extractNonce(hello);
            if (nonce == null) {
                Wire.writeText(out, Handshake.ackBad("NO_NONCE"));
                return;
            }

            String sessionToken = peerAuth != null ? peerAuth.consumeTokenForNonce(nonce) : null;
            if (sessionToken == null || sessionToken.isEmpty()) {
                Wire.writeText(out, Handshake.ackBad("UNAUTHORIZED_PEER"));
                return;
            }

            String moduleNonce = Handshake.newNonce();
            Wire.writeText(out, Handshake.ack(nonce, moduleNonce, sessionToken));

            Wire.Frame authFrame = Wire.read(in);
            String authLine = authFrame.text();
            if (authFrame.type != Wire.TYPE_TEXT || !Handshake.isAuth(authLine)) {
                Wire.writeText(out, Handshake.ackBad("BAD_AUTH"));
                return;
            }
            if (!Handshake.matches(Handshake.proof(moduleNonce, sessionToken),
                    Handshake.extractProof(authLine))) {
                Wire.writeText(out, Handshake.ackBad("BAD_TOKEN"));
                return;
            }
            Wire.writeText(out, Handshake.ready());

            // ---- Command loop ----
            while (running.get() && !s.isClosed()) {
                Wire.Frame cmd = Wire.read(in);
                if (cmd.type != Wire.TYPE_TEXT) {
                    continue;
                }
                String line = cmd.text();
                if (line == null || line.isEmpty()) continue;
                if (!serve(line, out)) break;
            }
        } catch (Throwable ignored) {
        } finally {
            try {
                s.close();
            } catch (Throwable ignored) {
            }
        }
    }

    private static io.github.ryf5584.wxdbdump.payload.Progress progressWriter(BufferedOutputStream out) {
        return (done, total, stage) -> {
            try {
                Wire.writeText(out, "#P {\"done\":" + done + ",\"total\":" + total
                        + ",\"stage\":\"" + esc(stage) + "\"}");
            } catch (Throwable ignored) {
            }
        };
    }

    private static long streamFile(File f, BufferedOutputStream out) throws Exception {
        long sent = 0;
        try (FileInputStream fin = new FileInputStream(f)) {
            byte[] buf = new byte[64 * 1024];
            int r;
            while ((r = fin.read(buf)) > 0) {
                byte[] chunk = new byte[r];
                System.arraycopy(buf, 0, chunk, 0, r);
                Wire.writeBytes(out, chunk);
                sent += r;
            }
        }
        return sent;
    }

    /** OutputStream adapter that frames decrypted bytes into 64 KiB Wire binary chunks in memory. */
    private static final class FramedChunkOutputStream extends OutputStream {
        private final BufferedOutputStream wireOut;
        private final byte[] buf = new byte[64 * 1024];
        private int pos = 0;

        FramedChunkOutputStream(BufferedOutputStream wireOut) {
            this.wireOut = wireOut;
        }

        @Override
        public void write(int b) throws IOException {
            buf[pos++] = (byte) b;
            if (pos == buf.length) flushBuffer();
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            int remaining = len;
            int offset = off;
            while (remaining > 0) {
                int space = buf.length - pos;
                int copy = Math.min(space, remaining);
                System.arraycopy(b, offset, buf, pos, copy);
                pos += copy;
                offset += copy;
                remaining -= copy;
                if (pos == buf.length) flushBuffer();
            }
        }

        private void flushBuffer() throws IOException {
            if (pos <= 0) return;
            byte[] chunk = new byte[pos];
            System.arraycopy(buf, 0, chunk, 0, pos);
            Wire.writeBytes(wireOut, chunk);
            pos = 0;
        }

        @Override
        public void flush() throws IOException {
            flushBuffer();
            wireOut.flush();
        }
    }

    private boolean serve(String line, BufferedOutputStream out) throws Exception {
        String[] parts = line.split(" ", 2);
        String op = parts[0];
        String arg = parts.length > 1 ? parts[1].trim() : "";

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
                    Wire.writeText(out, "{\"ok\":false,\"reason\":\"avatar file not readable\"}");
                    return true;
                }
                Wire.writeText(out, "{\"ok\":true,\"size\":" + f.length() + "}");
                streamFile(f, out);
                Wire.writeText(out, "END");
                return true;
            }

            case "DBS": {
                List<Account> accounts = engine.listAccounts(progressWriter(out));
                for (Account a : accounts) {
                    if (!a.dirName.equals(arg)) continue;
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
                KeyVault.DbKey k = engine.vault().getForPath(arg);
                if (k == null) {
                    Wire.writeText(out, "{\"ok\":false,\"reason\":\"key not captured or not verified\"}");
                } else {
                    boolean reuse = !engine.vault().hasExact(arg);
                    Wire.writeText(out, "{\"ok\":true,\"pageSize\":" + k.pageSize
                            + ",\"verified\":" + k.verified
                            + ",\"source\":\"" + esc(k.source) + (reuse ? "/account-reuse" : "") + "\""
                            + ",\"hex\":\"" + k.keyHex() + "\"}");
                }
                return true;
            }

            case "MD5": {
                Wire.writeText(out, Digest.md5Hex(arg));
                return true;
            }

            case "FETCH": {
                File f = new File(arg);
                if (!f.exists() || !f.canRead()) {
                    Wire.writeText(out, "{\"ok\":false,\"reason\":\"not readable\"}");
                    return true;
                }
                Wire.writeText(out, "{\"ok\":true,\"size\":" + f.length() + "}");
                streamFile(f, out);
                Wire.writeText(out, "END");
                return true;
            }

            case "VERIFY": {
                PlainDumper.Result r = engine.verifyPlain(arg);
                if (r.ok) {
                    Wire.writeText(out, "{\"ok\":true,\"size\":" + r.size + ",\"plaintext\":true}");
                } else {
                    Wire.writeText(out, "{\"ok\":false,\"reason\":\"" + esc(String.valueOf(r.reason)) + "\"}");
                }
                return true;
            }

            case "DUMP": {
                PlainDumper.Result probe = engine.verifyPlain(arg);
                if (!probe.ok) {
                    Wire.writeText(out, "{\"ok\":false,\"reason\":\"" + esc(String.valueOf(probe.reason)) + "\"}");
                    return true;
                }
                Wire.writeText(out, "{\"ok\":true,\"size\":" + probe.size + ",\"plaintext\":true}");
                FramedChunkOutputStream framedOut = new FramedChunkOutputStream(out);
                PlainDumper.Result streamed = engine.streamPlain(arg, framedOut);
                framedOut.flush();
                if (!streamed.ok) {
                    Log.w("net", "DUMP stream interrupted: " + streamed.reason);
                    return false;
                }
                Wire.writeText(out, "END");
                return true;
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
