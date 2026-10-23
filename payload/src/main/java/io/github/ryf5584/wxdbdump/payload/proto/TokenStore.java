package io.github.ryf5584.wxdbdump.payload.proto;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory, single-use ephemeral token store for the loopback handshake.
 *
 * <p>Every loopback connection begins with the app generating a fresh {@code clientNonce}
 * and calling {@link #issue(String)} to register a 256-bit random token bound to that nonce.
 * When the module inside WeChat receives {@code HELLO}, it queries the app's Binder
 * ContentProvider with {@code clientNonce}; the provider verifies {@code Binder.getCallingUid()}
 * and calls {@link #consume(String)}, which atomically removes and returns the token.
 *
 * <p>Tokens never touch disk, cannot be replayed (consumed on first read), and expire after
 * {@link #DEFAULT_TTL_MS} milliseconds.
 */
public final class TokenStore {

    /** Default lifetime of an unconsumed handshake token (15 seconds). */
    public static final long DEFAULT_TTL_MS = 15_000L;

    /** Upper bound on concurrent pending nonces to prevent memory exhaustion. */
    private static final int MAX_PENDING = 64;

    private static final class Entry {
        final String token;
        final long expiresAtMs;

        Entry(String token, long expiresAtMs) {
            this.token = token;
            this.expiresAtMs = expiresAtMs;
        }
    }

    private final ConcurrentHashMap<String, Entry> pending = new ConcurrentHashMap<>();
    private final long ttlMs;

    public TokenStore() {
        this(DEFAULT_TTL_MS);
    }

    public TokenStore(long ttlMs) {
        if (ttlMs <= 0) throw new IllegalArgumentException("ttlMs must be positive");
        this.ttlMs = ttlMs;
    }

    /**
     * Issues a fresh 256-bit one-time token bound to {@code clientNonceHex}.
     *
     * @return the newly generated 64-character hex token
     */
    public String issue(String clientNonceHex) {
        return issue(clientNonceHex, System.currentTimeMillis());
    }

    String issue(String clientNonceHex, long nowMs) {
        if (clientNonceHex == null || clientNonceHex.isEmpty()) {
            throw new IllegalArgumentException("clientNonceHex must not be empty");
        }
        evictExpired(nowMs);
        if (pending.size() >= MAX_PENDING) {
            pending.clear();
        }
        String token = Handshake.newToken();
        pending.put(clientNonceHex, new Entry(token, nowMs + ttlMs));
        return token;
    }

    /**
     * Atomically consumes and removes the token bound to {@code clientNonceHex}.
     *
     * @return the token if present and not expired, or {@code null} otherwise
     */
    public String consume(String clientNonceHex) {
        return consume(clientNonceHex, System.currentTimeMillis());
    }

    String consume(String clientNonceHex, long nowMs) {
        if (clientNonceHex == null || clientNonceHex.isEmpty()) return null;
        Entry removed = pending.remove(clientNonceHex);
        if (removed == null) return null;
        if (nowMs > removed.expiresAtMs) return null;
        return removed.token;
    }

    /** Discards an unconsumed token (e.g. when a socket connect attempt fails before HELLO). */
    public void revoke(String clientNonceHex) {
        if (clientNonceHex != null) {
            pending.remove(clientNonceHex);
        }
    }

    /** Number of currently active (non-expired) tokens. */
    public int activeCount() {
        evictExpired(System.currentTimeMillis());
        return pending.size();
    }

    private void evictExpired(long nowMs) {
        Iterator<Map.Entry<String, Entry>> it = pending.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, Entry> e = it.next();
            if (nowMs > e.getValue().expiresAtMs) {
                it.remove();
            }
        }
    }
}
