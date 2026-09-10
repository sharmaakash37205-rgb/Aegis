package com.aegis.security;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.HexFormat;

/**
 * High-performance, thread-safe session manager generating 256-bit cryptographic tokens.
 */
public class SessionManager {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final long DEFAULT_SESSION_DURATION_SECONDS = 24 * 60 * 60; // 24 hours

    public static class Session {
        private final String token;
        private final String username;
        private final String ipAddress;
        private final String userAgent;
        private final Instant createdAt;
        private Instant expiresAt;
        private Instant lastActivityAt;

        public Session(String token, String username, String ipAddress, String userAgent, Instant createdAt, Instant expiresAt) {
            this.token = token;
            this.username = username;
            this.ipAddress = ipAddress;
            this.userAgent = userAgent;
            this.createdAt = createdAt;
            this.expiresAt = expiresAt;
            this.lastActivityAt = createdAt;
        }

        public String getToken() { return token; }
        public String getUsername() { return username; }
        public String getIpAddress() { return ipAddress; }
        public String getUserAgent() { return userAgent; }
        public Instant getCreatedAt() { return createdAt; }
        public Instant getExpiresAt() { return expiresAt; }
        public Instant getLastActivityAt() { return lastActivityAt; }

        public boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }

        public void touch(long extensionSeconds) {
            this.lastActivityAt = Instant.now();
            this.expiresAt = Instant.now().plusSeconds(extensionSeconds);
        }
    }

    private final Map<String, Session> activeSessions = new ConcurrentHashMap<>();
    private final long sessionDurationSeconds;

    public SessionManager() {
        this(DEFAULT_SESSION_DURATION_SECONDS);
    }

    public SessionManager(long sessionDurationSeconds) {
        this.sessionDurationSeconds = sessionDurationSeconds;
    }

    /**
     * Generates a 256-bit cryptographically secure session token and creates a session.
     */
    public Session createSession(String username, String ipAddress, String userAgent) {
        cleanupExpiredSessions();

        byte[] tokenBytes = new byte[32]; // 256-bit
        SECURE_RANDOM.nextBytes(tokenBytes);
        String token = HexFormat.of().formatHex(tokenBytes);

        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(sessionDurationSeconds);

        Session session = new Session(token, username, ipAddress, userAgent, now, expiresAt);
        activeSessions.put(token, session);
        return session;
    }

    /**
     * Validates a session token and refreshes its timestamp if valid.
     */
    public Optional<Session> validateSession(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }

        Session session = activeSessions.get(token);
        if (session == null) {
            return Optional.empty();
        }

        if (session.isExpired()) {
            activeSessions.remove(token);
            return Optional.empty();
        }

        session.touch(sessionDurationSeconds);
        return Optional.of(session);
    }

    /**
     * Revokes a session token (logout).
     */
    public boolean revokeSession(String token) {
        if (token == null) return false;
        return activeSessions.remove(token) != null;
    }

    /**
     * Revokes all active sessions for a given username.
     */
    public void revokeAllUserSessions(String username) {
        if (username == null) return;
        activeSessions.entrySet().removeIf(entry -> username.equalsIgnoreCase(entry.getValue().getUsername()));
    }

    /**
     * Returns total active valid sessions.
     */
    public int getActiveSessionCount() {
        cleanupExpiredSessions();
        return activeSessions.size();
    }

    /**
     * Cleans up expired sessions.
     */
    public void cleanupExpiredSessions() {
        activeSessions.entrySet().removeIf(entry -> entry.getValue().isExpired());
    }
}
