package com.aegis.security;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Security Audit Logger for tracking all authentication events, failed attempts, and account activities.
 */
public class AuditLogger {

    public enum EventType {
        REGISTER_SUCCESS,
        REGISTER_FAILED,
        LOGIN_SUCCESS,
        LOGIN_FAILED,
        ACCOUNT_LOCKED,
        LOGOUT,
        PASSWORD_CHANGED,
        PASSWORD_RESET_SUCCESS,
        PASSWORD_RESET_FAILED,
        UNAUTHORIZED_ACCESS
    }


    public static class AuditEntry {
        private final String timestamp;
        private final EventType type;
        private final String username;
        private final String ipAddress;
        private final String details;

        public AuditEntry(EventType type, String username, String ipAddress, String details) {
            this.timestamp = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
            this.type = type;
            this.username = username != null ? username : "anonymous";
            this.ipAddress = ipAddress != null ? ipAddress : "unknown";
            this.details = details != null ? details : "";
        }

        public AuditEntry(String timestamp, EventType type, String username, String ipAddress, String details) {
            this.timestamp = timestamp;
            this.type = type;
            this.username = username;
            this.ipAddress = ipAddress;
            this.details = details;
        }

        public String getTimestamp() { return timestamp; }
        public EventType getType() { return type; }
        public String getUsername() { return username; }
        public String getIpAddress() { return ipAddress; }
        public String getDetails() { return details; }

        public String toLogLine() {
            return String.format("[%s] [%s] User='%s' IP='%s' - %s", timestamp, type, username, ipAddress, details);
        }

        public String toJson() {
            return String.format("{\"timestamp\":\"%s\",\"type\":\"%s\",\"username\":\"%s\",\"ip\":\"%s\",\"details\":\"%s\"}",
                escapeJson(timestamp), escapeJson(type.name()), escapeJson(username), escapeJson(ipAddress), escapeJson(details));
        }

        private String escapeJson(String s) {
            if (s == null) return "";
            return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ").replace("\r", " ");
        }
    }

    private final List<AuditEntry> recentEvents = Collections.synchronizedList(new ArrayList<>());
    private final File logFile;
    private static final int MAX_IN_MEMORY_EVENTS = 200;

    public AuditLogger(String logFilePath) {
        this.logFile = new File(logFilePath);
        File parent = logFile.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
    }

    public synchronized void log(EventType type, String username, String ipAddress, String details) {
        AuditEntry entry = new AuditEntry(type, username, ipAddress, details);
        
        recentEvents.add(0, entry);
        if (recentEvents.size() > MAX_IN_MEMORY_EVENTS) {
            recentEvents.remove(recentEvents.size() - 1);
        }

        // Output to console
        System.out.println("🛡️ [AUDIT] " + entry.toLogLine());

        // Append to persistent log file
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(logFile, true))) {
            writer.write(entry.toLogLine());
            writer.newLine();
        } catch (IOException e) {
            System.err.println("Failed to write audit log: " + e.getMessage());
        }
    }

    public List<AuditEntry> getRecentEvents(int limit) {
        synchronized (recentEvents) {
            int count = Math.min(limit, recentEvents.size());
            return new ArrayList<>(recentEvents.subList(0, count));
        }
    }

    public List<AuditEntry> getUserEvents(String username, int limit) {
        List<AuditEntry> results = new ArrayList<>();
        synchronized (recentEvents) {
            for (AuditEntry entry : recentEvents) {
                if (entry.getUsername().equalsIgnoreCase(username)) {
                    results.add(entry);
                    if (results.size() >= limit) break;
                }
            }
        }
        return results;
    }
}
