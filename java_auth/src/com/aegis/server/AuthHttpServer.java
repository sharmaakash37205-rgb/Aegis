package com.aegis.server;

import com.aegis.security.AuditLogger;
import com.aegis.security.SessionManager;
import com.aegis.storage.UserManager;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Executors;

/**
 * Embedded Java HTTP/REST Server providing secure authentication APIs and Web Portal.
 * Enables users to securely access and manage their account anytime, anywhere.
 */
public class AuthHttpServer {

    private final int port;
    private final String webRoot;
    private final UserManager userManager;
    private final SessionManager sessionManager;
    private final AuditLogger auditLogger;
    private HttpServer server;
    private final Instant startTime = Instant.now();

    public AuthHttpServer(int port, String webRoot, UserManager userManager, SessionManager sessionManager, AuditLogger auditLogger) {
        this.port = port;
        this.webRoot = webRoot;
        this.userManager = userManager;
        this.sessionManager = sessionManager;
        this.auditLogger = auditLogger;
    }

    public synchronized void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);

        // Register Handlers
        server.createContext("/api/auth/register", new RegisterHandler());
        server.createContext("/api/auth/login", new LoginHandler());
        server.createContext("/api/auth/verify", new VerifyHandler());
        server.createContext("/api/auth/logout", new LogoutHandler());
        server.createContext("/api/auth/change-password", new ChangePasswordHandler());
        server.createContext("/api/auth/forgot-password/get-question", new ForgotPasswordGetQuestionHandler());
        server.createContext("/api/auth/forgot-password/reset", new ForgotPasswordResetHandler());
        server.createContext("/api/auth/audit", new AuditHandler());
        server.createContext("/api/auth/status", new StatusHandler());

        // Static Web Portal Handler
        server.createContext("/", new StaticFileHandler(webRoot));

        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor()); // Java 21+ Virtual Threads
        server.start();

        System.out.println("🚀 Aegis Auth Server running at http://localhost:" + port + "/");
        System.out.println("🌐 Remote / LAN Access enabled on port " + port);
    }

    public synchronized void stop() {
        if (server != null) {
            server.stop(0);
            System.out.println("🛑 Aegis Auth Server stopped.");
        }
    }

    public int getPort() {
        return port;
    }

    // --- Handlers ---

    private class RegisterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String username = extractJsonField(body, "username");
            String displayName = extractJsonField(body, "displayName");
            String email = extractJsonField(body, "email");
            String password = extractJsonField(body, "password");
            String securityQuestion = extractJsonField(body, "securityQuestion");
            String securityAnswer = extractJsonField(body, "securityAnswer");
            String ip = getClientIp(exchange);

            if (username == null || password == null) {
                sendJsonResponse(exchange, 400, "{\"success\":false,\"error\":\"Username and password are required.\"}");
                return;
            }

            UserManager.AuthResult result = userManager.register(
                username,
                displayName,
                email,
                password.toCharArray(),
                securityQuestion,
                securityAnswer,
                ip
            );
            if (result.isSuccess()) {
                SessionManager.Session session = sessionManager.createSession(
                    result.getUser().getUsername(),
                    ip,
                    getUserAgent(exchange)
                );
                String userJson = buildUserJson(result.getUser());
                String json = String.format("{\"success\":true,\"message\":\"%s\",\"token\":\"%s\",\"user\":%s}",
                    escapeJson(result.getMessage()), session.getToken(), userJson);
                sendJsonResponse(exchange, 201, json);
            } else {
                String json = String.format("{\"success\":false,\"error\":\"%s\"}", escapeJson(result.getMessage()));
                sendJsonResponse(exchange, 400, json);
            }
        }
    }


    private class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String username = extractJsonField(body, "username");
            String password = extractJsonField(body, "password");
            String ip = getClientIp(exchange);

            if (username == null || password == null) {
                sendJsonResponse(exchange, 400, "{\"success\":false,\"error\":\"Username and password are required.\"}");
                return;
            }

            UserManager.AuthResult result = userManager.authenticate(username, password.toCharArray(), ip);
            if (result.isSuccess()) {
                SessionManager.Session session = sessionManager.createSession(
                    result.getUser().getUsername(),
                    ip,
                    getUserAgent(exchange)
                );
                String userJson = buildUserJson(result.getUser());
                String json = String.format("{\"success\":true,\"message\":\"%s\",\"token\":\"%s\",\"user\":%s}",
                    escapeJson(result.getMessage()), session.getToken(), userJson);
                sendJsonResponse(exchange, 200, json);
            } else {
                int statusCode = result.isLocked() ? 423 : 401; // 423 Locked
                String json = String.format("{\"success\":false,\"error\":\"%s\",\"locked\":%b,\"remainingLockSeconds\":%d}",
                    escapeJson(result.getMessage()), result.isLocked(), result.getRemainingLockSeconds());
                sendJsonResponse(exchange, statusCode, json);
            }
        }
    }

    private class VerifyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            String token = extractBearerToken(exchange);
            Optional<SessionManager.Session> sessionOpt = sessionManager.validateSession(token);

            if (sessionOpt.isPresent()) {
                SessionManager.Session session = sessionOpt.get();
                UserManager.User user = userManager.getUser(session.getUsername());
                String userJson = user != null ? buildUserJson(user) : "{}";
                String json = String.format("{\"valid\":true,\"username\":\"%s\",\"expiresAt\":\"%s\",\"user\":%s}",
                    escapeJson(session.getUsername()), session.getExpiresAt().toString(), userJson);
                sendJsonResponse(exchange, 200, json);
            } else {
                sendJsonResponse(exchange, 401, "{\"valid\":false,\"error\":\"Invalid or expired session token.\"}");
            }
        }
    }

    private class LogoutHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            String token = extractBearerToken(exchange);
            Optional<SessionManager.Session> sessionOpt = sessionManager.validateSession(token);
            if (sessionOpt.isPresent()) {
                String username = sessionOpt.get().getUsername();
                sessionManager.revokeSession(token);
                auditLogger.log(AuditLogger.EventType.LOGOUT, username, getClientIp(exchange), "User logged out");
            }
            sendJsonResponse(exchange, 200, "{\"success\":true,\"message\":\"Logged out successfully.\"}");
        }
    }

    private class ChangePasswordHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            String token = extractBearerToken(exchange);
            Optional<SessionManager.Session> sessionOpt = sessionManager.validateSession(token);
            if (sessionOpt.isEmpty()) {
                sendJsonResponse(exchange, 401, "{\"success\":false,\"error\":\"Unauthorized\"}");
                return;
            }

            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String currentPassword = extractJsonField(body, "currentPassword");
            String newPassword = extractJsonField(body, "newPassword");

            if (currentPassword == null || newPassword == null) {
                sendJsonResponse(exchange, 400, "{\"success\":false,\"error\":\"Current and new password required.\"}");
                return;
            }

            String username = sessionOpt.get().getUsername();
            UserManager.AuthResult result = userManager.changePassword(
                username,
                currentPassword.toCharArray(),
                newPassword.toCharArray(),
                getClientIp(exchange)
            );

            if (result.isSuccess()) {
                sendJsonResponse(exchange, 200, "{\"success\":true,\"message\":\"Password updated successfully.\"}");
            } else {
                sendJsonResponse(exchange, 400, "{\"success\":false,\"error\":\"" + escapeJson(result.getMessage()) + "\"}");
            }
        }
    }

    private class ForgotPasswordGetQuestionHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String username = extractJsonField(body, "username");
            if (username == null || username.isBlank()) {
                username = extractJsonField(body, "usernameOrEmail");
            }

            if (username == null || username.isBlank()) {
                sendJsonResponse(exchange, 400, "{\"success\":false,\"error\":\"Username or email is required.\"}");
                return;
            }

            String question = userManager.getSecurityQuestion(username);
            if (question != null) {
                String json = String.format("{\"success\":true,\"username\":\"%s\",\"question\":\"%s\"}",
                    escapeJson(username), escapeJson(question));
                sendJsonResponse(exchange, 200, json);
            } else {
                sendJsonResponse(exchange, 404, "{\"success\":false,\"error\":\"Account not found with this username or email.\"}");
            }
        }
    }

    private class ForgotPasswordResetHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJsonResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String username = extractJsonField(body, "username");
            if (username == null || username.isBlank()) {
                username = extractJsonField(body, "usernameOrEmail");
            }
            String answer = extractJsonField(body, "answer");
            String newPassword = extractJsonField(body, "newPassword");
            String ip = getClientIp(exchange);

            if (username == null || newPassword == null) {
                sendJsonResponse(exchange, 400, "{\"success\":false,\"error\":\"Username and new password are required.\"}");
                return;
            }

            UserManager.AuthResult result = userManager.resetPasswordWithSecurityAnswer(
                username,
                answer,
                newPassword.toCharArray(),
                ip
            );

            if (result.isSuccess()) {
                sendJsonResponse(exchange, 200, "{\"success\":true,\"message\":\"" + escapeJson(result.getMessage()) + "\"}");
            } else {
                sendJsonResponse(exchange, 400, "{\"success\":false,\"error\":\"" + escapeJson(result.getMessage()) + "\"}");
            }
        }
    }


    private class AuditHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            if ("OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendResponse(exchange, 204, "");
                return;
            }

            String token = extractBearerToken(exchange);
            Optional<SessionManager.Session> sessionOpt = sessionManager.validateSession(token);
            if (sessionOpt.isEmpty()) {
                sendJsonResponse(exchange, 401, "{\"success\":false,\"error\":\"Unauthorized\"}");
                return;
            }

            String username = sessionOpt.get().getUsername();
            List<AuditLogger.AuditEntry> events = userManager.getUserCount() == 1
                ? auditLogger.getRecentEvents(50)
                : auditLogger.getUserEvents(username, 50);

            StringBuilder sb = new StringBuilder();
            sb.append("{\"success\":true,\"events\":[");
            for (int i = 0; i < events.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append(events.get(i).toJson());
            }
            sb.append("]}");
            sendJsonResponse(exchange, 200, sb.toString());
        }
    }

    private class StatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            addCorsHeaders(exchange);
            long uptimeSeconds = Instant.now().getEpochSecond() - startTime.getEpochSecond();
            String json = String.format(
                "{\"service\":\"Aegis Auth Server\",\"status\":\"UP\",\"registeredUsers\":%d,\"activeSessions\":%d,\"uptimeSeconds\":%d}",
                userManager.getUserCount(), sessionManager.getActiveSessionCount(), uptimeSeconds
            );
            sendJsonResponse(exchange, 200, json);
        }
    }

    private class StaticFileHandler implements HttpHandler {
        private final File baseDir;

        public StaticFileHandler(String rootPath) {
            this.baseDir = new File(rootPath);
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();
            if (path == null || path.equals("/") || path.isBlank()) {
                path = "/index.html";
            }

            // Security: Prevent path traversal
            File requestedFile = new File(baseDir, path).getCanonicalFile();
            if (!requestedFile.getPath().startsWith(baseDir.getCanonicalPath()) || !requestedFile.exists() || requestedFile.isDirectory()) {
                // Fallback to index.html for SPA routing
                requestedFile = new File(baseDir, "index.html");
                if (!requestedFile.exists()) {
                    sendResponse(exchange, 404, "404 Not Found");
                    return;
                }
            }

            String mimeType = getMimeType(requestedFile.getName());
            byte[] fileBytes = Files.readAllBytes(requestedFile.toPath());

            Headers headers = exchange.getResponseHeaders();
            headers.set("Content-Type", mimeType);
            headers.set("Cache-Control", "no-cache, no-store, must-revalidate");
            headers.set("X-Content-Type-Options", "nosniff");
            headers.set("X-Frame-Options", "DENY");

            exchange.sendResponseHeaders(200, fileBytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(fileBytes);
            }
        }

        private String getMimeType(String filename) {
            String lower = filename.toLowerCase();
            if (lower.endsWith(".html")) return "text/html; charset=UTF-8";
            if (lower.endsWith(".css")) return "text/css; charset=UTF-8";
            if (lower.endsWith(".js")) return "application/javascript; charset=UTF-8";
            if (lower.endsWith(".json")) return "application/json; charset=UTF-8";
            if (lower.endsWith(".png")) return "image/png";
            if (lower.endsWith(".ico")) return "image/x-icon";
            if (lower.endsWith(".svg")) return "image/svg+xml";
            return "text/plain";
        }
    }

    // --- Helpers ---

    private void addCorsHeaders(HttpExchange exchange) {
        Headers headers = exchange.getResponseHeaders();
        headers.set("Access-Control-Allow-Origin", "*");
        headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
    }

    private void sendJsonResponse(HttpExchange exchange, int statusCode, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private String extractBearerToken(HttpExchange exchange) {
        String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7).trim();
        }
        return null;
    }

    private String getClientIp(HttpExchange exchange) {
        String forwarded = exchange.getRequestHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return exchange.getRemoteAddress().getAddress().getHostAddress();
    }

    private String getUserAgent(HttpExchange exchange) {
        String agent = exchange.getRequestHeaders().getFirst("User-Agent");
        return agent != null ? agent : "Unknown Device";
    }

    private String buildUserJson(UserManager.User u) {
        return String.format(
            "{\"username\":\"%s\",\"displayName\":\"%s\",\"email\":\"%s\",\"createdAt\":\"%s\",\"lastLoginAt\":%s,\"vaultSalt\":\"%s\"}",
            escapeJson(u.getUsername()),
            escapeJson(u.getDisplayName()),
            escapeJson(u.getEmail()),
            escapeJson(u.getCreatedAt()),
            u.getLastLoginAt() != null ? "\"" + escapeJson(u.getLastLoginAt()) + "\"" : "null",
            escapeJson(u.getVaultSalt())
        );
    }

    private String extractJsonField(String json, String field) {
        String search = "\"" + field + "\"";
        int idx = json.indexOf(search);
        if (idx == -1) return null;
        int colon = json.indexOf(':', idx + search.length());
        if (colon == -1) return null;
        int quoteStart = json.indexOf('"', colon + 1);
        if (quoteStart == -1) return null;
        int quoteEnd = json.indexOf('"', quoteStart + 1);
        while (quoteEnd != -1 && json.charAt(quoteEnd - 1) == '\\') {
            quoteEnd = json.indexOf('"', quoteEnd + 1);
        }
        if (quoteEnd == -1) return null;
        return unescapeJson(json.substring(quoteStart + 1, quoteEnd));
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private String unescapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\\"", "\"").replace("\\\\", "\\").replace("\\n", "\n").replace("\\r", "\r");
    }
}
