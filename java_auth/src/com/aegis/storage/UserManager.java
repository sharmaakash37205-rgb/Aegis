package com.aegis.storage;

import com.aegis.security.AuditLogger;
import com.aegis.security.PasswordHasher;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages user accounts, persistence to JSON, rate-limiting, and account
 * lockout policies.
 */
public class UserManager {

    public static final int MAX_FAILED_ATTEMPTS = 5;
    public static final long LOCKOUT_DURATION_SECONDS = 5 * 60; // 5 minutes

    public static class User {
        private String username;
        private String displayName;
        private String email;
        private String passwordHash;
        private String salt;
        private int iterations;
        private String createdAt;
        private String lastLoginAt;
        private int failedAttempts;
        private String lockedUntil; // ISO Instant or null
        private String vaultSalt; // Unique salt for user vault encryption
        private String securityQuestion;
        private String securityAnswerHash;
        private String securityAnswerSalt;

        public User() {
        }

        public User(String username, String displayName, String email, String passwordHash, String salt, int iterations,
                String vaultSalt) {
            this(username, displayName, email, passwordHash, salt, iterations, vaultSalt,
                    "What was the name of your first security key or pet?", null, null);
        }

        public User(String username, String displayName, String email, String passwordHash, String salt, int iterations,
                String vaultSalt, String securityQuestion, String securityAnswerHash, String securityAnswerSalt) {
            this.username = username;
            this.displayName = displayName;
            this.email = email;
            this.passwordHash = passwordHash;
            this.salt = salt;
            this.iterations = iterations;
            this.vaultSalt = vaultSalt;
            this.securityQuestion = securityQuestion != null && !securityQuestion.isBlank() ? securityQuestion
                    : "What was the name of your first security key or pet?";
            this.securityAnswerHash = securityAnswerHash;
            this.securityAnswerSalt = securityAnswerSalt;
            this.createdAt = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
            this.lastLoginAt = null;
            this.failedAttempts = 0;
            this.lockedUntil = null;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getDisplayName() {
            return displayName != null ? displayName : username;
        }

        public void setDisplayName(String displayName) {
            this.displayName = displayName;
        }

        public String getEmail() {
            return email != null ? email : "";
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getPasswordHash() {
            return passwordHash;
        }

        public void setPasswordHash(String passwordHash) {
            this.passwordHash = passwordHash;
        }

        public String getSalt() {
            return salt;
        }

        public void setSalt(String salt) {
            this.salt = salt;
        }

        public int getIterations() {
            return iterations;
        }

        public void setIterations(int iterations) {
            this.iterations = iterations;
        }

        public String getCreatedAt() {
            return createdAt;
        }

        public void setCreatedAt(String createdAt) {
            this.createdAt = createdAt;
        }

        public String getLastLoginAt() {
            return lastLoginAt;
        }

        public void setLastLoginAt(String lastLoginAt) {
            this.lastLoginAt = lastLoginAt;
        }

        public int getFailedAttempts() {
            return failedAttempts;
        }

        public void setFailedAttempts(int failedAttempts) {
            this.failedAttempts = failedAttempts;
        }

        public String getLockedUntil() {
            return lockedUntil;
        }

        public void setLockedUntil(String lockedUntil) {
            this.lockedUntil = lockedUntil;
        }

        public String getVaultSalt() {
            return vaultSalt;
        }

        public void setVaultSalt(String vaultSalt) {
            this.vaultSalt = vaultSalt;
        }

        public String getSecurityQuestion() {
            return securityQuestion != null ? securityQuestion : "What was the name of your first security key or pet?";
        }

        public void setSecurityQuestion(String securityQuestion) {
            this.securityQuestion = securityQuestion;
        }

        public String getSecurityAnswerHash() {
            return securityAnswerHash;
        }

        public void setSecurityAnswerHash(String securityAnswerHash) {
            this.securityAnswerHash = securityAnswerHash;
        }

        public String getSecurityAnswerSalt() {
            return securityAnswerSalt;
        }

        public void setSecurityAnswerSalt(String securityAnswerSalt) {
            this.securityAnswerSalt = securityAnswerSalt;
        }

        public boolean isLocked() {
            if (lockedUntil == null)
                return false;
            try {
                Instant lockExpiry = Instant.parse(lockedUntil);
                return Instant.now().isBefore(lockExpiry);
            } catch (Exception e) {
                return false;
            }
        }

        public long getRemainingLockoutSeconds() {
            if (lockedUntil == null)
                return 0;
            try {
                Instant lockExpiry = Instant.parse(lockedUntil);
                long diff = lockExpiry.getEpochSecond() - Instant.now().getEpochSecond();
                return Math.max(0, diff);
            } catch (Exception e) {
                return 0;
            }
        }
    }

    public static class AuthResult {
        private final boolean success;
        private final String message;
        private final User user;
        private final boolean locked;
        private final long remainingLockSeconds;

        public AuthResult(boolean success, String message, User user) {
            this(success, message, user, false, 0);
        }

        public AuthResult(boolean success, String message, User user, boolean locked, long remainingLockSeconds) {
            this.success = success;
            this.message = message;
            this.user = user;
            this.locked = locked;
            this.remainingLockSeconds = remainingLockSeconds;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getMessage() {
            return message;
        }

        public User getUser() {
            return user;
        }

        public boolean isLocked() {
            return locked;
        }

        public long getRemainingLockSeconds() {
            return remainingLockSeconds;
        }
    }

    private final Map<String, User> users = new ConcurrentHashMap<>();
    private final Map<String, Integer> recoveryFailures = new ConcurrentHashMap<>();
    private final Map<String, Instant> recoveryLockouts = new ConcurrentHashMap<>();
    private final File dataFile;
    private final AuditLogger auditLogger;

    public UserManager(String dataFilePath, AuditLogger auditLogger) {
        this.dataFile = new File(dataFilePath);
        this.auditLogger = auditLogger;
        loadUsers();
    }

    /**
     * Registers a new user account with optional security recovery challenge.
     */
    public synchronized AuthResult register(String username, String displayName, String email, char[] password,
            String ipAddress) {
        return register(username, displayName, email, password, "What was the name of your first security key or pet?",
                null, ipAddress);
    }

    public synchronized AuthResult register(String username, String displayName, String email, char[] password,
            String securityQuestion, String securityAnswer, String ipAddress) {
        if (displayName == null || displayName.isBlank()) {
            return new AuthResult(false, "Full name is required.", null);
        }
        if (email == null || email.isBlank()) {
            return new AuthResult(false, "Email address is required.", null);
        }
        if (username == null || username.trim().length() < 3) {
            return new AuthResult(false, "Username must be at least 3 characters.", null);
        }
        String cleanUsername = username.trim();
        if (!cleanUsername.matches("^[a-zA-Z0-9_.-]+$")) {
            return new AuthResult(false,
                    "Username contains invalid characters (letters, digits, dots, underscores, dashes only).", null);
        }

        if (users.containsKey(cleanUsername)) {
            auditLogger.log(AuditLogger.EventType.REGISTER_FAILED, cleanUsername, ipAddress, "Username already taken");
            return new AuthResult(false, "Username is already registered.", null);
        }

        String strengthErr = PasswordHasher.checkPasswordStrength(new String(password));
        if (strengthErr != null) {
            return new AuthResult(false, strengthErr, null);
        }

        PasswordHasher.HashResult hashRes = PasswordHasher.hashPassword(password);
        byte[] vaultSaltBytes = new byte[16];
        new SecureRandom().nextBytes(vaultSaltBytes);
        String vaultSalt = Base64.getEncoder().encodeToString(vaultSaltBytes);

        String answerHash = null;
        String answerSalt = null;
        if (securityAnswer != null && !securityAnswer.trim().isEmpty()) {
            PasswordHasher.HashResult ansHashRes = PasswordHasher
                    .hashPassword(securityAnswer.trim().toLowerCase().toCharArray());
            answerHash = ansHashRes.getHashBase64();
            answerSalt = ansHashRes.getSaltBase64();
        }

        User newUser = new User(
                cleanUsername,
                displayName.trim(),
                email.trim(),
                hashRes.getHashBase64(),
                hashRes.getSaltBase64(),
                hashRes.getIterations(),
                vaultSalt,
                securityQuestion != null && !securityQuestion.isBlank() ? securityQuestion.trim()
                        : "What was the name of your first security key or pet?",
                answerHash,
                answerSalt);

        users.put(cleanUsername, newUser);
        saveUsers();

        auditLogger.log(AuditLogger.EventType.REGISTER_SUCCESS, cleanUsername, ipAddress,
                "Account successfully created");
        return new AuthResult(true, "Registration successful!", newUser);
    }

    /**
     * Authenticates a user with password and enforces lockout rules on repeated
     * failures.
     */
    public synchronized AuthResult authenticate(String username, char[] password, String ipAddress) {
        if (username == null || username.isBlank()) {
            return new AuthResult(false, "Username is required.", null);
        }

        String cleanUsername = username.trim();
        User user = findUserByUsernameOrEmail(cleanUsername);

        if (user == null) {
            // Constant-time dummy hash to resist username enumeration via timing attacks
            PasswordHasher.hashWithSalt(password, "AAAAAAAAAAAAAAAAAAAAAA==", PasswordHasher.ITERATIONS);
            auditLogger.log(AuditLogger.EventType.LOGIN_FAILED, cleanUsername, ipAddress, "User does not exist");
            return new AuthResult(false, "Invalid username or password.", null);
        }

        String userKey = user.getUsername();

        // Check Account Lockout
        if (user.isLocked()) {
            long remaining = user.getRemainingLockoutSeconds();
            auditLogger.log(AuditLogger.EventType.UNAUTHORIZED_ACCESS, userKey, ipAddress,
                    "Attempt to login while locked (" + remaining + "s left)");
            return new AuthResult(false,
                    "Account is temporarily locked due to failed attempts. Try again in " + remaining + " seconds.",
                    user, true, remaining);
        }

        // Verify password
        boolean valid = PasswordHasher.verifyPassword(password, user.getPasswordHash(), user.getSalt(),
                user.getIterations());

        if (valid) {
            // Reset failed counter & clear lockout
            user.setFailedAttempts(0);
            user.setLockedUntil(null);
            user.setLastLoginAt(DateTimeFormatter.ISO_INSTANT.format(Instant.now()));
            saveUsers();

            auditLogger.log(AuditLogger.EventType.LOGIN_SUCCESS, userKey, ipAddress,
                    "Login authenticated successfully");
            return new AuthResult(true, "Authentication successful!", user);
        } else {
            // Increment failed attempts
            int failed = user.getFailedAttempts() + 1;
            user.setFailedAttempts(failed);

            if (failed >= MAX_FAILED_ATTEMPTS) {
                Instant lockExpiry = Instant.now().plusSeconds(LOCKOUT_DURATION_SECONDS);
                user.setLockedUntil(DateTimeFormatter.ISO_INSTANT.format(lockExpiry));
                saveUsers();

                auditLogger.log(AuditLogger.EventType.ACCOUNT_LOCKED, userKey, ipAddress, "Account locked for "
                        + (LOCKOUT_DURATION_SECONDS / 60) + " minutes after " + failed + " failures");
                return new AuthResult(false, "Too many failed attempts. Account locked for 5 minutes.", user, true,
                        LOCKOUT_DURATION_SECONDS);
            } else {
                saveUsers();
                int attemptsLeft = MAX_FAILED_ATTEMPTS - failed;
                auditLogger.log(AuditLogger.EventType.LOGIN_FAILED, userKey, ipAddress,
                        "Incorrect password (" + attemptsLeft + " attempts left)");
                return new AuthResult(false, "Invalid username or password. (" + attemptsLeft + " attempts remaining)",
                        user);
            }
        }
    }

    /**
     * Retrieves the configured security question for a given username or email.
     */
    public synchronized String getSecurityQuestion(String usernameOrEmail) {
        if (usernameOrEmail == null || usernameOrEmail.isBlank())
            return null;
        User user = findUserByUsernameOrEmail(usernameOrEmail.trim());
        if (user == null)
            return null;
        return user.getSecurityQuestion();
    }

    /**
     * Resets master password using zero-knowledge security answer verification.
     */
    public synchronized AuthResult resetPasswordWithSecurityAnswer(String usernameOrEmail, String securityAnswer,
            char[] newPassword, String ipAddress) {
        if (usernameOrEmail == null || usernameOrEmail.isBlank()) {
            return new AuthResult(false, "Username or email is required.", null);
        }

        String query = usernameOrEmail.trim();
        User user = findUserByUsernameOrEmail(query);

        if (user == null) {
            auditLogger.log(AuditLogger.EventType.PASSWORD_RESET_FAILED, query, ipAddress,
                    "User not found for password recovery");
            return new AuthResult(false, "Account not found.", null);
        }

        String userKey = user.getUsername();

        // Check Password Recovery Lockout (protects security answer against brute-force enumeration)
        Instant recLock = recoveryLockouts.get(userKey);
        if (recLock != null && Instant.now().isBefore(recLock)) {
            long remaining = java.time.Duration.between(Instant.now(), recLock).toSeconds();
            auditLogger.log(AuditLogger.EventType.UNAUTHORIZED_ACCESS, userKey, ipAddress,
                    "Attempt to recover password while recovery locked (" + remaining + "s left)");
            return new AuthResult(false,
                    "Too many failed security answer attempts. Password recovery is temporarily locked for " + remaining + " seconds.",
                    user, true, remaining);
        }

        // If user has no security answer set, deny password reset (prevent account takeover)
        if (user.getSecurityAnswerHash() == null || user.getSecurityAnswerSalt() == null) {
            auditLogger.log(AuditLogger.EventType.PASSWORD_RESET_FAILED, userKey, ipAddress,
                    "No security answer configured — password reset denied");
            return new AuthResult(false,
                    "Password reset is unavailable. No security answer was configured for this account. Please contact the administrator.",
                    user);
        }

        if (securityAnswer == null || securityAnswer.trim().isEmpty()) {
            auditLogger.log(AuditLogger.EventType.PASSWORD_RESET_FAILED, userKey, ipAddress,
                    "Empty security answer provided");
            return new AuthResult(false, "Security answer is required.", user);
        }

        // Verify security answer (case-insensitive)
        String cleanAnswer = securityAnswer.trim().toLowerCase();
        boolean validAnswer = PasswordHasher.verifyPassword(cleanAnswer.toCharArray(), user.getSecurityAnswerHash(),
                user.getSecurityAnswerSalt(), PasswordHasher.ITERATIONS);

        if (!validAnswer) {
            int fails = recoveryFailures.getOrDefault(userKey, 0) + 1;
            recoveryFailures.put(userKey, fails);

            if (fails >= MAX_FAILED_ATTEMPTS) {
                recoveryLockouts.put(userKey, Instant.now().plusSeconds(LOCKOUT_DURATION_SECONDS));
                recoveryFailures.remove(userKey);

                auditLogger.log(AuditLogger.EventType.ACCOUNT_LOCKED, userKey, ipAddress,
                        "Password recovery locked for " + (LOCKOUT_DURATION_SECONDS / 60)
                                + " minutes after " + fails + " failed security answers");
                return new AuthResult(false,
                        "Too many failed recovery attempts. Password recovery locked for 5 minutes.", user, true,
                        LOCKOUT_DURATION_SECONDS);
            } else {
                int attemptsLeft = MAX_FAILED_ATTEMPTS - fails;
                auditLogger.log(AuditLogger.EventType.PASSWORD_RESET_FAILED, userKey, ipAddress,
                        "Incorrect security challenge answer (" + attemptsLeft + " attempts left)");
                return new AuthResult(false,
                        "Security challenge answer is incorrect. (" + attemptsLeft + " attempts remaining)", user);
            }
        }

        String strengthErr = PasswordHasher.checkPasswordStrength(new String(newPassword));
        if (strengthErr != null) {
            return new AuthResult(false, strengthErr, user);
        }

        recoveryFailures.remove(userKey);
        recoveryLockouts.remove(userKey);
        PasswordHasher.HashResult newHash = PasswordHasher.hashPassword(newPassword);
        user.setPasswordHash(newHash.getHashBase64());
        user.setSalt(newHash.getSaltBase64());
        user.setIterations(newHash.getIterations());
        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        saveUsers();

        auditLogger.log(AuditLogger.EventType.PASSWORD_RESET_SUCCESS, userKey, ipAddress,
                "Password reset successfully via security challenge");
        return new AuthResult(true, "Password has been reset successfully! You can now log in.", user);
    }

    public synchronized AuthResult changePassword(String username, char[] currentPassword, char[] newPassword,
            String ipAddress) {
        String cleanUsername = username.trim();
        User user = findUserByUsernameOrEmail(cleanUsername);
        if (user == null) {
            return new AuthResult(false, "User not found.", null);
        }

        boolean valid = PasswordHasher.verifyPassword(currentPassword, user.getPasswordHash(), user.getSalt(),
                user.getIterations());
        if (!valid) {
            return new AuthResult(false, "Current password is incorrect.", user);
        }

        String strengthErr = PasswordHasher.checkPasswordStrength(new String(newPassword));
        if (strengthErr != null) {
            return new AuthResult(false, strengthErr, user);
        }

        PasswordHasher.HashResult newHash = PasswordHasher.hashPassword(newPassword);
        user.setPasswordHash(newHash.getHashBase64());
        user.setSalt(newHash.getSaltBase64());
        user.setIterations(newHash.getIterations());
        saveUsers();

        auditLogger.log(AuditLogger.EventType.PASSWORD_CHANGED, user.getUsername(), ipAddress,
                "Password changed successfully");
        return new AuthResult(true, "Password updated successfully!", user);
    }

    public User getUser(String username) {
        if (username == null)
            return null;
        return findUserByUsernameOrEmail(username.trim());
    }

    private User findUserByUsernameOrEmail(String query) {
        if (query == null)
            return null;
        User user = users.get(query);
        if (user != null)
            return user;
        for (User u : users.values()) {
            if (query.equalsIgnoreCase(u.getEmail()) || query.equals(u.getUsername())) {
                return u;
            }
        }
        return null;
    }

    public int getUserCount() {
        return users.size();
    }

    public List<User> getAllUsers() {
        return new ArrayList<>(users.values());
    }

    // --- JSON Persistence ---

    private synchronized void loadUsers() {
        if (!dataFile.exists()) {
            return;
        }

        try {
            String content = Files.readString(dataFile.toPath(), StandardCharsets.UTF_8);
            parseUsersJson(content);
            System.out.println(" Loaded " + users.size() + " user accounts from " + dataFile.getName());
        } catch (Exception e) {
            System.err.println("Failed to load user database: " + e.getMessage());
        }
    }

    private synchronized void saveUsers() {
        File parent = dataFile.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        File tmpFile = new File(dataFile.getAbsolutePath() + ".tmp");
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("[\n");
            int index = 0;
            for (User u : users.values()) {
                if (index > 0)
                    sb.append(",\n");
                sb.append("  {\n");
                sb.append("    \"username\": \"").append(escapeJson(u.getUsername())).append("\",\n");
                sb.append("    \"displayName\": \"").append(escapeJson(u.getDisplayName())).append("\",\n");
                sb.append("    \"email\": \"").append(escapeJson(u.getEmail())).append("\",\n");
                sb.append("    \"passwordHash\": \"").append(escapeJson(u.getPasswordHash())).append("\",\n");
                sb.append("    \"salt\": \"").append(escapeJson(u.getSalt())).append("\",\n");
                sb.append("    \"iterations\": ").append(u.getIterations()).append(",\n");
                sb.append("    \"createdAt\": \"").append(escapeJson(u.getCreatedAt())).append("\",\n");
                sb.append("    \"lastLoginAt\": ")
                        .append(u.getLastLoginAt() != null ? "\"" + escapeJson(u.getLastLoginAt()) + "\"" : "null")
                        .append(",\n");
                sb.append("    \"failedAttempts\": ").append(u.getFailedAttempts()).append(",\n");
                sb.append("    \"lockedUntil\": ")
                        .append(u.getLockedUntil() != null ? "\"" + escapeJson(u.getLockedUntil()) + "\"" : "null")
                        .append(",\n");
                sb.append("    \"vaultSalt\": \"").append(escapeJson(u.getVaultSalt())).append("\",\n");
                sb.append("    \"securityQuestion\": \"").append(escapeJson(u.getSecurityQuestion())).append("\",\n");
                sb.append("    \"securityAnswerHash\": ")
                        .append(u.getSecurityAnswerHash() != null ? "\"" + escapeJson(u.getSecurityAnswerHash()) + "\""
                                : "null")
                        .append(",\n");
                sb.append("    \"securityAnswerSalt\": ")
                        .append(u.getSecurityAnswerSalt() != null ? "\"" + escapeJson(u.getSecurityAnswerSalt()) + "\""
                                : "null")
                        .append("\n");
                sb.append("  }");
                index++;
            }
            sb.append("\n]\n");

            Files.writeString(tmpFile.toPath(), sb.toString(), StandardCharsets.UTF_8);
            try {
                Files.move(tmpFile.toPath(), dataFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception moveErr) {
                Files.copy(tmpFile.toPath(), dataFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                tmpFile.delete();
            }
        } catch (Exception e) {
            System.err.println("Error saving users to file: " + e.getMessage());
            if (tmpFile.exists()) {
                tmpFile.delete();
            }
        }

    }

    private void parseUsersJson(String json) {
        json = json.trim();
        if (!json.startsWith("[") || !json.endsWith("]"))
            return;

        int start = json.indexOf('{');
        while (start != -1) {
            int end = findMatchingBrace(json, start);
            if (end == -1)
                break;

            String objStr = json.substring(start, end + 1);
            User u = parseSingleUser(objStr);
            if (u != null && u.getUsername() != null) {
                users.put(u.getUsername(), u);
            }
            start = json.indexOf('{', end + 1);
        }
    }

    private int findMatchingBrace(String text, int start) {
        int depth = 0;
        for (int i = start; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '{')
                depth++;
            else if (c == '}') {
                depth--;
                if (depth == 0)
                    return i;
            }
        }
        return -1;
    }

    private User parseSingleUser(String objStr) {
        User u = new User();
        u.setUsername(extractJsonString(objStr, "username"));
        u.setDisplayName(extractJsonString(objStr, "displayName"));
        u.setEmail(extractJsonString(objStr, "email"));
        u.setPasswordHash(extractJsonString(objStr, "passwordHash"));
        u.setSalt(extractJsonString(objStr, "salt"));
        u.setCreatedAt(extractJsonString(objStr, "createdAt"));
        u.setLastLoginAt(extractJsonString(objStr, "lastLoginAt"));
        u.setLockedUntil(extractJsonString(objStr, "lockedUntil"));
        u.setVaultSalt(extractJsonString(objStr, "vaultSalt"));
        u.setSecurityQuestion(extractJsonString(objStr, "securityQuestion"));
        u.setSecurityAnswerHash(extractJsonString(objStr, "securityAnswerHash"));
        u.setSecurityAnswerSalt(extractJsonString(objStr, "securityAnswerSalt"));

        Integer iters = extractJsonInt(objStr, "iterations");
        u.setIterations(iters != null ? iters : PasswordHasher.ITERATIONS);

        Integer failed = extractJsonInt(objStr, "failedAttempts");
        u.setFailedAttempts(failed != null ? failed : 0);

        return u;
    }

    private String extractJsonString(String json, String key) {
        String search = "\"" + key + "\":";
        int idx = json.indexOf(search);
        if (idx == -1)
            return null;
        int valStart = idx + search.length();
        while (valStart < json.length() && Character.isWhitespace(json.charAt(valStart))) {
            valStart++;
        }
        if (valStart >= json.length() || json.charAt(valStart) != '"') {
            return null; // Not a quoted string (e.g. null, numeric, or boolean)
        }
        int valEnd = json.indexOf('"', valStart + 1);
        while (valEnd != -1 && json.charAt(valEnd - 1) == '\\') {
            valEnd = json.indexOf('"', valEnd + 1);
        }
        if (valEnd == -1)
            return null;
        return unescapeJson(json.substring(valStart + 1, valEnd));
    }

    private Integer extractJsonInt(String json, String key) {
        String search = "\"" + key + "\":";
        int idx = json.indexOf(search);
        if (idx == -1)
            return null;
        int start = idx + search.length();
        while (start < json.length() && Character.isWhitespace(json.charAt(start)))
            start++;
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-'))
            end++;
        if (start == end)
            return null;
        try {
            return Integer.parseInt(json.substring(start, end));
        } catch (Exception e) {
            return null;
        }
    }

    private String escapeJson(String s) {
        if (s == null)
            return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private String unescapeJson(String s) {
        if (s == null)
            return "";
        return s.replace("\\\"", "\"").replace("\\\\", "\\").replace("\\n", "\n").replace("\\r", "\r");
    }
}
