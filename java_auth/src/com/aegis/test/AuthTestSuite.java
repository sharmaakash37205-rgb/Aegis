package com.aegis.test;

import com.aegis.crypto.JavaCryptoEngine;
import com.aegis.security.AuditLogger;
import com.aegis.security.PasswordHasher;
import com.aegis.security.SessionManager;
import com.aegis.storage.UserManager;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Optional;

/**
 * Automated Verification & Cryptographic Test Suite for Aegis Java Auth System.
 */
public class AuthTestSuite {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        System.out.println("==================================================");
        System.out.println("🧪 RUNNING AEGIS AUTHENTICATION & CRYPTO TEST SUITE");
        System.out.println("==================================================\n");

        testPasswordHashing();
        testPasswordStrengthPolicy();
        testSessionManagement();
        testUserManagerAndLockout();
        testStreamingCryptoEngine();

        System.out.println("\n==================================================");
        System.out.println(String.format("🏁 TEST RESULTS: %d PASSED, %d FAILED", passed, failed));
        System.out.println("==================================================");

        if (failed > 0) {
            System.exit(1);
        }
    }

    private static void assertTrue(String testName, boolean condition, String message) {
        if (condition) {
            System.out.println("  ✅ PASS: " + testName);
            passed++;
        } else {
            System.err.println("  ❌ FAIL: " + testName + " - " + message);
            failed++;
        }
    }

    private static void testPasswordHashing() {
        System.out.println("▶ [1/5] Testing PBKDF2-HMAC-SHA256 Password Hashing...");

        char[] password = "SecureVault#Pass2026!".toCharArray();
        PasswordHasher.HashResult res = PasswordHasher.hashPassword(password);

        assertTrue("Hash generation not null", res != null && res.getHashBase64() != null, "Hash result is null");
        assertTrue("Salt generation 128-bit", res.getSaltBase64().length() >= 20, "Salt size invalid");
        assertTrue("Iterations 600,000", res.getIterations() == 600_000, "Iteration mismatch");

        boolean match = PasswordHasher.verifyPassword(password, res.getHashBase64(), res.getSaltBase64(),
                res.getIterations());
        assertTrue("Correct password verification", match, "Verification failed for correct password");

        boolean wrongMatch = PasswordHasher.verifyPassword("WrongPassword#123".toCharArray(), res.getHashBase64(),
                res.getSaltBase64(), res.getIterations());
        assertTrue("Incorrect password rejection", !wrongMatch, "Verification passed for incorrect password");
    }

    private static void testPasswordStrengthPolicy() {
        System.out.println("▶ [2/5] Testing Password Complexity Policy...");

        assertTrue("Reject short password", PasswordHasher.checkPasswordStrength("Sh0rt!") != null,
                "Accepted short password");
        assertTrue("Reject no uppercase", PasswordHasher.checkPasswordStrength("lowercase123!") != null,
                "Accepted no uppercase");
        assertTrue("Reject no digits", PasswordHasher.checkPasswordStrength("NoDigitsHere!!") != null,
                "Accepted no digits");
        assertTrue("Reject no special", PasswordHasher.checkPasswordStrength("NoSpecialChar123") != null,
                "Accepted no special char");
        assertTrue("Accept strong password", PasswordHasher.checkPasswordStrength("P@ssw0rd2026SuperSecure") == null,
                "Rejected valid password");
    }

    private static void testSessionManagement() {
        System.out.println("▶ [3/5] Testing 256-bit Cryptographic Session Tokens...");

        SessionManager sm = new SessionManager(2); // 2 second TTL for test
        SessionManager.Session session = sm.createSession("agent_007", "192.168.1.50", "Firefox/120.0");

        assertTrue("Token length is 64 hex chars (256-bit)", session.getToken().length() == 64, "Token length invalid");

        Optional<SessionManager.Session> valid = sm.validateSession(session.getToken());
        assertTrue("Session validation success", valid.isPresent() && valid.get().getUsername().equals("agent_007"),
                "Session validation failed");

        boolean revoked = sm.revokeSession(session.getToken());
        assertTrue("Session revocation", revoked && sm.validateSession(session.getToken()).isEmpty(),
                "Session still valid after revoke");
    }

    private static void testUserManagerAndLockout() {
        System.out.println("▶ [4/5] Testing User Registration, Authentication & Brute-Force Lockout...");

        File testData = new File("data/test_users.json");
        if (testData.exists())
            testData.delete();

        AuditLogger audit = new AuditLogger("data/test_audit.log");
        UserManager um = new UserManager(testData.getAbsolutePath(), audit);

        char[] pass = "MasterKey#2026!".toCharArray();
        String question = "What was the name of your first security key or pet?";
        String answer = "CyberShield99";

        UserManager.AuthResult regRes = um.register("testuser", "Test Agent", "test@aegis.local", pass, question,
                answer, "127.0.0.1");
        assertTrue("User registration with custom username",
                regRes.isSuccess() && regRes.getUser().getUsername().equals("testuser"),
                "Registration failed: " + regRes.getMessage());

        UserManager.AuthResult authRes = um.authenticate("testuser", pass, "127.0.0.1");
        assertTrue("Valid authentication", authRes.isSuccess(), "Authentication failed: " + authRes.getMessage());

        char[] caseSensitivePass = "CaseSensitive#2026!".toCharArray();
        UserManager.AuthResult caseSensitiveReg = um.register("CaseUser", "Case User", "case@aegis.local",
                caseSensitivePass, "127.0.0.1");
        assertTrue("Username preserves registration case",
                caseSensitiveReg.isSuccess() && "CaseUser".equals(caseSensitiveReg.getUser().getUsername()),
                "Username case was not preserved");
        UserManager.AuthResult exactCaseLogin = um.authenticate("CaseUser", caseSensitivePass, "127.0.0.1");
        assertTrue("Exact-case username authenticates", exactCaseLogin.isSuccess(), "Exact-case login failed");
        UserManager.AuthResult wrongCaseLogin = um.authenticate("caseuser", caseSensitivePass, "127.0.0.1");
        assertTrue("Different-case username is rejected", !wrongCaseLogin.isSuccess(),
                "Username matching is still case-insensitive");

        // Test Security Question Lookup
        String retrievedQuestion = um.getSecurityQuestion("testuser");
        assertTrue("Retrieve Security Question", question.equals(retrievedQuestion), "Security question mismatch");

        // Test 5 failed attempts -> lockout
        char[] wrongPass = "WrongPass#123".toCharArray();
        for (int i = 1; i <= 4; i++) {
            UserManager.AuthResult failRes = um.authenticate("testuser", wrongPass, "127.0.0.1");
            assertTrue("Attempt " + i + " failed but not locked", !failRes.isSuccess() && !failRes.isLocked(),
                    "Unexpected lock state at attempt " + i);
        }

        UserManager.AuthResult fifthFail = um.authenticate("testuser", wrongPass, "127.0.0.1");
        assertTrue("Attempt 5 triggers lockout", !fifthFail.isSuccess() && fifthFail.isLocked(),
                "Lockout was not triggered on 5th attempt");

        // Attempt during lockout with right password should still be rejected
        UserManager.AuthResult lockedAttempt = um.authenticate("testuser", pass, "127.0.0.1");
        assertTrue("Lockout blocks correct password while active",
                !lockedAttempt.isSuccess() && lockedAttempt.isLocked(), "Allowed login while locked");

        // Test Forgot Password Recovery with Wrong Answer
        UserManager.AuthResult wrongAnsRes = um.resetPasswordWithSecurityAnswer("testuser", "WrongAnswer",
                "BrandNew#Pass2026!".toCharArray(), "127.0.0.1");
        assertTrue("Reject wrong security answer during reset", !wrongAnsRes.isSuccess(),
                "Accepted wrong security answer");

        // Test Forgot Password Recovery with Correct Answer
        char[] newPass = "BrandNew#Pass2026!".toCharArray();
        UserManager.AuthResult resetRes = um.resetPasswordWithSecurityAnswer("testuser", answer, newPass, "127.0.0.1");
        assertTrue("Password reset with correct security answer", resetRes.isSuccess(),
                "Password reset failed: " + resetRes.getMessage());

        // Test Login with New Password & Verify Lockout is Cleared
        UserManager.AuthResult newLoginRes = um.authenticate("testuser", newPass, "127.0.0.1");
        assertTrue("Login with newly recovered password", newLoginRes.isSuccess() && !newLoginRes.isLocked(),
                "Failed to login with new password");

        // Clean up test files
        if (testData.exists())
            testData.delete();
        new File("data/test_audit.log").delete();
    }

    private static void testStreamingCryptoEngine() {
        System.out.println("▶ [5/5] Testing Java Native AES-256-GCM Streaming Encryption...");

        try {
            File rawFile = new File("data/test_plain.txt");
            File encFile = new File("data/test_encrypted.vault");
            File decFile = new File("data/test_decrypted.txt");

            String originalContent = "Aegis Vault Military-Grade Test Payload — 128-bit chunk authentication with sequenced nonces.\n"
                    .repeat(500);
            Files.writeString(rawFile.toPath(), originalContent, StandardCharsets.UTF_8);

            char[] cryptoPass = "VaultP@ssphrase#999".toCharArray();

            // Encrypt
            JavaCryptoEngine.encryptFile(rawFile, encFile, cryptoPass, null);
            assertTrue("Encrypted file generated", encFile.exists() && encFile.length() > rawFile.length(),
                    "Encrypted file missing or empty");

            // Verify SECV Header
            byte[] header = Files.readAllBytes(encFile.toPath());
            byte[] magic = Arrays.copyOfRange(header, 0, 4);
            assertTrue("Encrypted file has SECV magic header", Arrays.equals(magic, "SECV".getBytes()),
                    "Magic header mismatch");

            // Decrypt
            JavaCryptoEngine.decryptFile(encFile, decFile, cryptoPass, null);
            assertTrue("Decrypted file generated", decFile.exists(), "Decrypted file missing");

            String decryptedContent = Files.readString(decFile.toPath(), StandardCharsets.UTF_8);
            assertTrue("Plaintext matches decrypted byte-for-byte", originalContent.equals(decryptedContent),
                    "Content mismatch after decryption");

            // Clean up
            rawFile.delete();
            encFile.delete();
            decFile.delete();
        } catch (Exception e) {
            assertTrue("Crypto engine execution", false, "Exception: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
