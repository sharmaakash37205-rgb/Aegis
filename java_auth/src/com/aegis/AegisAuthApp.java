package com.aegis;

import com.aegis.security.AuditLogger;
import com.aegis.security.SessionManager;
import com.aegis.server.AuthHttpServer;
import com.aegis.storage.UserManager;
import com.aegis.ui.LoginGui;

import javax.swing.*;
import java.awt.GraphicsEnvironment;
import java.io.File;

/**
 * Main Application Runner for Aegis Secure Authentication System.
 * Starts embedded Java REST & Web Server and Modern Desktop GUI.
 */
public class AegisAuthApp {

    public static final String VERSION = "1.0.0-Java25";
    public static final int DEFAULT_PORT = 8080;

    public static void main(String[] args) {
        int port = DEFAULT_PORT;
        boolean headless = false;

        // Parse CLI options
        for (int i = 0; i < args.length; i++) {
            if ("--port".equals(args[i]) && i + 1 < args.length) {
                try {
                    port = Integer.parseInt(args[++i]);
                } catch (NumberFormatException ignored) {}
            } else if ("--headless".equals(args[i]) || "--server-only".equals(args[i])) {
                headless = true;
            }
        }

        System.out.println("==================================================");
        System.out.println("  🛡️  AEGIS VAULT — SECURE AUTHENTICATION SYSTEM   ");
        System.out.println("       Version: " + VERSION + " | Java SE 25        ");
        System.out.println("==================================================");

        // Ensure directories exist
        File dataDir = new File("data");
        if (!dataDir.exists()) {
            dataDir.mkdirs();
        }

        // Initialize Services
        AuditLogger auditLogger = new AuditLogger("data/audit.log");
        SessionManager sessionManager = new SessionManager();
        UserManager userManager = new UserManager("data/users.json", auditLogger);

        // Locate web assets root
        String webPath = "java_auth/web";
        if (!new File(webPath).exists()) {
            webPath = "web";
        }

        // Start HTTP/REST & Web Portal Server
        AuthHttpServer server = null;
        int activePort = port;
        for (int retry = 0; retry < 5; retry++) {
            try {
                server = new AuthHttpServer(activePort, webPath, userManager, sessionManager, auditLogger);
                server.start();
                break;
            } catch (Exception e) {
                System.out.println("Port " + activePort + " unavailable, trying " + (activePort + 1) + "...");
                activePort++;
            }
        }

        if (server == null) {
            System.err.println("❌ Failed to bind HTTP server to any port.");
        } else {
            final AuthHttpServer finalServer = server;
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("\nShutting down Aegis Auth System...");
                finalServer.stop();
            }));
        }

        // Launch Desktop GUI if not running headless
        if (!headless && !GraphicsEnvironment.isHeadless()) {
            final int guiServerPort = activePort;
            SwingUtilities.invokeLater(() -> {
                try {
                    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                } catch (Exception ignored) {}

                LoginGui gui = new LoginGui(userManager, sessionManager, auditLogger, guiServerPort);
                gui.setVisible(true);
            });
        } else {
            System.out.println("🖥️ Running in headless server mode. Press Ctrl+C to stop.");
        }
    }
}
