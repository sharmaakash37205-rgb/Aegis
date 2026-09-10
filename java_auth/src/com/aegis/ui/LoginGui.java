package com.aegis.ui;

import com.aegis.crypto.JavaCryptoEngine;
import com.aegis.security.AuditLogger;
import com.aegis.security.PasswordHasher;
import com.aegis.security.SessionManager;
import com.aegis.storage.UserManager;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.net.URI;
import java.util.Optional;

/**
 * Modern Dark-Themed Desktop Java GUI for Aegis Vault Authentication & Account
 * Security.
 */
public class LoginGui extends JFrame {

    // Theme Palette (Matching Aegis Vault Dark UI)
    private static final Color COLOR_BG = new Color(15, 23, 42); // #0f172a Slate 900
    private static final Color COLOR_CARD = new Color(30, 41, 59); // #1e293b Slate 800
    private static final Color COLOR_CARD_BORDER = new Color(51, 65, 85); // #334155 Slate 700
    private static final Color COLOR_INPUT_BG = new Color(15, 23, 42); // #0f172a
    private static final Color COLOR_PRIMARY = new Color(2, 132, 199); // #0284c7 Cyan / Sky Blue
    private static final Color COLOR_PRIMARY_HOVER = new Color(3, 105, 161);
    private static final Color COLOR_SUCCESS = new Color(16, 185, 129); // #10b981 Emerald Green
    private static final Color COLOR_DANGER = new Color(239, 68, 68); // #ef4444 Red
    private static final Color COLOR_TEXT_MAIN = new Color(248, 250, 252); // #f8fafc
    private static final Color COLOR_TEXT_MUTED = new Color(148, 163, 184); // #94a3b8

    private final UserManager userManager;
    private final SessionManager sessionManager;
    private final AuditLogger auditLogger;
    private final int serverPort;

    private CardLayout cardLayout;
    private JPanel mainContentPanel;

    // Login Form Fields
    private JTextField loginUserField;
    private JPasswordField loginPassField;
    private JLabel loginStatusLabel;
    private JButton loginButton;

    // Register Form Fields
    private JTextField regUserField;
    private JTextField regNameField;
    private JTextField regEmailField;
    private JPasswordField regPassField;
    private JPasswordField regConfirmPassField;
    private JProgressBar regStrengthBar;
    private JLabel regStrengthLabel;
    private JLabel regStatusLabel;
    private JButton regButton;

    // Dashboard View
    private JLabel dashWelcomeLabel;
    private JLabel dashUserLabel;
    private JLabel dashEmailLabel;
    private JLabel dashCreatedLabel;
    private JLabel dashLastLoginLabel;
    private JLabel dashSessionTokenLabel;
    private SessionManager.Session currentSession;
    private UserManager.User currentUser;

    public LoginGui(UserManager userManager, SessionManager sessionManager, AuditLogger auditLogger, int serverPort) {
        this.userManager = userManager;
        this.sessionManager = sessionManager;
        this.auditLogger = auditLogger;
        this.serverPort = serverPort;

        initWindow();
        buildUI();
    }

    private void initWindow() {
        setTitle("Aegis Vault — Secure Authentication System (Java 25)");
        setSize(520, 720);
        setMinimumSize(new Dimension(480, 640));
        setLocationRelativeTo(null);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        getContentPane().setBackground(COLOR_BG);

        // Try load app icon
        File iconFile = new File("assets/app_icon.png");
        if (iconFile.exists()) {
            setIconImage(new ImageIcon(iconFile.getAbsolutePath()).getImage());
        }
    }

    private void buildUI() {
        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(COLOR_BG);
        root.setBorder(new EmptyBorder(25, 25, 25, 25));

        // Header Panel
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBackground(COLOR_BG);
        headerPanel.setBorder(new EmptyBorder(0, 0, 15, 0));

        JLabel titleLabel = new JLabel("🛡️  AEGIS SECURITY PORTAL");
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 22));
        titleLabel.setForeground(COLOR_TEXT_MAIN);

        JLabel subtitleLabel = new JLabel("Zero-Knowledge Identity & Vault Authentication • Java SE Engine");
        subtitleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        subtitleLabel.setForeground(COLOR_TEXT_MUTED);

        headerPanel.add(titleLabel, BorderLayout.NORTH);
        headerPanel.add(subtitleLabel, BorderLayout.SOUTH);
        root.add(headerPanel, BorderLayout.NORTH);

        // Main Card Layout for Switchable Views (Login / Register / Dashboard)
        cardLayout = new CardLayout();
        mainContentPanel = new JPanel(cardLayout);
        mainContentPanel.setBackground(COLOR_BG);

        mainContentPanel.add(createAuthCard(), "AUTH_VIEW");
        mainContentPanel.add(createDashboardCard(), "DASHBOARD_VIEW");

        root.add(mainContentPanel, BorderLayout.CENTER);

        // Footer with Web Access Link
        JPanel footerPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        footerPanel.setBackground(COLOR_BG);

        JLabel webInfoLabel = new JLabel("🌐 Access anywhere on network:");
        webInfoLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        webInfoLabel.setForeground(COLOR_TEXT_MUTED);

        JLabel webLink = new JLabel("http://localhost:" + serverPort);
        webLink.setFont(new Font("Segoe UI", Font.BOLD, 11));
        webLink.setForeground(COLOR_PRIMARY);
        webLink.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        webLink.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                try {
                    Desktop.getDesktop().browse(new URI("http://localhost:" + serverPort));
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(LoginGui.this,
                            "Open http://localhost:" + serverPort + " in your browser.");
                }
            }
        });

        footerPanel.add(webInfoLabel);
        footerPanel.add(webLink);
        root.add(footerPanel, BorderLayout.SOUTH);

        add(root);
    }

    private JPanel createAuthCard() {
        JPanel card = createRoundedCard();
        card.setLayout(new BorderLayout());

        // Tab Navigation Header
        JPanel tabHeader = new JPanel(new GridLayout(1, 2, 8, 0));
        tabHeader.setBackground(COLOR_CARD);
        tabHeader.setBorder(new EmptyBorder(0, 0, 15, 0));

        JButton tabLogin = createStyledButton("🔑 Login", COLOR_PRIMARY);
        JButton tabRegister = createStyledButton("✨ Create Account", COLOR_CARD_BORDER);

        CardLayout formCardLayout = new CardLayout();
        JPanel formContainer = new JPanel(formCardLayout);
        formContainer.setBackground(COLOR_CARD);

        JPanel loginForm = createLoginForm();
        JPanel registerForm = createRegisterForm();

        formContainer.add(loginForm, "LOGIN");
        formContainer.add(registerForm, "REGISTER");

        tabLogin.addActionListener(e -> {
            tabLogin.setBackground(COLOR_PRIMARY);
            tabRegister.setBackground(COLOR_CARD_BORDER);
            formCardLayout.show(formContainer, "LOGIN");
        });

        tabRegister.addActionListener(e -> {
            tabRegister.setBackground(COLOR_PRIMARY);
            tabLogin.setBackground(COLOR_CARD_BORDER);
            formCardLayout.show(formContainer, "REGISTER");
        });

        tabHeader.add(tabLogin);
        tabHeader.add(tabRegister);

        card.add(tabHeader, BorderLayout.NORTH);
        card.add(formContainer, BorderLayout.CENTER);

        return card;
    }

    private JPanel createLoginForm() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(COLOR_CARD);

        panel.add(createFieldLabel("Username or Email"));
        loginUserField = createTextField();
        panel.add(loginUserField);
        panel.add(Box.createVerticalStrut(12));

        panel.add(createFieldLabel("Master Passphrase"));
        loginPassField = createPasswordField();
        panel.add(loginPassField);
        panel.add(Box.createVerticalStrut(15));

        loginStatusLabel = new JLabel(" ");
        loginStatusLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        loginStatusLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(loginStatusLabel);
        panel.add(Box.createVerticalStrut(15));

        loginButton = createStyledButton("🚀 Authenticate & Unlock Vault", COLOR_PRIMARY);
        loginButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        loginButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        loginButton.addActionListener(e -> performLogin());

        // Press Enter to submit
        loginPassField.addActionListener(e -> performLogin());
        loginUserField.addActionListener(e -> performLogin());

        panel.add(loginButton);
        panel.add(Box.createVerticalGlue());

        return panel;
    }

    private JPanel createRegisterForm() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(COLOR_CARD);

        panel.add(createFieldLabel("Username"));
        regUserField = createTextField();
        panel.add(regUserField);
        panel.add(Box.createVerticalStrut(8));

        panel.add(createFieldLabel("Display Name (Optional)"));
        regNameField = createTextField();
        panel.add(regNameField);
        panel.add(Box.createVerticalStrut(8));

        panel.add(createFieldLabel("Email Address (Optional)"));
        regEmailField = createTextField();
        panel.add(regEmailField);
        panel.add(Box.createVerticalStrut(8));

        panel.add(createFieldLabel("Master Password (min 8 chars, mixed case, digit, special)"));
        regPassField = createPasswordField();
        panel.add(regPassField);
        panel.add(Box.createVerticalStrut(4));

        regStrengthBar = new JProgressBar(0, 100);
        regStrengthBar.setValue(0);
        regStrengthBar.setPreferredSize(new Dimension(Integer.MAX_VALUE, 6));
        regStrengthBar.setMaximumSize(new Dimension(Integer.MAX_VALUE, 6));
        regStrengthBar.setForeground(COLOR_DANGER);
        regStrengthBar.setBackground(COLOR_INPUT_BG);
        regStrengthBar.setBorderPainted(false);
        regStrengthBar.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(regStrengthBar);

        regStrengthLabel = new JLabel("Password strength: None");
        regStrengthLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        regStrengthLabel.setForeground(COLOR_TEXT_MUTED);
        regStrengthLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(regStrengthLabel);
        panel.add(Box.createVerticalStrut(8));

        panel.add(createFieldLabel("Confirm Password"));
        regConfirmPassField = createPasswordField();
        panel.add(regConfirmPassField);
        panel.add(Box.createVerticalStrut(10));

        regStatusLabel = new JLabel(" ");
        regStatusLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        regStatusLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(regStatusLabel);
        panel.add(Box.createVerticalStrut(10));

        regButton = createStyledButton("✨ Create Secure Account", COLOR_SUCCESS);
        regButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        regButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        regButton.addActionListener(e -> performRegistration());

        panel.add(regButton);

        // Add real-time password strength listener
        regPassField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                updateStrength();
            }

            public void removeUpdate(DocumentEvent e) {
                updateStrength();
            }

            public void changedUpdate(DocumentEvent e) {
                updateStrength();
            }
        });

        return panel;
    }

    private JPanel createDashboardCard() {
        JPanel card = createRoundedCard();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));

        dashWelcomeLabel = new JLabel("Welcome back!");
        dashWelcomeLabel.setFont(new Font("Segoe UI", Font.BOLD, 20));
        dashWelcomeLabel.setForeground(COLOR_TEXT_MAIN);
        dashWelcomeLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(dashWelcomeLabel);

        JLabel statusBadge = new JLabel("● Session Active & Authenticated");
        statusBadge.setFont(new Font("Segoe UI", Font.BOLD, 12));
        statusBadge.setForeground(COLOR_SUCCESS);
        statusBadge.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(statusBadge);
        card.add(Box.createVerticalStrut(15));

        // Details Panel
        JPanel detailsBox = new JPanel(new GridLayout(5, 1, 4, 4));
        detailsBox.setBackground(COLOR_INPUT_BG);
        detailsBox.setBorder(new EmptyBorder(12, 12, 12, 12));
        detailsBox.setAlignmentX(Component.LEFT_ALIGNMENT);

        dashUserLabel = new JLabel("Username: ");
        dashUserLabel.setForeground(COLOR_TEXT_MAIN);
        dashEmailLabel = new JLabel("Email: ");
        dashEmailLabel.setForeground(COLOR_TEXT_MUTED);
        dashCreatedLabel = new JLabel("Member Since: ");
        dashCreatedLabel.setForeground(COLOR_TEXT_MUTED);
        dashLastLoginLabel = new JLabel("Last Login: ");
        dashLastLoginLabel.setForeground(COLOR_TEXT_MUTED);
        dashSessionTokenLabel = new JLabel("Session Token: ");
        dashSessionTokenLabel.setForeground(COLOR_PRIMARY);

        detailsBox.add(dashUserLabel);
        detailsBox.add(dashEmailLabel);
        detailsBox.add(dashCreatedLabel);
        detailsBox.add(dashLastLoginLabel);
        detailsBox.add(dashSessionTokenLabel);

        card.add(detailsBox);
        card.add(Box.createVerticalStrut(20));

        // Action Buttons
        JButton launchVaultBtn = createStyledButton("🛡️ Launch Aegis Vault Application", COLOR_PRIMARY);
        launchVaultBtn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        launchVaultBtn.setAlignmentX(Component.LEFT_ALIGNMENT);
        launchVaultBtn.addActionListener(e -> launchAegisVault());
        card.add(launchVaultBtn);
        card.add(Box.createVerticalStrut(10));

        JButton quickEncryptBtn = createStyledButton("⚡ Quick Encrypt/Decrypt File (Java Engine)", COLOR_SUCCESS);
        quickEncryptBtn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        quickEncryptBtn.setAlignmentX(Component.LEFT_ALIGNMENT);
        quickEncryptBtn.addActionListener(e -> showJavaCryptoDialog());
        card.add(quickEncryptBtn);
        card.add(Box.createVerticalStrut(10));

        JButton logoutBtn = createStyledButton("🚪 Logout & Invalidate Session", COLOR_DANGER);
        logoutBtn.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        logoutBtn.setAlignmentX(Component.LEFT_ALIGNMENT);
        logoutBtn.addActionListener(e -> performLogout());
        card.add(logoutBtn);

        card.add(Box.createVerticalGlue());

        return card;
    }

    // --- Actions ---

    private void performLogin() {
        String username = loginUserField.getText().trim();
        char[] password = loginPassField.getPassword();

        if (username.isEmpty() || password.length == 0) {
            showLoginError("Please enter both username and password.");
            return;
        }

        loginButton.setEnabled(false);
        loginButton.setText("Verifying Credentials (PBKDF2 600K)...");
        loginStatusLabel.setText("🔐 Cryptographic verification in progress...");
        loginStatusLabel.setForeground(COLOR_TEXT_MUTED);

        SwingWorker<UserManager.AuthResult, Void> worker = new SwingWorker<>() {
            @Override
            protected UserManager.AuthResult doInBackground() {
                return userManager.authenticate(username, password, "127.0.0.1 (Desktop GUI)");
            }

            @Override
            protected void done() {
                loginButton.setEnabled(true);
                loginButton.setText("🚀 Authenticate & Unlock Vault");
                try {
                    UserManager.AuthResult res = get();
                    if (res.isSuccess()) {
                        currentUser = res.getUser();
                        currentSession = sessionManager.createSession(currentUser.getUsername(), "127.0.0.1",
                                "Aegis Desktop Client");
                        loginPassField.setText("");
                        showDashboard();
                    } else {
                        showLoginError(res.getMessage());
                    }
                } catch (Exception ex) {
                    showLoginError("Authentication error: " + ex.getMessage());
                }
            }
        };
        worker.execute();
    }

    private void performRegistration() {
        String username = regUserField.getText().trim();
        String displayName = regNameField.getText().trim();
        String email = regEmailField.getText().trim();
        char[] pass = regPassField.getPassword();
        char[] confirm = regConfirmPassField.getPassword();

        if (username.isEmpty() || pass.length == 0) {
            showRegError("Username and password are required.");
            return;
        }

        if (!java.util.Arrays.equals(pass, confirm)) {
            showRegError("Passwords do not match.");
            return;
        }

        regButton.setEnabled(false);
        regButton.setText("Generating Salt & Hashing...");
        regStatusLabel.setText("Computing PBKDF2 with 600,000 iterations...");
        regStatusLabel.setForeground(COLOR_TEXT_MUTED);

        SwingWorker<UserManager.AuthResult, Void> worker = new SwingWorker<>() {
            @Override
            protected UserManager.AuthResult doInBackground() {
                return userManager.register(username, displayName, email, pass, "127.0.0.1 (Desktop GUI)");
            }

            @Override
            protected void done() {
                regButton.setEnabled(true);
                regButton.setText("✨ Create Secure Account");
                try {
                    UserManager.AuthResult res = get();
                    if (res.isSuccess()) {
                        currentUser = res.getUser();
                        currentSession = sessionManager.createSession(currentUser.getUsername(), "127.0.0.1",
                                "Aegis Desktop Client");
                        regPassField.setText("");
                        regConfirmPassField.setText("");
                        showDashboard();
                    } else {
                        showRegError(res.getMessage());
                    }
                } catch (Exception ex) {
                    showRegError("Registration failed: " + ex.getMessage());
                }
            }
        };
        worker.execute();
    }

    private void showDashboard() {
        if (currentUser != null && currentSession != null) {
            dashWelcomeLabel.setText("Welcome back, " + currentUser.getDisplayName() + "!");
            dashUserLabel.setText("👤 Username: " + currentUser.getUsername());
            dashEmailLabel.setText(
                    "📧 Email: " + (currentUser.getEmail().isEmpty() ? "Not specified" : currentUser.getEmail()));
            dashCreatedLabel.setText("📅 Member Since: " + currentUser.getCreatedAt().substring(0, 10));
            dashLastLoginLabel.setText("⏱️ Last Login: Just now");
            String tokenShort = currentSession.getToken().substring(0, 16) + "...";
            dashSessionTokenLabel.setText("🔑 Token: " + tokenShort);

            cardLayout.show(mainContentPanel, "DASHBOARD_VIEW");
        }
    }

    private void performLogout() {
        if (currentSession != null) {
            sessionManager.revokeSession(currentSession.getToken());
            auditLogger.log(AuditLogger.EventType.LOGOUT, currentUser != null ? currentUser.getUsername() : "unknown",
                    "127.0.0.1", "Desktop Logout");
            currentSession = null;
            currentUser = null;
        }
        cardLayout.show(mainContentPanel, "AUTH_VIEW");
        loginStatusLabel.setText("Logged out successfully.");
        loginStatusLabel.setForeground(COLOR_SUCCESS);
    }

    private void launchAegisVault() {
        try {
            // Check if main.py exists
            File mainPy = new File("main.py");
            if (mainPy.exists()) {
                ProcessBuilder pb = new ProcessBuilder("python", "main.py");
                pb.directory(new File("."));
                pb.start();
                JOptionPane.showMessageDialog(this, "Aegis Vault application launched successfully!", "Launched",
                        JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this, "main.py not found in current workspace directory.", "Error",
                        JOptionPane.ERROR_MESSAGE);
            }
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Failed to launch main.py: " + e.getMessage(), "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void showJavaCryptoDialog() {
        JFileChooser fileChooser = new JFileChooser(".");
        fileChooser.setDialogTitle("Select file to Encrypt or Decrypt");
        int res = fileChooser.showOpenDialog(this);
        if (res != JFileChooser.APPROVE_OPTION)
            return;

        File selectedFile = fileChooser.getSelectedFile();
        boolean isEncrypted = selectedFile.getName().endsWith(".vault") || selectedFile.getName().endsWith(".enc");

        JPasswordField pwdField = new JPasswordField(20);
        int opt = JOptionPane.showConfirmDialog(
                this,
                new Object[] { (isEncrypted ? "Enter Password to Decrypt:" : "Enter Password to Encrypt:"), pwdField },
                isEncrypted ? "Decrypt File (Java AES-256-GCM)" : "Encrypt File (Java AES-256-GCM)",
                JOptionPane.OK_CANCEL_OPTION);

        if (opt != JOptionPane.OK_OPTION)
            return;
        char[] password = pwdField.getPassword();
        if (password.length == 0) {
            JOptionPane.showMessageDialog(this, "Password cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        File outFile;
        File desktopDir = new File(System.getProperty("user.home"), "Desktop");
        File oneDriveDesktop = new File(System.getenv("OneDrive", ""), "Desktop");
        if (oneDriveDesktop.isDirectory()) {
            desktopDir = oneDriveDesktop;
        }
        File outputRoot = new File(desktopDir, "Secure Folder");
        if (isEncrypted) {
            String outName = selectedFile.getName().replaceFirst("\\.(vault|enc)$", "");
            if (outName.equals(selectedFile.getName()))
                outName += ".decrypted";
            File outputDir = new File(outputRoot, "Decrypted file");
            if (!outputDir.exists() && !outputDir.mkdirs()) {
                JOptionPane.showMessageDialog(this, "Unable to create Decrypted file folder.", "Error",
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
            outFile = new File(outputDir, outName);
            if (outFile.exists()) {
                outFile = new File(outputDir, "restored_" + outName);
            }
        } else {
            File outputDir = new File(outputRoot, "Encrypted file");
            if (!outputDir.exists() && !outputDir.mkdirs()) {
                JOptionPane.showMessageDialog(this, "Unable to create Encrypted file folder.", "Error",
                        JOptionPane.ERROR_MESSAGE);
                return;
            }
            outFile = new File(outputDir, selectedFile.getName() + ".vault");
        }

        ProgressMonitor monitor = new ProgressMonitor(this, (isEncrypted ? "Decrypting..." : "Encrypting..."),
                "Processing chunks", 0, 100);
        monitor.setMillisToDecideToPopup(0);
        monitor.setMillisToPopup(0);

        SwingWorker<Void, Void> cryptoWorker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() throws Exception {
                if (isEncrypted) {
                    JavaCryptoEngine.decryptFile(selectedFile, outFile, password, (processed, total) -> {
                        int percent = total > 0 ? (int) ((processed * 100) / total) : 0;
                        SwingUtilities.invokeLater(() -> monitor.setProgress(percent));
                    });
                } else {
                    JavaCryptoEngine.encryptFile(selectedFile, outFile, password, (processed, total) -> {
                        int percent = total > 0 ? (int) ((processed * 100) / total) : 0;
                        SwingUtilities.invokeLater(() -> monitor.setProgress(percent));
                    });
                }
                return null;
            }

            @Override
            protected void done() {
                monitor.close();
                try {
                    get();
                    JOptionPane.showMessageDialog(LoginGui.this,
                            (isEncrypted ? "Decryption" : "Encryption") + " complete!\nOutput: "
                                    + outFile.getAbsolutePath(),
                            "Success", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(LoginGui.this,
                            "Cryptographic error: " + ex.getCause().getMessage(),
                            "Failure", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        cryptoWorker.execute();
    }

    private void updateStrength() {
        String pwd = new String(regPassField.getPassword());
        if (pwd.isEmpty()) {
            regStrengthBar.setValue(0);
            regStrengthLabel.setText("Password strength: None");
            regStrengthLabel.setForeground(COLOR_TEXT_MUTED);
            return;
        }

        int score = 0;
        if (pwd.length() >= 8)
            score += 25;
        if (pwd.length() >= 14)
            score += 15;
        if (pwd.matches(".*[A-Z].*"))
            score += 20;
        if (pwd.matches(".*[a-z].*"))
            score += 15;
        if (pwd.matches(".*[0-9].*"))
            score += 15;
        if (pwd.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*"))
            score += 10;

        regStrengthBar.setValue(score);
        if (score < 40) {
            regStrengthBar.setForeground(COLOR_DANGER);
            regStrengthLabel.setText("Password strength: Weak");
            regStrengthLabel.setForeground(COLOR_DANGER);
        } else if (score < 75) {
            regStrengthBar.setForeground(new Color(234, 179, 8)); // Yellow/Amber
            regStrengthLabel.setText("Password strength: Medium");
            regStrengthLabel.setForeground(new Color(234, 179, 8));
        } else if (score < 90) {
            regStrengthBar.setForeground(COLOR_SUCCESS);
            regStrengthLabel.setText("Password strength: Strong");
            regStrengthLabel.setForeground(COLOR_SUCCESS);
        } else {
            regStrengthBar.setForeground(COLOR_PRIMARY);
            regStrengthLabel.setText("Password strength: Military-Grade 🛡️");
            regStrengthLabel.setForeground(COLOR_PRIMARY);
        }
    }

    private void showLoginError(String msg) {
        loginStatusLabel.setText("❌ " + msg);
        loginStatusLabel.setForeground(COLOR_DANGER);
    }

    private void showRegError(String msg) {
        regStatusLabel.setText("❌ " + msg);
        regStatusLabel.setForeground(COLOR_DANGER);
    }

    // --- UI Helper Components ---

    private JPanel createRoundedCard() {
        JPanel card = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(COLOR_CARD);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 16, 16);
                g2.setColor(COLOR_CARD_BORDER);
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 16, 16);
                g2.dispose();
            }
        };
        card.setOpaque(false);
        card.setBorder(new EmptyBorder(20, 20, 20, 20));
        return card;
    }

    private JLabel createFieldLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        label.setForeground(COLOR_TEXT_MUTED);
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        label.setBorder(new EmptyBorder(0, 0, 4, 0));
        return label;
    }

    private JTextField createTextField() {
        JTextField tf = new JTextField();
        tf.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        tf.setBackground(COLOR_INPUT_BG);
        tf.setForeground(COLOR_TEXT_MAIN);
        tf.setCaretColor(COLOR_TEXT_MAIN);
        tf.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(COLOR_CARD_BORDER, 1, true),
                BorderFactory.createEmptyBorder(8, 10, 8, 10)));
        tf.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        tf.setAlignmentX(Component.LEFT_ALIGNMENT);
        return tf;
    }

    private JPasswordField createPasswordField() {
        JPasswordField pf = new JPasswordField();
        pf.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        pf.setBackground(COLOR_INPUT_BG);
        pf.setForeground(COLOR_TEXT_MAIN);
        pf.setCaretColor(COLOR_TEXT_MAIN);
        pf.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(COLOR_CARD_BORDER, 1, true),
                BorderFactory.createEmptyBorder(8, 10, 8, 10)));
        pf.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        pf.setAlignmentX(Component.LEFT_ALIGNMENT);
        return pf;
    }

    private JButton createStyledButton(String text, Color bg) {
        JButton btn = new JButton(text);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 13));
        btn.setBackground(bg);
        btn.setForeground(Color.WHITE);
        btn.setFocusPainted(false);
        btn.setBorderPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setBorder(BorderFactory.createEmptyBorder(10, 16, 10, 16));
        return btn;
    }
}
