import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;

public class ProcessMonitorLinux extends JFrame {

    // Configurare
    private int checkIntervalSeconds = 60;
    private int maxRuntimeMinutes = 30;
    private int warningMinutes = 25;
    private static final String LOG_FILE = System.getProperty("user.home") + "/.process_monitor.log";
    private static final String CONFIG_FILE = System.getProperty("user.home") + "/.process_monitor.conf";
    private static final String AUTOSTART_DIR = System.getProperty("user.home") + "/.config/autostart";
    private static final String AUTOSTART_FILE = AUTOSTART_DIR + "/process-monitor.desktop";

    // Cuvinte cheie
    private Set<String> keywords = new HashSet<>(Arrays.asList(
            "chrome", "firefox", "brave", "opera", "chromium",
            "steam", "minecraft", "wine", "lutris",
            "discord", "spotify", "telegram", "slack"
    ));

    // Tracking
    private final Map<Integer, Long> processStartTimes = new ConcurrentHashMap<>();
    private final Map<Integer, Boolean> warningShown = new ConcurrentHashMap<>();

    // UI Components
    private JTable processTable;
    private DefaultTableModel tableModel;
    private JTextArea logArea;
    private JButton startButton, stopButton, configButton;
    private JLabel statusLabel;
    private ScheduledExecutorService scheduler;
    private boolean isMonitoring = false;

    public ProcessMonitorLinux() {
        setTitle("Process Monitor - Linux");
        setSize(900, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        loadConfig();
        initUI();
        checkPermissions();
    }

    private void checkPermissions() {
        // Verifică dacă poate accesa /proc
        File procDir = new File("/proc");
        if (!procDir.canRead()) {
            JOptionPane.showMessageDialog(this,
                    "Warning: Limited access to /proc directory.\n" +
                            "Some features may not work correctly.",
                    "Permission Warning", JOptionPane.WARNING_MESSAGE);
        }
    }

    private void initUI() {
        setLayout(new BorderLayout(10, 10));

        // Top Panel - Controls
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));

        startButton = new JButton("Start Monitoring");
        stopButton = new JButton("Stop");
        configButton = new JButton("Settings");
        JButton logButton = new JButton("View Full Log");
        JButton autostartButton = new JButton("Add to Autostart");

        startButton.setBackground(new Color(34, 139, 34));
        startButton.setForeground(Color.WHITE);
        stopButton.setBackground(new Color(178, 34, 34));
        stopButton.setForeground(Color.WHITE);
        stopButton.setEnabled(false);

        startButton.addActionListener(e -> startMonitoring());
        stopButton.addActionListener(e -> stopMonitoring());
        configButton.addActionListener(e -> showConfigDialog());
        logButton.addActionListener(e -> openLogFile());
        autostartButton.addActionListener(e -> addToAutostart());

        topPanel.add(startButton);
        topPanel.add(stopButton);
        topPanel.add(configButton);
        topPanel.add(logButton);
        topPanel.add(autostartButton);

        statusLabel = new JLabel("Status: Stopped");
        statusLabel.setFont(new Font("Arial", Font.BOLD, 12));
        topPanel.add(Box.createHorizontalStrut(20));
        topPanel.add(statusLabel);

        add(topPanel, BorderLayout.NORTH);

        // Center - SplitPane
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.6);

        // Process Table
        String[] columns = {"Process Name", "PID", "User", "Runtime (min)", "Status"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        processTable = new JTable(tableModel);
        processTable.setFont(new Font("Monospace", Font.PLAIN, 12));
        processTable.getTableHeader().setFont(new Font("Sans", Font.BOLD, 12));

        // Context menu pentru procese
        JPopupMenu contextMenu = new JPopupMenu();
        JMenuItem killItem = new JMenuItem("Kill Process (SIGTERM)");
        JMenuItem forceKillItem = new JMenuItem("Force Kill (SIGKILL)");
        JMenuItem ignoreItem = new JMenuItem("Ignore This Session");

        killItem.addActionListener(e -> killSelectedProcess(false));
        forceKillItem.addActionListener(e -> killSelectedProcess(true));
        ignoreItem.addActionListener(e -> ignoreSelectedProcess());

        contextMenu.add(killItem);
        contextMenu.add(forceKillItem);
        contextMenu.addSeparator();
        contextMenu.add(ignoreItem);

        processTable.setComponentPopupMenu(contextMenu);

        JScrollPane tableScroll = new JScrollPane(processTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Tracked Processes"));

        // Log Area
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospace", Font.PLAIN, 11));
        JScrollPane logScroll = new JScrollPane(logArea);
        logScroll.setBorder(BorderFactory.createTitledBorder("Activity Log"));

        splitPane.setTopComponent(tableScroll);
        splitPane.setBottomComponent(logScroll);

        add(splitPane, BorderLayout.CENTER);

        // Bottom Panel - Info
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bottomPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10));
        JLabel infoLabel = new JLabel(
                "Max Runtime: " + maxRuntimeMinutes + " min | " +
                        "Keywords: " + keywords.size() + " | " +
                        "Check Interval: " + checkIntervalSeconds + "s"
        );
        infoLabel.setFont(new Font("Sans", Font.PLAIN, 11));
        bottomPanel.add(infoLabel);
        add(bottomPanel, BorderLayout.SOUTH);
    }

    private void killSelectedProcess(boolean forceKill) {
        int selectedRow = processTable.getSelectedRow();
        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(this, "Please select a process first.");
            return;
        }

        int pid = (int) tableModel.getValueAt(selectedRow, 1);
        String processName = (String) tableModel.getValueAt(selectedRow, 0);

        try {
            String signal = forceKill ? "SIGKILL" : "SIGTERM";
            ProcessBuilder pb = new ProcessBuilder("kill", forceKill ? "-9" : "-15", String.valueOf(pid));
            Process p = pb.start();
            p.waitFor();

            logToUI("Manual kill (" + signal + "): " + processName + " (PID: " + pid + ")");
        } catch (Exception e) {
            logToUI("Failed to kill process: " + e.getMessage());
        }
    }

    private void ignoreSelectedProcess() {
        int selectedRow = processTable.getSelectedRow();
        if (selectedRow == -1) return;

        int pid = (int) tableModel.getValueAt(selectedRow, 1);
        processStartTimes.remove(pid);
        warningShown.remove(pid);
        logToUI("Ignoring PID " + pid + " for this session");
    }

    private void startMonitoring() {
        if (isMonitoring) return;

        isMonitoring = true;
        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        statusLabel.setText("Status: Monitoring Active");
        statusLabel.setForeground(new Color(34, 139, 34));

        logToUI("=== Monitoring Started ===");
        log("Monitoring started");

        scheduler = Executors.newScheduledThreadPool(1);
        scheduler.scheduleAtFixedRate(() -> {
            try {
                checkAndTerminateProcesses();
            } catch (Exception e) {
                logToUI("Error: " + e.getMessage());
            }
        }, 0, checkIntervalSeconds, TimeUnit.SECONDS);
    }

    private void stopMonitoring() {
        if (!isMonitoring) return;

        isMonitoring = false;
        if (scheduler != null) {
            scheduler.shutdown();
        }

        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        statusLabel.setText("Status: Stopped");
        statusLabel.setForeground(new Color(178, 34, 34));

        logToUI("=== Monitoring Stopped ===");
        log("Monitoring stopped");

        tableModel.setRowCount(0);
        processStartTimes.clear();
        warningShown.clear();
    }

    private void checkAndTerminateProcesses() {
        try {
            List<ProcessInfo> processes = getRunningProcesses();
            long currentTime = System.currentTimeMillis();

            // Update table
            SwingUtilities.invokeLater(() -> tableModel.setRowCount(0));

            for (ProcessInfo process : processes) {
                if (matchesKeywords(process.name)) {
                    processStartTimes.putIfAbsent(process.pid, currentTime);

                    long startTime = processStartTimes.get(process.pid);
                    long runtimeMinutes = (currentTime - startTime) / (1000 * 60);

                    String status;
                    if (runtimeMinutes >= maxRuntimeMinutes) {
                        terminateProcess(process);
                        processStartTimes.remove(process.pid);
                        warningShown.remove(process.pid);
                        continue;
                    } else if (runtimeMinutes >= warningMinutes &&
                            !warningShown.getOrDefault(process.pid, false)) {
                        status = "⚠ Warning";
                        showWarningNotification(process, runtimeMinutes);
                        warningShown.put(process.pid, true);
                    } else if (runtimeMinutes >= warningMinutes) {
                        status = "⚠ Warning Sent";
                    } else {
                        status = "✓ OK";
                    }

                    int finalRuntime = (int) runtimeMinutes;
                    String finalStatus = status;
                    SwingUtilities.invokeLater(() -> {
                        tableModel.addRow(new Object[]{
                                process.name,
                                process.pid,
                                process.user,
                                finalRuntime,
                                finalStatus
                        });
                    });
                }
            }

            cleanupDeadProcesses(processes);

        } catch (Exception e) {
            logToUI("Error checking processes: " + e.getMessage());
        }
    }

    private List<ProcessInfo> getRunningProcesses() throws IOException {
        List<ProcessInfo> processes = new ArrayList<>();

        // Folosește ps pentru a obține procesele
        ProcessBuilder pb = new ProcessBuilder("ps", "aux");
        Process process = pb.start();

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {

            String line;
            reader.readLine(); // Skip header

            while ((line = reader.readLine()) != null) {
                String[] parts = line.trim().split("\\s+", 11);
                if (parts.length >= 11) {
                    String user = parts[0];
                    int pid = Integer.parseInt(parts[1]);
                    String command = parts[10];

                    // Extrage numele procesului din command
                    String processName = extractProcessName(command);
                    processes.add(new ProcessInfo(processName, pid, user));
                }
            }
        }

        return processes;
    }

    private String extractProcessName(String command) {
        // Elimină path-ul și argumentele
        String[] parts = command.split("\\s+");
        String basePath = parts[0];

        // Extrage doar numele fișierului
        int lastSlash = basePath.lastIndexOf('/');
        if (lastSlash != -1) {
            return basePath.substring(lastSlash + 1);
        }
        return basePath;
    }

    private void terminateProcess(ProcessInfo process) {
        try {
            // Încearcă mai întâi SIGTERM (graceful)
            ProcessBuilder pb = new ProcessBuilder("kill", "-15", String.valueOf(process.pid));
            Process p = pb.start();
            p.waitFor();

            // Așteaptă 2 secunde
            Thread.sleep(2000);

            // Verifică dacă procesul încă rulează
            if (isProcessRunning(process.pid)) {
                // Dacă încă rulează, folosește SIGKILL
                pb = new ProcessBuilder("kill", "-9", String.valueOf(process.pid));
                p = pb.start();
                p.waitFor();
                logToUI("Force killed (SIGKILL): " + process.name);
            }

            String msg = "Terminated: " + process.name + " (PID: " +
                    process.pid + ", User: " + process.user + ") after " +
                    maxRuntimeMinutes + " min";
            logToUI(msg);
            log(msg);

            showNotification("Process Terminated",
                    process.name + " was closed after " + maxRuntimeMinutes + " minutes");

        } catch (Exception e) {
            logToUI("Failed to terminate " + process.name + ": " + e.getMessage());
        }
    }

    private boolean isProcessRunning(int pid) {
        try {
            ProcessBuilder pb = new ProcessBuilder("kill", "-0", String.valueOf(pid));
            Process p = pb.start();
            return p.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private void showWarningNotification(ProcessInfo process, long runtime) {
        int remaining = maxRuntimeMinutes - (int) runtime;
        String msg = "⚠ Warning: " + process.name + " will close in " + remaining + " minutes";
        logToUI(msg);
        log(msg);

        showNotification("Process Warning",
                process.name + " will be closed in " + remaining + " minutes!");
    }

    private void showNotification(String title, String message) {
        // Încearcă notify-send (disponibil pe majoritatea distro-urilor)
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "notify-send",
                    "-i", "dialog-warning",
                    "-u", "critical",
                    title,
                    message
            );
            pb.start();
        } catch (Exception e) {
            // Fallback la JOptionPane dacă notify-send nu e disponibil
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(this, message, title,
                        JOptionPane.WARNING_MESSAGE);
            });
        }
    }

    private boolean matchesKeywords(String processName) {
        String lower = processName.toLowerCase();
        return keywords.stream().anyMatch(lower::contains);
    }

    private void cleanupDeadProcesses(List<ProcessInfo> activeProcesses) {
        Set<Integer> activePids = new HashSet<>();
        activeProcesses.forEach(p -> activePids.add(p.pid));
        processStartTimes.keySet().removeIf(pid -> !activePids.contains(pid));
        warningShown.keySet().removeIf(pid -> !activePids.contains(pid));
    }

    private void showConfigDialog() {
        JDialog dialog = new JDialog(this, "Settings", true);
        dialog.setSize(500, 400);
        dialog.setLocationRelativeTo(this);
        dialog.setLayout(new BorderLayout(10, 10));

        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // Max runtime
        gbc.gridx = 0; gbc.gridy = 0;
        panel.add(new JLabel("Max Runtime (minutes):"), gbc);
        JSpinner runtimeSpinner = new JSpinner(new SpinnerNumberModel(maxRuntimeMinutes, 1, 480, 5));
        gbc.gridx = 1;
        panel.add(runtimeSpinner, gbc);

        // Warning time
        gbc.gridx = 0; gbc.gridy = 1;
        panel.add(new JLabel("Warning Time (minutes):"), gbc);
        JSpinner warningSpinner = new JSpinner(new SpinnerNumberModel(warningMinutes, 1, 480, 5));
        gbc.gridx = 1;
        panel.add(warningSpinner, gbc);

        // Check interval
        gbc.gridx = 0; gbc.gridy = 2;
        panel.add(new JLabel("Check Interval (seconds):"), gbc);
        JSpinner intervalSpinner = new JSpinner(new SpinnerNumberModel(checkIntervalSeconds, 10, 300, 10));
        gbc.gridx = 1;
        panel.add(intervalSpinner, gbc);

        // Keywords
        gbc.gridx = 0; gbc.gridy = 3;
        panel.add(new JLabel("Keywords (comma-separated):"), gbc);
        JTextArea keywordsArea = new JTextArea(3, 20);
        keywordsArea.setText(String.join(", ", keywords));
        keywordsArea.setLineWrap(true);
        gbc.gridx = 1;
        panel.add(new JScrollPane(keywordsArea), gbc);

        dialog.add(panel, BorderLayout.CENTER);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveButton = new JButton("Save");
        JButton cancelButton = new JButton("Cancel");

        saveButton.addActionListener(e -> {
            maxRuntimeMinutes = (int) runtimeSpinner.getValue();
            warningMinutes = (int) warningSpinner.getValue();
            checkIntervalSeconds = (int) intervalSpinner.getValue();

            keywords.clear();
            String[] kws = keywordsArea.getText().split(",");
            for (String kw : kws) {
                keywords.add(kw.trim().toLowerCase());
            }

            saveConfig();
            logToUI("Settings saved");
            dialog.dispose();
        });

        cancelButton.addActionListener(e -> dialog.dispose());

        buttonPanel.add(saveButton);
        buttonPanel.add(cancelButton);
        dialog.add(buttonPanel, BorderLayout.SOUTH);

        dialog.setVisible(true);
    }

    private void saveConfig() {
        try (PrintWriter writer = new PrintWriter(new FileWriter(CONFIG_FILE))) {
            writer.println("maxRuntime=" + maxRuntimeMinutes);
            writer.println("warningTime=" + warningMinutes);
            writer.println("checkInterval=" + checkIntervalSeconds);
            writer.println("keywords=" + String.join(",", keywords));
            log("Configuration saved to " + CONFIG_FILE);
        } catch (IOException e) {
            logToUI("Failed to save config: " + e.getMessage());
        }
    }

    private void loadConfig() {
        try {
            File configFile = new File(CONFIG_FILE);
            if (!configFile.exists()) {
                log("No config file found, using defaults");
                return;
            }

            Properties props = new Properties();
            props.load(new FileInputStream(configFile));

            maxRuntimeMinutes = Integer.parseInt(props.getProperty("maxRuntime", "30"));
            warningMinutes = Integer.parseInt(props.getProperty("warningTime", "25"));
            checkIntervalSeconds = Integer.parseInt(props.getProperty("checkInterval", "60"));

            String kws = props.getProperty("keywords", "");
            if (!kws.isEmpty()) {
                keywords = new HashSet<>(Arrays.asList(kws.split(",")));
            }
            log("Configuration loaded from " + CONFIG_FILE);
        } catch (Exception e) {
            logToUI("Failed to load config: " + e.getMessage());
        }
    }

    private void addToAutostart() {
        try {
            // Creează directorul autostart dacă nu există
            File autostartDir = new File(AUTOSTART_DIR);
            if (!autostartDir.exists()) {
                autostartDir.mkdirs();
            }

            // Obține path-ul la JAR
            String jarPath = new File(ProcessMonitorLinux.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI()).getPath();

            if (!jarPath.endsWith(".jar")) {
                JOptionPane.showMessageDialog(this,
                        "Please compile to JAR first:\n" +
                                "jar cfm ProcessMonitor.jar manifest.txt *.class",
                        "Not a JAR", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            // Creează fișierul .desktop
            String desktopContent =
                    "[Desktop Entry]\n" +
                            "Type=Application\n" +
                            "Name=Process Monitor\n" +
                            "Comment=Monitor and limit process runtime\n" +
                            "Exec=java -jar " + jarPath + "\n" +
                            "Icon=utilities-system-monitor\n" +
                            "Terminal=false\n" +
                            "Categories=System;Monitor;\n" +
                            "X-GNOME-Autostart-enabled=true\n";

            Files.write(Paths.get(AUTOSTART_FILE), desktopContent.getBytes());

            // Face fișierul executabil
            new File(AUTOSTART_FILE).setExecutable(true);

            JOptionPane.showMessageDialog(this,
                    "Successfully added to autostart!\n" +
                            "File: " + AUTOSTART_FILE,
                    "Success", JOptionPane.INFORMATION_MESSAGE);
            logToUI("Added to autostart: " + AUTOSTART_FILE);
            log("Added to autostart");

        } catch (Exception e) {
            JOptionPane.showMessageDialog(this,
                    "Error adding to autostart: " + e.getMessage() + "\n\n" +
                            "You can manually add it by creating:\n" + AUTOSTART_FILE,
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void openLogFile() {
        try {
            // Încearcă xdg-open (funcționează pe majoritatea distro-urilor)
            ProcessBuilder pb = new ProcessBuilder("xdg-open", LOG_FILE);
            pb.start();
        } catch (Exception e) {
            // Fallback: încearcă editoare comune
            String[] editors = {"gedit", "kate", "nano", "vim", "leafpad"};
            boolean opened = false;

            for (String editor : editors) {
                try {
                    ProcessBuilder pb = new ProcessBuilder(editor, LOG_FILE);
                    pb.start();
                    opened = true;
                    break;
                } catch (Exception ignored) {}
            }

            if (!opened) {
                JOptionPane.showMessageDialog(this,
                        "Could not open log file automatically.\n" +
                                "Please open: " + LOG_FILE,
                        "Info", JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    private void logToUI(String message) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());
            logArea.append("[" + timestamp + "] " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    private void log(String message) {
        try {
            String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                    .format(new Date());
            String logEntry = timestamp + " - " + message + System.lineSeparator();
            Files.write(Paths.get(LOG_FILE), logEntry.getBytes(),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            System.err.println("Failed to write log: " + e.getMessage());
        }
    }

    static class ProcessInfo {
        String name;
        int pid;
        String user;

        ProcessInfo(String name, int pid, String user) {
            this.name = name;
            this.pid = pid;
            this.user = user;
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                // Încearcă să folosească look-and-feel-ul nativ
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                // Fallback la default dacă sistemul nativ nu funcționează
                try {
                    UIManager.setLookAndFeel("javax.swing.plaf.nimbus.NimbusLookAndFeel");
                } catch (Exception ex) {
                    // Folosește default swing look and feel
                }
            }
            new ProcessMonitorLinux().setVisible(true);
        });
    }
}