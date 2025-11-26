import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.lang.management.*;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import com.sun.management.OperatingSystemMXBean;

public class ProcessMonitorLinux extends JFrame {

    // Configurare Process Monitor
    private int checkIntervalSeconds = 60;
    private int maxRuntimeMinutes = 30;
    private int warningMinutes = 25;

    // Configurare System Monitor
    private int systemCheckIntervalSeconds = 5;

    // Paths
    private static final String LOG_FILE = System.getProperty("user.home") + "/.system_monitor.log";
    private static final String CONFIG_FILE = System.getProperty("user.home") + "/.system_monitor.conf";
    private static final String AUTOSTART_DIR = System.getProperty("user.home") + "/.config/autostart";
    private static final String AUTOSTART_FILE = AUTOSTART_DIR + "/system-monitor.desktop";

    // Cuvinte cheie pentru procese
    private Set<String> keywords = new HashSet<>(Arrays.asList(
            "chrome", "firefox", "brave", "opera", "chromium",
            "steam", "minecraft", "wine", "lutris",
            "discord", "spotify", "telegram", "slack"
    ));

    // Tracking procese
    private final Map<Integer, Long> processStartTimes = new ConcurrentHashMap<>();
    private final Map<Integer, Boolean> warningShown = new ConcurrentHashMap<>();

    // System monitoring
    private OperatingSystemMXBean osBean;
    private Runtime runtime;

    // UI Components - Process Monitor
    private JTable processTable;
    private DefaultTableModel processTableModel;
    private JTextArea logArea;
    private JButton startProcessButton, stopProcessButton, configButton;
    private JLabel processStatusLabel;
    private ScheduledExecutorService processScheduler;
    private boolean isProcessMonitoring = false;

    // UI Components - System Monitor
    private JLabel cpuLabel, ramLabel, totalRamLabel, freeRamLabel, usedRamLabel;
    private JProgressBar cpuProgressBar, ramProgressBar;
    private JButton startSystemButton, stopSystemButton;
    private JLabel systemStatusLabel;
    private ScheduledExecutorService systemScheduler;
    private boolean isSystemMonitoring = false;
    private JTable systemHistoryTable;
    private DefaultTableModel systemHistoryModel;
    private final int MAX_HISTORY_ROWS = 100;

    public ProcessMonitorLinux() {
        setTitle("System Monitor - Linux (Process & Resources)");
        setSize(1000, 700);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        initSystemBeans();
        loadConfig();
        initUI();
        checkPermissions();
    }

    private void initSystemBeans() {
        osBean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
        runtime = Runtime.getRuntime();
    }

    private void checkPermissions() {
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

        // Main tabbed pane
        JTabbedPane tabbedPane = new JTabbedPane();

        // Tab 1: System Resources Monitor
        tabbedPane.addTab("System Resources", createSystemMonitorPanel());

        // Tab 2: Process Monitor
        tabbedPane.addTab("Process Monitor", createProcessMonitorPanel());

        // Tab 3: Settings & Logs
        tabbedPane.addTab("Logs & Settings", createLogsPanel());

        add(tabbedPane, BorderLayout.CENTER);

        // Bottom status bar
        JPanel statusBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusBar.setBorder(BorderFactory.createEtchedBorder());
        JLabel infoLabel = new JLabel("System Monitor v1.0 | Log: " + LOG_FILE);
        statusBar.add(infoLabel);
        add(statusBar, BorderLayout.SOUTH);
    }

    private JPanel createSystemMonitorPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top control panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        startSystemButton = new JButton("Start System Monitoring");
        stopSystemButton = new JButton("Stop");
        JButton autostartButton = new JButton("Add to Autostart");

        startSystemButton.setBackground(new Color(34, 139, 34));
        startSystemButton.setForeground(Color.WHITE);
        stopSystemButton.setBackground(new Color(178, 34, 34));
        stopSystemButton.setForeground(Color.WHITE);
        stopSystemButton.setEnabled(false);

        startSystemButton.addActionListener(e -> startSystemMonitoring());
        stopSystemButton.addActionListener(e -> stopSystemMonitoring());
        autostartButton.addActionListener(e -> addToAutostart());

        controlPanel.add(startSystemButton);
        controlPanel.add(stopSystemButton);
        controlPanel.add(autostartButton);

        systemStatusLabel = new JLabel("Status: Stopped");
        systemStatusLabel.setFont(new Font("Sans", Font.BOLD, 12));
        controlPanel.add(Box.createHorizontalStrut(20));
        controlPanel.add(systemStatusLabel);

        panel.add(controlPanel, BorderLayout.NORTH);

        // Center - Current stats and history
        JPanel centerPanel = new JPanel(new BorderLayout(10, 10));

        // Current stats panel
        JPanel statsPanel = new JPanel(new GridLayout(2, 1, 10, 10));
        statsPanel.setBorder(BorderFactory.createTitledBorder("Current System Status"));

        // CPU Panel
        JPanel cpuPanel = new JPanel(new BorderLayout(10, 5));
        cpuPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        cpuLabel = new JLabel("CPU Load: 0.00%");
        cpuLabel.setFont(new Font("Monospace", Font.BOLD, 14));
        cpuProgressBar = new JProgressBar(0, 100);
        cpuProgressBar.setStringPainted(true);
        cpuProgressBar.setPreferredSize(new Dimension(400, 30));
        cpuPanel.add(cpuLabel, BorderLayout.NORTH);
        cpuPanel.add(cpuProgressBar, BorderLayout.CENTER);

        // RAM Panel
        JPanel ramPanel = new JPanel(new BorderLayout(10, 5));
        ramPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel ramLabelsPanel = new JPanel(new GridLayout(4, 1, 5, 5));
        ramLabel = new JLabel("RAM Usage: 0.00%");
        ramLabel.setFont(new Font("Monospace", Font.BOLD, 14));
        totalRamLabel = new JLabel("Total RAM: 0 MB");
        freeRamLabel = new JLabel("Free RAM: 0 MB");
        usedRamLabel = new JLabel("Used RAM: 0 MB");

        ramLabelsPanel.add(ramLabel);
        ramLabelsPanel.add(totalRamLabel);
        ramLabelsPanel.add(usedRamLabel);
        ramLabelsPanel.add(freeRamLabel);

        ramProgressBar = new JProgressBar(0, 100);
        ramProgressBar.setStringPainted(true);
        ramProgressBar.setPreferredSize(new Dimension(400, 30));

        ramPanel.add(ramLabelsPanel, BorderLayout.NORTH);
        ramPanel.add(ramProgressBar, BorderLayout.CENTER);

        statsPanel.add(cpuPanel);
        statsPanel.add(ramPanel);

        centerPanel.add(statsPanel, BorderLayout.NORTH);

        // History table
        String[] historyColumns = {"Time", "CPU Load (%)", "Total RAM (MB)", "Used RAM (MB)", "Free RAM (MB)"};
        systemHistoryModel = new DefaultTableModel(historyColumns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        systemHistoryTable = new JTable(systemHistoryModel);
        systemHistoryTable.setFont(new Font("Monospace", Font.PLAIN, 11));
        JScrollPane historyScroll = new JScrollPane(systemHistoryTable);
        historyScroll.setBorder(BorderFactory.createTitledBorder("History (Last " + MAX_HISTORY_ROWS + " readings)"));

        centerPanel.add(historyScroll, BorderLayout.CENTER);

        panel.add(centerPanel, BorderLayout.CENTER);

        // Bottom info
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel intervalLabel = new JLabel("Update Interval: " + systemCheckIntervalSeconds + " seconds");
        bottomPanel.add(intervalLabel);
        panel.add(bottomPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createProcessMonitorPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top Panel - Controls
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        startProcessButton = new JButton("Start Process Monitoring");
        stopProcessButton = new JButton("Stop");
        configButton = new JButton("Settings");

        startProcessButton.setBackground(new Color(34, 139, 34));
        startProcessButton.setForeground(Color.WHITE);
        stopProcessButton.setBackground(new Color(178, 34, 34));
        stopProcessButton.setForeground(Color.WHITE);
        stopProcessButton.setEnabled(false);

        startProcessButton.addActionListener(e -> startProcessMonitoring());
        stopProcessButton.addActionListener(e -> stopProcessMonitoring());
        configButton.addActionListener(e -> showConfigDialog());

        topPanel.add(startProcessButton);
        topPanel.add(stopProcessButton);
        topPanel.add(configButton);

        processStatusLabel = new JLabel("Status: Stopped");
        processStatusLabel.setFont(new Font("Sans", Font.BOLD, 12));
        topPanel.add(Box.createHorizontalStrut(20));
        topPanel.add(processStatusLabel);

        panel.add(topPanel, BorderLayout.NORTH);

        // Center - Process Table
        String[] columns = {"Process Name", "PID", "User", "Runtime (min)", "Status"};
        processTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        processTable = new JTable(processTableModel);
        processTable.setFont(new Font("Monospace", Font.PLAIN, 12));

        // Context menu
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

        panel.add(tableScroll, BorderLayout.CENTER);

        // Bottom Panel - Info
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel infoLabel = new JLabel(
                "Max Runtime: " + maxRuntimeMinutes + " min | " +
                        "Keywords: " + keywords.size() + " | " +
                        "Check Interval: " + checkIntervalSeconds + "s"
        );
        bottomPanel.add(infoLabel);
        panel.add(bottomPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createLogsPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top controls
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton openLogButton = new JButton("Open Log File");
        JButton clearLogButton = new JButton("Clear UI Log");

        openLogButton.addActionListener(e -> openLogFile());
        clearLogButton.addActionListener(e -> logArea.setText(""));

        topPanel.add(openLogButton);
        topPanel.add(clearLogButton);
        panel.add(topPanel, BorderLayout.NORTH);

        // Log Area
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospace", Font.PLAIN, 11));
        JScrollPane logScroll = new JScrollPane(logArea);
        logScroll.setBorder(BorderFactory.createTitledBorder("Activity Log"));

        panel.add(logScroll, BorderLayout.CENTER);

        return panel;
    }

    // ===== SYSTEM MONITORING METHODS =====

    private void startSystemMonitoring() {
        if (isSystemMonitoring) return;

        isSystemMonitoring = true;
        startSystemButton.setEnabled(false);
        stopSystemButton.setEnabled(true);
        systemStatusLabel.setText("Status: Monitoring Active");
        systemStatusLabel.setForeground(new Color(34, 139, 34));

        logToUI("=== System Monitoring Started ===");
        log("System monitoring started");

        systemScheduler = Executors.newScheduledThreadPool(1);
        systemScheduler.scheduleAtFixedRate(() -> {
            try {
                updateSystemStats();
            } catch (Exception e) {
                logToUI("System monitoring error: " + e.getMessage());
            }
        }, 0, systemCheckIntervalSeconds, TimeUnit.SECONDS);
    }

    private void stopSystemMonitoring() {
        if (!isSystemMonitoring) return;

        isSystemMonitoring = false;
        if (systemScheduler != null) {
            systemScheduler.shutdown();
        }

        startSystemButton.setEnabled(true);
        stopSystemButton.setEnabled(false);
        systemStatusLabel.setText("Status: Stopped");
        systemStatusLabel.setForeground(new Color(178, 34, 34));

        logToUI("=== System Monitoring Stopped ===");
        log("System monitoring stopped");
    }

    private void updateSystemStats() {
        // Get CPU load
        double cpuLoad = osBean.getSystemCpuLoad() * 100;
        if (cpuLoad < 0) {
            // Fallback pentru unele sisteme
            cpuLoad = osBean.getProcessCpuLoad() * 100;
        }

        // Get RAM info
        long totalMemory = osBean.getTotalPhysicalMemorySize();
        long freeMemory = osBean.getFreePhysicalMemorySize();
        long usedMemory = totalMemory - freeMemory;
        double ramUsagePercent = ((double) usedMemory / totalMemory) * 100;

        // Convert to MB
        long totalMemoryMB = totalMemory / (1024 * 1024);
        long freeMemoryMB = freeMemory / (1024 * 1024);
        long usedMemoryMB = usedMemory / (1024 * 1024);

        // Update UI
        final double finalCpuLoad = cpuLoad;
        final double finalRamUsage = ramUsagePercent;

        SwingUtilities.invokeLater(() -> {
            // Update labels
            cpuLabel.setText(String.format("CPU Load: %.2f%%", finalCpuLoad));
            ramLabel.setText(String.format("RAM Usage: %.2f%%", finalRamUsage));
            totalRamLabel.setText(String.format("Total RAM: %d MB", totalMemoryMB));
            usedRamLabel.setText(String.format("Used RAM: %d MB", usedMemoryMB));
            freeRamLabel.setText(String.format("Free RAM: %d MB", freeMemoryMB));

            // Update progress bars
            cpuProgressBar.setValue((int) finalCpuLoad);
            ramProgressBar.setValue((int) finalRamUsage);

            // Set colors based on usage
            if (finalCpuLoad > 80) {
                cpuProgressBar.setForeground(Color.RED);
            } else if (finalCpuLoad > 60) {
                cpuProgressBar.setForeground(Color.ORANGE);
            } else {
                cpuProgressBar.setForeground(new Color(34, 139, 34));
            }

            if (finalRamUsage > 80) {
                ramProgressBar.setForeground(Color.RED);
            } else if (finalRamUsage > 60) {
                ramProgressBar.setForeground(Color.ORANGE);
            } else {
                ramProgressBar.setForeground(new Color(34, 139, 34));
            }

            // Add to history table
            String timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());
            systemHistoryModel.insertRow(0, new Object[]{
                    timestamp,
                    String.format("%.2f", finalCpuLoad),
                    totalMemoryMB,
                    usedMemoryMB,
                    freeMemoryMB
            });

            // Limit history rows
            while (systemHistoryModel.getRowCount() > MAX_HISTORY_ROWS) {
                systemHistoryModel.removeRow(systemHistoryModel.getRowCount() - 1);
            }
        });

        // Log to file
        String logMessage = String.format(
                "CPU: %.2f%% | RAM: %.2f%% (Used: %d MB, Free: %d MB, Total: %d MB)",
                finalCpuLoad, finalRamUsage, usedMemoryMB, freeMemoryMB, totalMemoryMB
        );
        log(logMessage);
    }

    // ===== PROCESS MONITORING METHODS =====

    private void killSelectedProcess(boolean forceKill) {
        int selectedRow = processTable.getSelectedRow();
        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(this, "Please select a process first.");
            return;
        }

        int pid = (int) processTableModel.getValueAt(selectedRow, 1);
        String processName = (String) processTableModel.getValueAt(selectedRow, 0);

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

        int pid = (int) processTableModel.getValueAt(selectedRow, 1);
        processStartTimes.remove(pid);
        warningShown.remove(pid);
        logToUI("Ignoring PID " + pid + " for this session");
    }

    private void startProcessMonitoring() {
        if (isProcessMonitoring) return;

        isProcessMonitoring = true;
        startProcessButton.setEnabled(false);
        stopProcessButton.setEnabled(true);
        processStatusLabel.setText("Status: Monitoring Active");
        processStatusLabel.setForeground(new Color(34, 139, 34));

        logToUI("=== Process Monitoring Started ===");
        log("Process monitoring started");

        processScheduler = Executors.newScheduledThreadPool(1);
        processScheduler.scheduleAtFixedRate(() -> {
            try {
                checkAndTerminateProcesses();
            } catch (Exception e) {
                logToUI("Process monitoring error: " + e.getMessage());
            }
        }, 0, checkIntervalSeconds, TimeUnit.SECONDS);
    }

    private void stopProcessMonitoring() {
        if (!isProcessMonitoring) return;

        isProcessMonitoring = false;
        if (processScheduler != null) {
            processScheduler.shutdown();
        }

        startProcessButton.setEnabled(true);
        stopProcessButton.setEnabled(false);
        processStatusLabel.setText("Status: Stopped");
        processStatusLabel.setForeground(new Color(178, 34, 34));

        logToUI("=== Process Monitoring Stopped ===");
        log("Process monitoring stopped");

        processTableModel.setRowCount(0);
        processStartTimes.clear();
        warningShown.clear();
    }

    private void checkAndTerminateProcesses() {
        try {
            List<ProcessInfo> processes = getRunningProcesses();
            long currentTime = System.currentTimeMillis();

            SwingUtilities.invokeLater(() -> processTableModel.setRowCount(0));

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
                        status = "Warning";
                        showWarningNotification(process, runtimeMinutes);
                        warningShown.put(process.pid, true);
                    } else if (runtimeMinutes >= warningMinutes) {
                        status = "Warning Sent";
                    } else {
                        status = "OK";
                    }

                    int finalRuntime = (int) runtimeMinutes;
                    String finalStatus = status;
                    SwingUtilities.invokeLater(() -> {
                        processTableModel.addRow(new Object[]{
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

                    String processName = extractProcessName(command);
                    processes.add(new ProcessInfo(processName, pid, user));
                }
            }
        }

        return processes;
    }

    private String extractProcessName(String command) {
        String[] parts = command.split("\\s+");
        String basePath = parts[0];

        int lastSlash = basePath.lastIndexOf('/');
        if (lastSlash != -1) {
            return basePath.substring(lastSlash + 1);
        }
        return basePath;
    }

    private void terminateProcess(ProcessInfo process) {
        try {
            ProcessBuilder pb = new ProcessBuilder("kill", "-15", String.valueOf(process.pid));
            Process p = pb.start();
            p.waitFor();

            Thread.sleep(2000);

            if (isProcessRunning(process.pid)) {
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
        String msg = "Warning: " + process.name + " will close in " + remaining + " minutes";
        logToUI(msg);
        log(msg);

        showNotification("Process Warning",
                process.name + " will be closed in " + remaining + " minutes!");
    }

    private void showNotification(String title, String message) {
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

    // ===== CONFIGURATION METHODS =====

    private void showConfigDialog() {
        JDialog dialog = new JDialog(this, "Process Monitor Settings", true);
        dialog.setSize(500, 450);
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

        // Process check interval
        gbc.gridx = 0; gbc.gridy = 2;
        panel.add(new JLabel("Process Check Interval (seconds):"), gbc);
        JSpinner intervalSpinner = new JSpinner(new SpinnerNumberModel(checkIntervalSeconds, 10, 300, 10));
        gbc.gridx = 1;
        panel.add(intervalSpinner, gbc);

        // System check interval
        gbc.gridx = 0; gbc.gridy = 3;
        panel.add(new JLabel("System Check Interval (seconds):"), gbc);
        JSpinner systemIntervalSpinner = new JSpinner(new SpinnerNumberModel(systemCheckIntervalSeconds, 1, 60, 1));
        gbc.gridx = 1;
        panel.add(systemIntervalSpinner, gbc);

        // Keywords
        gbc.gridx = 0; gbc.gridy = 4;
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
            systemCheckIntervalSeconds = (int) systemIntervalSpinner.getValue();

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
            writer.println("systemCheckInterval=" + systemCheckIntervalSeconds);
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
            systemCheckIntervalSeconds = Integer.parseInt(props.getProperty("systemCheckInterval", "5"));

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
            File autostartDir = new File(AUTOSTART_DIR);
            if (!autostartDir.exists()) {
                autostartDir.mkdirs();
            }

            String jarPath = new File(ProcessMonitorLinux.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI()).getPath();

            if (!jarPath.endsWith(".jar")) {
                JOptionPane.showMessageDialog(this,
                        "Please compile to JAR first:\n" +
                                "jar cfm SystemMonitor.jar manifest.txt *.class",
                        "Not a JAR", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            String desktopContent =
                    "[Desktop Entry]\n" +
                            "Type=Application\n" +
                            "Name=System Monitor\n" +
                            "Comment=Monitor system resources and processes\n" +
                            "Exec=java -jar " + jarPath + "\n" +
                            "Icon=utilities-system-monitor\n" +
                            "Terminal=false\n" +
                            "Categories=System;Monitor;\n" +
                            "X-GNOME-Autostart-enabled=true\n";

            Files.write(Paths.get(AUTOSTART_FILE), desktopContent.getBytes());
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
            ProcessBuilder pb = new ProcessBuilder("xdg-open", LOG_FILE);
            pb.start();
        } catch (Exception e) {
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
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                try {
                    UIManager.setLookAndFeel("javax.swing.plaf.nimbus.NimbusLookAndFeel");
                } catch (Exception ex) {
                    // Use default
                }
            }
            new ProcessMonitorLinux().setVisible(true);
        });
    }
}