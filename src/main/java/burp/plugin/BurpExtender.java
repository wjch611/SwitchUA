package burp.plugin;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

public class BurpExtender implements BurpExtension {
    private MontoyaApi api;
    private JPanel panel;
    private JTextField uaFilePathField;
    private JToggleButton switchUAButton;
    private final List<String> userAgents = new ArrayList<>();
    private final Random random = new Random();
    private volatile boolean isSwitchUAEnabled = false;
    private DefaultTableModel tableModel;
    private final AtomicInteger requestCounter = new AtomicInteger(0);
    private static final String DEFAULT_UA_FILE_PATH = "E:\\SecTools\\ffuf\\ua.txt";

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        // Set extension name
        api.extension().setName("SwitchUA");

        // Initialize UI
        initializeUI();

        // Load default User-Agent dictionary if it exists
        File defaultUAFile = new File(DEFAULT_UA_FILE_PATH);
        if (validateFile(defaultUAFile)) {
            uaFilePathField.setText(defaultUAFile.getAbsolutePath());
            loadUserAgents(defaultUAFile);
        } else {
            api.logging().logToOutput("Default UA file not found or not readable: " + DEFAULT_UA_FILE_PATH);
        }

        // Register HTTP handler
        api.http().registerHttpHandler(new SwitchUAHttpHandler());

        // Add custom tab to Burp
        api.userInterface().registerSuiteTab("SwitchUA", panel);

        api.logging().logToOutput("SwitchUA plugin loaded successfully.");
    }

    private void initializeUI() {
        panel = new JPanel(new BorderLayout());
        JPanel topPanel = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(5, 5, 5, 5);

        // UA Dictionary File Path
        c.gridx = 0;
        c.gridy = 0;
        topPanel.add(new JLabel("UA Dictionary File:"), c);

        c.gridx = 1;
        c.weightx = 1.0;
        uaFilePathField = new JTextField(20);
        topPanel.add(uaFilePathField, c);

        c.gridx = 2;
        c.weightx = 0;
        JButton browseButton = new JButton("Browse");
        browseButton.addActionListener(e -> chooseUAFile());
        topPanel.add(browseButton, c);

        // Switch UA Toggle Button
        c.gridx = 0;
        c.gridy = 1;
        c.gridwidth = 2;
        switchUAButton = new JToggleButton("Switch UA (Disabled)", false);
        switchUAButton.addActionListener(e -> toggleSwitchUA());
        topPanel.add(switchUAButton, c);

        // Clear History Button
        c.gridx = 2;
        c.gridwidth = 1;
        JButton clearButton = new JButton("Clear History");
        clearButton.addActionListener(e -> clearHistory());
        topPanel.add(clearButton, c);

        // Add top panel to the main panel
        panel.add(topPanel, BorderLayout.NORTH);

        // Create table for modified requests
        String[] columnNames = {"#", "Method", "URL", "Modified User-Agent"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // Make table non-editable
            }
        };
        JTable table = new JTable(tableModel);
        table.setAutoCreateRowSorter(true);
        JScrollPane scrollPane = new JScrollPane(table);
        panel.add(scrollPane, BorderLayout.CENTER);
    }

    private void chooseUAFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        if (fileChooser.showOpenDialog(panel) == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            if (validateFile(selectedFile)) {
                uaFilePathField.setText(selectedFile.getAbsolutePath());
                loadUserAgents(selectedFile);
            }
        }
    }

    private boolean validateFile(File file) {
        if (!file.exists()) {
            api.logging().logToError("Selected file does not exist: " + file.getAbsolutePath());
            JOptionPane.showMessageDialog(panel, "File does not exist: " + file.getAbsolutePath(), "Error", JOptionPane.ERROR_MESSAGE);
            return false;
        }
        if (!file.canRead()) {
            api.logging().logToError("Selected file is not readable: " + file.getAbsolutePath());
            JOptionPane.showMessageDialog(panel, "File is not readable: " + file.getAbsolutePath(), "Error", JOptionPane.ERROR_MESSAGE);
            return false;
        }
        return true;
    }

    private void loadUserAgents(File file) {
        synchronized (userAgents) {
            userAgents.clear();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty()) {
                        userAgents.add(line);
                    }
                }
                api.logging().logToOutput("Loaded " + userAgents.size() + " User-Agents from " + file.getAbsolutePath());
            } catch (IOException e) {
                api.logging().logToError("Error loading UA file: " + e.getMessage());
                JOptionPane.showMessageDialog(panel, "Failed to load UA file: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void toggleSwitchUA() {
        isSwitchUAEnabled = switchUAButton.isSelected();
        switchUAButton.setText(isSwitchUAEnabled ? "Switch UA (Enabled)" : "Switch UA (Disabled)");
        api.logging().logToOutput("Switch UA " + (isSwitchUAEnabled ? "enabled" : "disabled"));
        if (isSwitchUAEnabled && userAgents.isEmpty()) {
            api.logging().logToError("No User-Agents loaded. Please select a UA dictionary file.");
            JOptionPane.showMessageDialog(panel, "No User-Agents loaded. Please select a UA dictionary file.", "Warning", JOptionPane.WARNING_MESSAGE);
            switchUAButton.setSelected(false);
            isSwitchUAEnabled = false;
            switchUAButton.setText("Switch UA (Disabled)");
        }
    }

    private void clearHistory() {
        tableModel.setRowCount(0); // Clear all rows in the table
        requestCounter.set(0); // Reset the request counter
        api.logging().logToOutput("SwitchUA history cleared.");
    }

    private void addRequestToTable(String method, String url, String modifiedUserAgent) {
        int requestNumber = requestCounter.incrementAndGet();
        tableModel.addRow(new Object[]{requestNumber, method, url, modifiedUserAgent});
    }

    private class SwitchUAHttpHandler implements HttpHandler {
        @Override
        public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
            if (!isSwitchUAEnabled || userAgents.isEmpty()) {
                api.logging().logToOutput("SwitchUA skipped: Enabled=" + isSwitchUAEnabled + ", User-Agents loaded=" + userAgents.size());
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            // Log original User-Agent
            String originalUA = requestToBeSent.headers().stream()
                    .filter(header -> header.name().equalsIgnoreCase("User-Agent"))
                    .map(HttpHeader::value)
                    .findFirst()
                    .orElse("No User-Agent");
            api.logging().logToOutput("Original User-Agent: " + originalUA);

            // Process request asynchronously
            return CompletableFuture.supplyAsync(() -> {
                try {
                    // Select random User-Agent
                    String newUserAgent;
                    synchronized (userAgents) {
                        newUserAgent = userAgents.get(random.nextInt(userAgents.size()));
                    }

                    // Remove existing User-Agent header
                    var updatedRequest = requestToBeSent.withRemovedHeader("User-Agent");

                    // Add new User-Agent header
                    updatedRequest = updatedRequest.withAddedHeader(HttpHeader.httpHeader("User-Agent", newUserAgent));

                    // Log the modified User-Agent
                    api.logging().logToOutput("Modified User-Agent to: " + newUserAgent);

                    // Add to UI table
                    SwingUtilities.invokeLater(() -> {
                        addRequestToTable(requestToBeSent.method(), requestToBeSent.url(), newUserAgent);
                    });

                    return RequestToBeSentAction.continueWith(updatedRequest);
                } catch (Exception e) {
                    api.logging().logToError("Error processing request: " + e.getMessage());
                    return RequestToBeSentAction.continueWith(requestToBeSent);
                }
            }).join(); // Block until async processing completes
        }

        @Override
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
    }
}