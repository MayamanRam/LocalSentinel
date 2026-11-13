using LocalSentinel.Data;
using LocalSentinel.Models;
using LocalSentinel.Services;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;

namespace LocalSentinel
{
    public partial class MainWindow : Window
    {
        private readonly DispatcherTimer processTimer = new();
        private readonly DispatcherTimer networkTimer = new();
        private readonly DispatcherTimer usbTimer = new();

        private HashSet<int> knownProcessIds = new();
        private HashSet<string> knownNetworkConnections = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, UsbEventRecord> connectedUsbDevices = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<FileSystemWatcher> fileWatchers = new();

        // Data Collections
        private readonly ObservableCollection<AlertRecord> alerts = new();
        private readonly ObservableCollection<ProcessEventRecord> processEvents = new();
        private readonly ObservableCollection<FileEventRecord> fileEvents = new();
        private readonly ObservableCollection<NetworkEventRecord> networkEvents = new();
        private readonly ObservableCollection<UsbEventRecord> usbEvents = new();

        // Filterable Collection Views
        private ICollectionView? alertsView;
        private ICollectionView? processEventsView;
        private ICollectionView? fileEventsView;
        private ICollectionView? networkEventsView;
        private ICollectionView? usbEventsView;

        // Core Services
        private readonly DatabaseService databaseService = new();
        private readonly ThreatDetectionEngine threatEngine = new();
        private readonly ProcessInspectionService processInspector = new();

        private readonly Dictionary<string, DateTime> recentDisplayedFileEvents = new(StringComparer.OrdinalIgnoreCase);
        private readonly TimeSpan fileDisplayDeduplicationWindow = TimeSpan.FromMilliseconds(800);

        private int eventCount;
        private bool isMonitoringActive = true;
        private bool isProcessTickRunning = false;
        private bool isNetworkTickRunning = false;
        private bool isUsbTickRunning = false;

        public MainWindow()
        {
            InitializeComponent();

            ConfigureViews();

            databaseService.InitializeDatabase();

            LoadStoredTelemetry();

            HostInfoText.Text = Environment.MachineName;
            DbPathText.Text = databaseService.DatabasePath;

            StartProcessMonitoring();
            StartFileMonitoring();
            StartNetworkMonitoring();
            StartUsbMonitoring();

            UpdateMetricsDisplay();
            UpdateOverallMonitoringStatus();
        }

        private void ConfigureViews()
        {
            // Alerts View
            alertsView = CollectionViewSource.GetDefaultView(alerts);
            alertsView.Filter = FilterAlerts;
            AlertsTable.ItemsSource = alertsView;

            // Process View
            processEventsView = CollectionViewSource.GetDefaultView(processEvents);
            processEventsView.Filter = FilterProcessEvents;
            ActivityTable.ItemsSource = processEventsView;

            // File View
            fileEventsView = CollectionViewSource.GetDefaultView(fileEvents);
            fileEventsView.Filter = FilterFileEvents;
            FileActivityTable.ItemsSource = fileEventsView;

            // Network View
            networkEventsView = CollectionViewSource.GetDefaultView(networkEvents);
            networkEventsView.Filter = FilterNetworkEvents;
            NetworkActivityTable.ItemsSource = networkEventsView;

            // USB View
            usbEventsView = CollectionViewSource.GetDefaultView(usbEvents);
            usbEventsView.Filter = FilterUsbEvents;
            UsbActivityTable.ItemsSource = usbEventsView;
        }

        private void LoadStoredTelemetry()
        {
            try
            {
                foreach (var alert in databaseService.GetRecentAlerts(100))
                {
                    alerts.Add(alert);
                }

                foreach (var record in databaseService.GetRecentProcessEvents(100))
                {
                    processEvents.Add(record);
                }

                foreach (var record in databaseService.GetRecentFileEvents(150))
                {
                    fileEvents.Add(record);
                }

                foreach (var record in databaseService.GetRecentNetworkEvents(100))
                {
                    networkEvents.Add(record);
                }

                foreach (var record in databaseService.GetRecentUsbEvents(50))
                {
                    usbEvents.Add(record);
                }

                UpdateAlertBadge();
                UpdateEmptyStates();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to load stored telemetry: {ex.Message}");
            }
        }

        // ================= Monitoring Control =================

        private void ToggleMonitoring_Click(object sender, RoutedEventArgs e)
        {
            if (isMonitoringActive)
            {
                // Pause Monitoring
                processTimer.Stop();
                networkTimer.Stop();
                usbTimer.Stop();
                foreach (var w in fileWatchers)
                {
                    w.EnableRaisingEvents = false;
                }

                isMonitoringActive = false;
                ToggleMonitoringBtn.Content = "▶ Resume";
                MonitoringStatusText.Text = "Paused";
                MonitoringStatusText.Foreground = new SolidColorBrush(Color.FromRgb(245, 158, 11));
                HeaderStatusText.Text = "⏸ PAUSED";
                OverallStatusBorder.Background = new SolidColorBrush(Color.FromRgb(120, 53, 15));
                OverallStatusBorder.BorderBrush = new SolidColorBrush(Color.FromRgb(217, 119, 6));
                HeaderStatusText.Foreground = new SolidColorBrush(Color.FromRgb(251, 191, 36));
            }
            else
            {
                // Resume Monitoring
                processTimer.Start();
                networkTimer.Start();
                usbTimer.Start();
                foreach (var w in fileWatchers)
                {
                    w.EnableRaisingEvents = true;
                }

                isMonitoringActive = true;
                ToggleMonitoringBtn.Content = "⏸ Pause";
                MonitoringStatusText.Text = "Active";
                MonitoringStatusText.Foreground = new SolidColorBrush(Color.FromRgb(56, 189, 248));
                HeaderStatusText.Text = "● ACTIVE MONITORING";
                OverallStatusBorder.Background = new SolidColorBrush(Color.FromRgb(6, 78, 59));
                OverallStatusBorder.BorderBrush = new SolidColorBrush(Color.FromRgb(5, 150, 105));
                HeaderStatusText.Foreground = new SolidColorBrush(Color.FromRgb(52, 211, 153));
            }
        }

        private void ClearLogs_Click(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show(
                "Are you sure you want to clear session views and wipe SQLite database telemetry?",
                "Confirm Forensics Clear",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning
            );

            if (result == MessageBoxResult.Yes)
            {
                alerts.Clear();
                processEvents.Clear();
                fileEvents.Clear();
                networkEvents.Clear();
                usbEvents.Clear();
                eventCount = 0;
                EventCountText.Text = "0";

                Task.Run(() =>
                {
                    databaseService.ClearAllEvents();
                }).ContinueWith(_ =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        UpdateAlertBadge();
                        UpdateMetricsDisplay();
                        UpdateEmptyStates();
                    });
                });
            }
        }

        // ================= Process Monitoring =================

        private void StartProcessMonitoring()
        {
            try
            {
                knownProcessIds = Process.GetProcesses().Select(p => p.Id).ToHashSet();
            }
            catch
            {
                knownProcessIds = new HashSet<int>();
            }

            processTimer.Interval = TimeSpan.FromSeconds(1);
            processTimer.Tick += ProcessTimer_Tick;
            processTimer.Start();
        }

        private async void ProcessTimer_Tick(object? sender, EventArgs e)
        {
            if (isProcessTickRunning || !isMonitoringActive)
            {
                return;
            }

            isProcessTickRunning = true;

            try
            {
                Process[] processes;
                try
                {
                    processes = Process.GetProcesses();
                }
                catch
                {
                    return;
                }

                var currentPids = processes.Select(p => p.Id).ToHashSet();
                var newProcesses = processes.Where(p => !knownProcessIds.Contains(p.Id)).ToList();
                knownProcessIds = currentPids;

                ProcessCountMetricText.Text = currentPids.Count.ToString();

                if (newProcesses.Count > 0)
                {
                    // Inspect off the UI thread
                    var discoveredRecords = await Task.Run(() =>
                    {
                        var list = new List<(ProcessEventRecord Record, List<AlertRecord> Alerts)>();
                        foreach (var proc in newProcesses)
                        {
                            try
                            {
                                var rec = processInspector.CreateProcessRecord(proc);
                                var procAlerts = threatEngine.EvaluateProcessEvent(rec);
                                list.Add((rec, procAlerts));
                            }
                            catch
                            {
                                // Process exited during inspection
                            }
                            finally
                            {
                                proc.Dispose();
                            }
                        }
                        return list;
                    });

                    // Add to UI and DB
                    foreach (var (record, procAlerts) in discoveredRecords)
                    {
                        processEvents.Insert(0, record);
                        if (processEvents.Count > 250)
                        {
                            processEvents.RemoveAt(processEvents.Count - 1);
                        }

                        _ = Task.Run(() => databaseService.AddProcessEvent(record));
                        IncrementEventCount();

                        foreach (var alert in procAlerts)
                        {
                            DispatchAlert(alert);
                        }
                    }

                    UpdateEmptyStates();
                }
                else
                {
                    foreach (var p in processes)
                    {
                        p.Dispose();
                    }
                }
            }
            finally
            {
                isProcessTickRunning = false;
            }
        }

        // ================= File Monitoring =================

        private void StartFileMonitoring()
        {
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string[] foldersToWatch =
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(userProfile, "Downloads")
            };

            var uniqueFolders = foldersToWatch
                .Where(f => !string.IsNullOrWhiteSpace(f))
                .Distinct(StringComparer.OrdinalIgnoreCase);

            foreach (string folder in uniqueFolders)
            {
                if (!Directory.Exists(folder))
                {
                    continue;
                }

                try
                {
                    var watcher = new FileSystemWatcher(folder)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName |
                                       NotifyFilters.DirectoryName |
                                       NotifyFilters.LastWrite |
                                       NotifyFilters.CreationTime |
                                       NotifyFilters.Size,
                        InternalBufferSize = 32768,
                        EnableRaisingEvents = true
                    };

                    watcher.Created += (s, e) => HandleFileChange("Created", e.Name ?? Path.GetFileName(e.FullPath), e.FullPath, null);
                    watcher.Changed += (s, e) => HandleFileChange("Modified", e.Name ?? Path.GetFileName(e.FullPath), e.FullPath, null);
                    watcher.Deleted += (s, e) => HandleFileChange("Deleted", e.Name ?? Path.GetFileName(e.FullPath), e.FullPath, null);
                    watcher.Renamed += (s, e) => HandleFileChange("Renamed", e.Name ?? Path.GetFileName(e.FullPath), e.FullPath, e.OldFullPath);

                    fileWatchers.Add(watcher);
                }
                catch
                {
                    // Continue if directory access restricted
                }
            }

            WatchersCountText.Text = $"{fileWatchers.Count} Directories Watched";
            StorageMetricText.Text = $"{fileWatchers.Count} Dirs | {connectedUsbDevices.Count} USB";
        }

        private void HandleFileChange(string eventType, string fileName, string fullPath, string? oldPath)
        {
            if (!isMonitoringActive)
            {
                return;
            }

            DateTime eventTime = DateTime.Now;
            var record = new FileEventRecord
            {
                Timestamp = eventTime,
                EventType = eventType,
                FileName = fileName,
                FullPath = fullPath,
                OldPath = oldPath
            };

            // Evaluate against threat detection rules
            var fileAlerts = threatEngine.EvaluateFileEvent(record);

            Task.Run(() => databaseService.AddFileEvent(record));

            Dispatcher.BeginInvoke(() =>
            {
                IncrementEventCount();

                foreach (var a in fileAlerts)
                {
                    DispatchAlert(a);
                }

                if (eventType.Equals("Modified", StringComparison.OrdinalIgnoreCase))
                {
                    string key = $"{eventType}|{fullPath}";
                    if (recentDisplayedFileEvents.TryGetValue(key, out DateTime previousTime))
                    {
                        if (eventTime - previousTime < fileDisplayDeduplicationWindow)
                        {
                            return;
                        }
                    }
                    recentDisplayedFileEvents[key] = eventTime;
                }

                fileEvents.Insert(0, record);
                if (fileEvents.Count > 250)
                {
                    fileEvents.RemoveAt(fileEvents.Count - 1);
                }

                UpdateEmptyStates();
            });
        }

        // ================= Network Monitoring =================

        private void StartNetworkMonitoring()
        {
            try
            {
                var current = NetworkConnectionService.GetActiveTcpConnections();
                knownNetworkConnections = current.Select(NetworkConnectionService.GetConnectionKey)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);
                NetworkCountMetricText.Text = current.Count.ToString();
            }
            catch
            {
                knownNetworkConnections = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }

            networkTimer.Interval = TimeSpan.FromSeconds(2);
            networkTimer.Tick += NetworkTimer_Tick;
            networkTimer.Start();
        }

        private async void NetworkTimer_Tick(object? sender, EventArgs e)
        {
            if (isNetworkTickRunning || !isMonitoringActive)
            {
                return;
            }

            isNetworkTickRunning = true;

            try
            {
                var currentConnections = await Task.Run(() => NetworkConnectionService.GetActiveTcpConnections());
                NetworkCountMetricText.Text = currentConnections.Count.ToString();

                var currentKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var newConnections = new List<(NetworkEventRecord Record, List<AlertRecord> Alerts)>();

                foreach (var record in currentConnections)
                {
                    string key = NetworkConnectionService.GetConnectionKey(record);
                    currentKeys.Add(key);

                    if (!knownNetworkConnections.Contains(key))
                    {
                        record.Timestamp = DateTime.Now;
                        var netAlerts = threatEngine.EvaluateNetworkEvent(record);
                        newConnections.Add((record, netAlerts));
                    }
                }

                knownNetworkConnections = currentKeys;

                foreach (var (record, netAlerts) in newConnections)
                {
                    networkEvents.Insert(0, record);
                    if (networkEvents.Count > 250)
                    {
                        networkEvents.RemoveAt(networkEvents.Count - 1);
                    }

                    _ = Task.Run(() => databaseService.AddNetworkEvent(record));
                    IncrementEventCount();

                    foreach (var alert in netAlerts)
                    {
                        DispatchAlert(alert);
                    }
                }

                UpdateEmptyStates();
            }
            finally
            {
                isNetworkTickRunning = false;
            }
        }

        // ================= USB Monitoring =================

        private void StartUsbMonitoring()
        {
            try
            {
                connectedUsbDevices.Clear();
                foreach (var d in UsbDeviceService.GetConnectedUsbStorageDevices())
                {
                    connectedUsbDevices[UsbDeviceService.GetDeviceKey(d)] = d;
                }
                StorageMetricText.Text = $"{fileWatchers.Count} Dirs | {connectedUsbDevices.Count} USB";
            }
            catch
            {
                // Fallback gracefully
            }

            usbTimer.Interval = TimeSpan.FromSeconds(3);
            usbTimer.Tick += UsbTimer_Tick;
            usbTimer.Start();
        }

        private async void UsbTimer_Tick(object? sender, EventArgs e)
        {
            if (isUsbTickRunning || !isMonitoringActive)
            {
                return;
            }

            isUsbTickRunning = true;

            try
            {
                var devices = await Task.Run(() => UsbDeviceService.GetConnectedUsbStorageDevices());
                var currentDevices = new Dictionary<string, UsbEventRecord>(StringComparer.OrdinalIgnoreCase);

                foreach (var d in devices)
                {
                    currentDevices[UsbDeviceService.GetDeviceKey(d)] = d;
                }

                // Discovered Connected Devices
                foreach (var pair in currentDevices)
                {
                    if (!connectedUsbDevices.ContainsKey(pair.Key))
                    {
                        AddUsbEvent("Connected", pair.Value);
                    }
                }

                // Discovered Removed Devices
                foreach (var pair in connectedUsbDevices)
                {
                    if (!currentDevices.ContainsKey(pair.Key))
                    {
                        AddUsbEvent("Removed", pair.Value);
                    }
                }

                connectedUsbDevices.Clear();
                foreach (var pair in currentDevices)
                {
                    connectedUsbDevices[pair.Key] = pair.Value;
                }

                StorageMetricText.Text = $"{fileWatchers.Count} Dirs | {connectedUsbDevices.Count} USB";
            }
            finally
            {
                isUsbTickRunning = false;
            }
        }

        private void AddUsbEvent(string eventType, UsbEventRecord device)
        {
            var record = new UsbEventRecord
            {
                Timestamp = DateTime.Now,
                EventType = eventType,
                DeviceName = device.DeviceName,
                SerialNumber = device.SerialNumber,
                PnpDeviceId = device.PnpDeviceId
            };

            var usbAlerts = threatEngine.EvaluateUsbEvent(record);

            usbEvents.Insert(0, record);
            if (usbEvents.Count > 100)
            {
                usbEvents.RemoveAt(usbEvents.Count - 1);
            }

            Task.Run(() => databaseService.AddUsbEvent(record));
            IncrementEventCount();

            foreach (var a in usbAlerts)
            {
                DispatchAlert(a);
            }

            UpdateEmptyStates();
        }

        // ================= Alert Management =================

        private void DispatchAlert(AlertRecord alert)
        {
            alerts.Insert(0, alert);
            if (alerts.Count > 200)
            {
                alerts.RemoveAt(alerts.Count - 1);
            }

            Task.Run(() => databaseService.AddAlert(alert));

            UpdateAlertBadge();
            UpdateEmptyStates();
        }

        private void UpdateAlertBadge()
        {
            int count = alerts.Count;
            SecurityAlertCountText.Text = count.ToString();
            AlertTabBadgeCount.Text = count.ToString();
            AlertTabBadge.Visibility = count > 0 ? Visibility.Visible : Visibility.Collapsed;

            int criticalHighCount = alerts.Count(a => a.Severity == AlertSeverity.Critical || a.Severity == AlertSeverity.High);
            if (criticalHighCount > 0)
            {
                AlertsSubtext.Text = $"{criticalHighCount} Critical/High";
                AlertsSubtext.Foreground = new SolidColorBrush(Color.FromRgb(239, 68, 68));
            }
            else
            {
                AlertsSubtext.Text = "MITRE ATT&CK Detections";
                AlertsSubtext.Foreground = new SolidColorBrush(Color.FromRgb(148, 163, 184));
            }
        }

        // ================= Filters & Search =================

        private bool FilterAlerts(object item)
        {
            if (item is not AlertRecord alert)
            {
                return false;
            }

            // Severity filter
            if (AlertSeverityFilterCombo.SelectedIndex > 0)
            {
                string selectedSeverity = ((ComboBoxItem)AlertSeverityFilterCombo.SelectedItem).Content.ToString() ?? "";
                if (!alert.SeverityText.Equals(selectedSeverity, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }
            }

            // Text search
            string query = AlertSearchBox.Text.Trim();
            if (string.IsNullOrWhiteSpace(query))
            {
                return true;
            }

            return alert.RuleName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                   alert.MitreTechniqueId.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                   alert.EntityIdentifier.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                   alert.Description.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                   alert.Source.Contains(query, StringComparison.OrdinalIgnoreCase);
        }

        private void AlertSeverityFilter_Changed(object sender, SelectionChangedEventArgs e)
        {
            alertsView?.Refresh();
            UpdateEmptyStates();
        }

        private void AlertSearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            alertsView?.Refresh();
            UpdateEmptyStates();
        }

        private void ClearAlertSearch_Click(object sender, RoutedEventArgs e)
        {
            AlertSearchBox.Clear();
            AlertSeverityFilterCombo.SelectedIndex = 0;
            AlertSearchBox.Focus();
        }

        private bool FilterProcessEvents(object item)
        {
            if (item is not ProcessEventRecord record)
            {
                return false;
            }

            string searchText = SearchBox.Text.Trim();
            if (string.IsNullOrWhiteSpace(searchText))
            {
                return true;
            }

            return record.ProcessName.Contains(searchText, StringComparison.OrdinalIgnoreCase) ||
                   record.ProcessId.ToString().Contains(searchText, StringComparison.OrdinalIgnoreCase) ||
                   (record.ParentProcessName?.Contains(searchText, StringComparison.OrdinalIgnoreCase) ?? false) ||
                   (record.ExecutablePath?.Contains(searchText, StringComparison.OrdinalIgnoreCase) ?? false) ||
                   (record.CommandLine?.Contains(searchText, StringComparison.OrdinalIgnoreCase) ?? false) ||
                   (record.Sha256?.Contains(searchText, StringComparison.OrdinalIgnoreCase) ?? false) ||
                   record.SignatureStatus.Contains(searchText, StringComparison.OrdinalIgnoreCase) ||
                   (record.SignerName?.Contains(searchText, StringComparison.OrdinalIgnoreCase) ?? false);
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            processEventsView?.Refresh();
            UpdateEmptyStates();
        }

        private void ClearSearch_Click(object sender, RoutedEventArgs e)
        {
            SearchBox.Clear();
            SearchBox.Focus();
        }

        private bool FilterFileEvents(object item)
        {
            if (item is not FileEventRecord record)
            {
                return false;
            }

            string query = FileSearchBox.Text.Trim();
            if (string.IsNullOrWhiteSpace(query))
            {
                return true;
            }

            return record.FileName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                   record.FullPath.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                   record.EventType.Contains(query, StringComparison.OrdinalIgnoreCase);
        }

        private void FileSearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            fileEventsView?.Refresh();
            UpdateEmptyStates();
        }

        private void ClearFileSearch_Click(object sender, RoutedEventArgs e)
        {
            FileSearchBox.Clear();
            FileSearchBox.Focus();
        }

        private bool FilterNetworkEvents(object item)
        {
            if (item is not NetworkEventRecord record)
            {
                return false;
            }

            string query = NetworkSearchBox.Text.Trim();
            if (string.IsNullOrWhiteSpace(query))
            {
                return true;
            }

            return (record.ProcessName?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false) ||
                   record.RemoteAddress.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                   record.RemotePort.ToString().Contains(query, StringComparison.OrdinalIgnoreCase) ||
                   record.LocalAddress.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                   record.ConnectionState.Contains(query, StringComparison.OrdinalIgnoreCase);
        }

        private void NetworkSearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            networkEventsView?.Refresh();
            UpdateEmptyStates();
        }

        private void ClearNetworkSearch_Click(object sender, RoutedEventArgs e)
        {
            NetworkSearchBox.Clear();
            NetworkSearchBox.Focus();
        }

        private bool FilterUsbEvents(object item)
        {
            if (item is not UsbEventRecord record)
            {
                return false;
            }

            string query = UsbSearchBox.Text.Trim();
            if (string.IsNullOrWhiteSpace(query))
            {
                return true;
            }

            return record.DeviceName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                   (record.SerialNumber?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false) ||
                   (record.PnpDeviceId?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false) ||
                   record.EventType.Contains(query, StringComparison.OrdinalIgnoreCase);
        }

        private void UsbSearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            usbEventsView?.Refresh();
            UpdateEmptyStates();
        }

        private void ClearUsbSearch_Click(object sender, RoutedEventArgs e)
        {
            UsbSearchBox.Clear();
            UsbSearchBox.Focus();
        }

        // ================= Forensics Export =================

        private void ExportReport_Click(object sender, RoutedEventArgs e)
        {
            ExportJsonSnapshot_Click(sender, e);
        }

        private void ExportJsonSnapshot_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog
            {
                Filter = "JSON Forensic Snapshot (*.json)|*.json",
                FileName = $"LocalSentinel_Forensics_{DateTime.Now:yyyyMMdd_HHmmss}.json"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var report = new ForensicExportReport
                    {
                        TotalAlerts = alerts.Count,
                        TotalProcesses = processEvents.Count,
                        TotalFileEvents = fileEvents.Count,
                        TotalNetworkEvents = networkEvents.Count,
                        TotalUsbEvents = usbEvents.Count,
                        Alerts = alerts.ToList(),
                        Processes = processEvents.ToList(),
                        FileEvents = fileEvents.ToList(),
                        NetworkEvents = networkEvents.ToList(),
                        UsbEvents = usbEvents.ToList()
                    };

                    string sha256 = ForensicExportService.ExportToJson(report, dialog.FileName);

                    MessageBox.Show(
                        $"Forensic snapshot exported successfully!\n\nFile: {dialog.FileName}\nSHA-256 Hash: {sha256}",
                        "Forensics Export Verified",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information
                    );
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Export failed: {ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ExportAlertsCsv_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog
            {
                Filter = "CSV File (*.csv)|*.csv",
                FileName = $"LocalSentinel_Alerts_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    string sha256 = ForensicExportService.ExportAlertsToCsv(alerts, dialog.FileName);
                    MessageBox.Show(
                        $"Alerts CSV exported successfully!\n\nFile: {dialog.FileName}\nSHA-256: {sha256}",
                        "CSV Export Verified",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information
                    );
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Export failed: {ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ExportProcessesCsv_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new SaveFileDialog
            {
                Filter = "CSV File (*.csv)|*.csv",
                FileName = $"LocalSentinel_Processes_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    string sha256 = ForensicExportService.ExportProcessesToCsv(processEvents, dialog.FileName);
                    MessageBox.Show(
                        $"Process telemetry CSV exported successfully!\n\nFile: {dialog.FileName}\nSHA-256: {sha256}",
                        "CSV Export Verified",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information
                    );
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Export failed: {ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        // ================= Metrics & Empty States =================

        private void IncrementEventCount()
        {
            eventCount++;
            EventCountText.Text = eventCount.ToString();
        }

        private void UpdateMetricsDisplay()
        {
            Task.Run(() => databaseService.GetMetrics()).ContinueWith(t =>
            {
                if (t.IsCompletedSuccessfully)
                {
                    var m = t.Result;
                    Dispatcher.Invoke(() =>
                    {
                        DbSizeText.Text = $"{m.DatabaseSizeBytes / 1024.0:F1} KB";
                        long totalRows = m.ProcessCount + m.FileCount + m.NetworkCount + m.UsbCount + m.AlertCount;
                        DbTotalRowsText.Text = $"{totalRows:N0} records (Proc: {m.ProcessCount}, Alerts: {m.AlertCount}, Files: {m.FileCount}, Net: {m.NetworkCount}, USB: {m.UsbCount})";
                    });
                }
            });
        }

        private void UpdateOverallMonitoringStatus()
        {
            if (isMonitoringActive)
            {
                MonitoringStatusText.Text = "Active";
                HeaderStatusText.Text = "● ACTIVE MONITORING";
            }
        }

        private void UpdateEmptyStates()
        {
            EmptyAlertsText.Visibility = (alertsView?.IsEmpty ?? true) ? Visibility.Visible : Visibility.Collapsed;
            EmptyActivityText.Visibility = (processEventsView?.IsEmpty ?? true) ? Visibility.Visible : Visibility.Collapsed;
            EmptyFileActivityText.Visibility = (fileEventsView?.IsEmpty ?? true) ? Visibility.Visible : Visibility.Collapsed;
            EmptyNetworkActivityText.Visibility = (networkEventsView?.IsEmpty ?? true) ? Visibility.Visible : Visibility.Collapsed;
            EmptyUsbActivityText.Visibility = (usbEventsView?.IsEmpty ?? true) ? Visibility.Visible : Visibility.Collapsed;
        }

        // ================= Cleanup on Close =================

        protected override void OnClosed(EventArgs e)
        {
            processTimer.Stop();
            networkTimer.Stop();
            usbTimer.Stop();

            processTimer.Tick -= ProcessTimer_Tick;
            networkTimer.Tick -= NetworkTimer_Tick;
            usbTimer.Tick -= UsbTimer_Tick;

            foreach (var watcher in fileWatchers)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch
                {
                    // Ignore
                }
            }
            fileWatchers.Clear();

            base.OnClosed(e);
        }
    }
}
