using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.DirectoryServices.AccountManagement;
using Microsoft.Toolkit.Uwp.Notifications;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;
using System;

/// <summary>
/// Need to modify : Shortcuts don't work
/// Need to modify : Check EventLog watcher for AdminPDL events
/// Need to modify : Check Desktop watcher
class Program
{
    static FileSystemWatcher? desktopWatcher = null;
    static FileSystemWatcher? appFoldersWatcherPF = null;
    static FileSystemWatcher? appFoldersWatcherPFX86 = null;
    static object lockObject = new object();
    static DateTime lastProcessTime = DateTime.MinValue;
    static void Main(string[] args)
    {
        try
        {
            string debugPath = @"C:\Users\NoAdmin\AppData\Local\Temp\ToastChecker_DEBUG.txt";
            Console.WriteLine("=== ToastChecker STARTUP ===");
            File.WriteAllText(debugPath, $"Started at {DateTime.Now:O}, User={Environment.UserName}, PID={Process.GetCurrentProcess().Id}{Environment.NewLine}");
            
            DebugLog.Info("Starting ToastChecker...");
            Logger.Log($"Started ToastChecker as {Environment.UserName}, PID {Process.GetCurrentProcess().Id}");
            bool isAdmin = CheckAndElevateAdminStatus();
            
            Console.WriteLine($"[DEBUG] CheckAndElevateAdminStatus returned: {isAdmin}");
            File.AppendAllText(debugPath, $"Admin check: {isAdmin}{Environment.NewLine}");
            
            if (!isAdmin)
            {
                Console.WriteLine("Failed to elevate to administrator. Exiting.");
                File.AppendAllText(debugPath, $"Admin check failed, exiting.{Environment.NewLine}");
                return;
            }

            // Perform initial cleanup
            DebugLog.Info("Performing initial cleanup...");
            Console.WriteLine("[DEBUG] About to call ProcessSpecificTargets()");
            File.AppendAllText(debugPath, $"Calling ProcessSpecificTargets...{Environment.NewLine}");
            ProcessSpecificTargets();
            Console.WriteLine("[DEBUG] ProcessSpecificTargets() completed");
            File.AppendAllText(debugPath, $"ProcessSpecificTargets completed.{Environment.NewLine}");

            // Initialize Desktop watcher to monitor for shortcuts/apps reappearing
            Console.WriteLine("[DEBUG] About to InitializeDesktopWatcher()");
            File.AppendAllText(debugPath, $"Calling InitializeDesktopWatcher...{Environment.NewLine}");
            InitializeDesktopWatcher();
            Console.WriteLine("[DEBUG] InitializeDesktopWatcher() completed");

            // Initialize App Folders watcher for LibreOffice and MPC-HC64
            Console.WriteLine("[DEBUG] About to InitializeAppFoldersWatcher()");
            File.AppendAllText(debugPath, $"Calling InitializeAppFoldersWatcher...{Environment.NewLine}");
            InitializeAppFoldersWatcher();
            Console.WriteLine("[DEBUG] InitializeAppFoldersWatcher() completed");

            // Initialize periodic scan timer (every 10 minutes)
            Console.WriteLine("[DEBUG] About to InitializePeriodicScanTimer()");
            File.AppendAllText(debugPath, $"Calling InitializePeriodicScanTimer...{Environment.NewLine}");
            InitializePeriodicScanTimer();
            Console.WriteLine("[DEBUG] InitializePeriodicScanTimer() completed");

            // Initialize Event Log watcher for AdminPDL events
            Console.WriteLine("[DEBUG] About to InitializeEventLogWatcher()");
            File.AppendAllText(debugPath, $"Calling InitializeEventLogWatcher...{Environment.NewLine}");
            InitializeEventLogWatcher();
            Console.WriteLine("[DEBUG] InitializeEventLogWatcher() completed");

            Console.WriteLine("ToastChecker is running. Monitoring for shortcuts and applications...");
            Console.WriteLine("Press Ctrl+C to exit.");
            File.AppendAllText(debugPath, $"Ready. Entering main loop.{Environment.NewLine}");
            
            while (true)
            {
                Thread.Sleep(1000);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error in Main: {ex.Message}");
            Console.WriteLine($"[ERROR DETAILS] {ex}");
            File.WriteAllText(@"C:\Users\NoAdmin\AppData\Local\Temp\ToastChecker_ERROR.txt", $"Exception: {ex}{Environment.NewLine}");
            SendToastNotification("ToastChecker Error", $"An error occurred: {ex.Message}");
        }
    }

    static void DisableWatchers()
    {
        try
        {
            if (desktopWatcher != null) desktopWatcher.EnableRaisingEvents = false;
            if (appFoldersWatcherPF != null) appFoldersWatcherPF.EnableRaisingEvents = false;
            if (appFoldersWatcherPFX86 != null) appFoldersWatcherPFX86.EnableRaisingEvents = false;
            Console.WriteLine("[Watchers] Disabled during processing");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Watchers] Error disabling: {ex.Message}");
        }
    }

    static void EnableWatchers()
    {
        try
        {
            if (desktopWatcher != null) desktopWatcher.EnableRaisingEvents = true;
            if (appFoldersWatcherPF != null) appFoldersWatcherPF.EnableRaisingEvents = true;
            if (appFoldersWatcherPFX86 != null) appFoldersWatcherPFX86.EnableRaisingEvents = true;
            Console.WriteLine("[Watchers] Re-enabled after processing");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Watchers] Error re-enabling: {ex.Message}");
        }
    }

    /// <summary>
    /// Checks if current user is administrator. If not, attempts elevation.
    /// </summary>
    static bool CheckAndElevateAdminStatus()
    {
        try
        {
            string currentUser = "NoAdmin";

            Console.Write("The Environment User is - " + currentUser);
            
            using (var ctx = new PrincipalContext(ContextType.Machine))
            using (var user = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, currentUser))
            {
                if (user != null)
                {
                    using (var adminGroup = GroupPrincipal.FindByIdentity(ctx, IdentityType.Name, "Administrateurs"))
                    {
                        if (adminGroup != null && user.IsMemberOf(adminGroup))
                        {
                            SendToastNotification("Administrator Status", $"{currentUser} is Administrator");
                            Console.WriteLine($"User {currentUser} is already Administrator.");
                            return true;
                        }
                    }
                }
            }

            Console.WriteLine($"User {currentUser} is not Administrator. Attempting elevation...");
            ElevateToAdministrator(currentUser);
            
            Thread.Sleep(2000);
            
            using (var ctx = new PrincipalContext(ContextType.Machine))
            using (var user = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, currentUser))
            {
                if (user != null)
                {
                    using (var adminGroup = GroupPrincipal.FindByIdentity(ctx, IdentityType.Name, "Administrateurs"))
                    {
                        if (adminGroup != null && user.IsMemberOf(adminGroup))
                        {
                            DebugLog.Success("Elevated to Admin");
                            SendToastNotification("Administrator Status", $"{currentUser} elevated to Administrator");
                            Console.WriteLine($"User {currentUser} successfully elevated to Administrator.");
                            return true;
                        }
                    }
                }
            }

            Console.WriteLine("Elevation verification failed.");
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error checking admin status: {ex.Message}");
            SendToastNotification("Admin Check Error", $"Failed to check admin status: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Elevates the specified user to Administrator using CMD net user command.
    /// </summary>
    static void ElevateToAdministrator(string userName)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c net localgroup Administrateurs {userName} /add ",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using (Process process = Process.Start(psi)!)
            {
                process.WaitForExit();
                
                if (process.ExitCode == 0)
                {
                    Console.WriteLine($"Successfully added {userName} to Administrators group.");
                }
                else
                {
                    string error = process.StandardError.ReadToEnd();
                    Console.WriteLine($"Failed to elevate {userName}: {error}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error during elevation: {ex.Message}");
        }
    }

    /// <summary>
    /// Initializes FileSystemWatcher on NoAdmin Desktop to monitor for shortcuts and apps.
    /// </summary>
    static void InitializeDesktopWatcher()
    {
        try
        {
            string noAdminDesktop = Path.Combine(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:", "Users", "NoAdmin", "Desktop");
            string publicDesktop = Path.Combine(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:", "Users", "Public", "Desktop");

            if (!Directory.Exists(noAdminDesktop))
            {
                DebugLog.Error($"Desktop path not found: {noAdminDesktop}");
                return;
            }

            FileSystemWatcher watcher = new FileSystemWatcher(noAdminDesktop)
            {
                Filter = "*.lnk",
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime
            };

            FileSystemWatcher watcherPublic = new FileSystemWatcher(publicDesktop)
            {
                Filter = "*.lnk",
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime
            };

            watcher.Created += (sender, e) =>
            {
                DebugLog.Info($"Shortcut detected: {Path.GetFileName(e.Name)}");
                Thread.Sleep(500); // Wait for file to be fully written
                
                // Add 2 minute delay before processing shortcuts to let installation start
                Console.WriteLine("[DesktopWatcher] Shortcut detected, waiting 2 minutes before processing...");
                Thread.Sleep(120000); // 2 minutes
                
                ProcessSpecificTargets();
            };

            watcherPublic.Created += (sender, e) =>
            {
                DebugLog.Info($"Shortcut detected: {Path.GetFileName(e.Name)}");
                Thread.Sleep(500); // Wait for file to be fully written
                
                // Add 2 minute delay before processing shortcuts to let installation start
                Console.WriteLine("[DesktopWatcher] Shortcut detected, waiting 2 minutes before processing...");
                Thread.Sleep(120000); // 2 minutes
                
                ProcessSpecificTargets();
            };

            watcher.EnableRaisingEvents = true;
            watcherPublic.EnableRaisingEvents = true;
            desktopWatcher = watcher;
            DebugLog.Success("Desktop watcher initialized");
            Logger.Log($"Desktop watcher initialized for {noAdminDesktop}");
            Console.WriteLine($"Watching {noAdminDesktop} for shortcuts...");
        }
        catch (Exception ex)
        {
            DebugLog.Error($"Failed to initialize Desktop watcher: {ex.Message}");
            Console.WriteLine($"Error initializing Desktop watcher: {ex.Message}");
        }
    }

    /// <summary>
    /// Initializes FileSystemWatcher on app installation folders to monitor for LibreOffice and MPC-HC64.
    /// </summary>
    static void InitializeAppFoldersWatcher()
    {
        try
        {
            string systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
            string programFiles = Path.Combine(systemDrive, "Program Files");
            string programFilesX86 = Path.Combine(systemDrive, "Program Files (x86)");

            // Watch Program Files for LibreOffice
            if (Directory.Exists(programFiles))
            {
                FileSystemWatcher watcherPF = new FileSystemWatcher(programFiles)
                {
                    Filter = "*",
                    NotifyFilter = NotifyFilters.DirectoryName | NotifyFilters.CreationTime
                };

                watcherPF.Created += (sender, e) =>
                {
                    string name = Path.GetFileName(e.Name) ?? string.Empty;
                    if (!string.IsNullOrEmpty(name) && name.IndexOf("LibreOffice", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        DebugLog.Info($"App folder detected: {name}");
                        
                        // Add 2 minute delay before processing apps to let installation fully start
                        Console.WriteLine($"[AppFoldersWatcher] LibreOffice detected, waiting 2 minutes before processing...");
                        Thread.Sleep(120000); // 2 minutes
                        
                        ProcessSpecificTargets();
                    }
                };

                watcherPF.EnableRaisingEvents = true;
                appFoldersWatcherPF = watcherPF;
                DebugLog.Success("Program Files (LibreOffice) watcher initialized");
                Logger.Log($"Program Files watcher initialized for LibreOffice at {programFiles}");
                Console.WriteLine($"Watching {programFiles} for LibreOffice...");
            }

            // Watch Program Files (x86) for MPC-HC64
            if (Directory.Exists(programFilesX86))
            {
                FileSystemWatcher watcherPFX86 = new FileSystemWatcher(programFilesX86)
                {
                    Filter = "*",
                    NotifyFilter = NotifyFilters.DirectoryName | NotifyFilters.CreationTime
                };

                watcherPFX86.Created += (sender, e) =>
                {
                    string name = Path.GetFileName(e.Name) ?? string.Empty;
                    if (!string.IsNullOrEmpty(name) && (name.IndexOf("K-Lite", StringComparison.OrdinalIgnoreCase) >= 0 || name.IndexOf("MPC-HC", StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        DebugLog.Info($"App folder detected: {name}");
                        
                        // Add 2 minute delay before processing apps to let installation fully start
                        Console.WriteLine($"[AppFoldersWatcher] K-Lite/MPC-HC detected, waiting 2 minutes before processing...");
                        Thread.Sleep(120000); // 2 minutes
                        
                        ProcessSpecificTargets();
                    }
                };

                watcherPFX86.EnableRaisingEvents = true;
                appFoldersWatcherPFX86 = watcherPFX86;
                DebugLog.Success("Program Files (x86) (K-Lite) watcher initialized");
                Logger.Log($"Program Files (x86) watcher initialized for K-Lite at {programFilesX86}");
                Console.WriteLine($"Watching {programFilesX86} for K-Lite Codec Pack...");
            }
        }
        catch (Exception ex)
        {
            DebugLog.Error($"Failed to initialize app folders watcher: {ex.Message}");
            Console.WriteLine($"Error initializing app folders watcher: {ex.Message}");
        }
    }

    /// <summary>
    /// Initializes a timer that periodically scans for target apps every 10 minutes.
    /// This catches reinstallations that occur in existing folders (not detected by FileSystemWatcher).
    /// 10 minutes allows enough time for installations to complete.
    /// </summary>
    static void InitializePeriodicScanTimer()
    {
        try
        {
            // 10 minutes = 600,000 milliseconds (increased from 5 to give installations time to complete)
            int intervalMs = 10 * 60 * 1000;
            
            Timer scanTimer = new Timer(state =>
            {
                Console.WriteLine("[PeriodicScan] Timer triggered - scanning for targets...");
                try
                {
                    ProcessSpecificTargets();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[PeriodicScan] Error during scan: {ex.Message}");
                    Logger.Log($"PeriodicScan error: {ex.Message}");
                }
            }, null, intervalMs, intervalMs);

            DebugLog.Success("Periodic scan timer initialized (10 min interval)");
            Logger.Log("Periodic scan timer initialized (10 minutes)");
            Console.WriteLine("Periodic scan enabled: checking every 10 minutes for apps (waits for installers to finish)...");
        }
        catch (Exception ex)
        {
            DebugLog.Error($"Failed to initialize periodic scan timer: {ex.Message}");
            Console.WriteLine($"Error initializing periodic scan timer: {ex.Message}");
            Logger.Log($"Failed to initialize periodic scan timer: {ex.Message}");
        }
    }

    /// <summary>
    /// Initializes Windows Event Log watcher to monitor for AdminPDL events.
    /// </summary>
    static void InitializeEventLogWatcher()
    {
        try
        {
            EventLogWatcher watcher = new EventLogWatcher(new EventLogQuery("System", PathType.LogName, "*[System[EventID=1001]]")) ///Uh? Why 1001?... and why system log?
            {
                Enabled = true
            };

            watcher.EventRecordWritten += (sender, e) =>
            {
                if (e.EventRecord != null)
                {
                    string eventSource = e.EventRecord.ProviderName;
                    
                    if (eventSource != null && eventSource.Contains("AdminPDL", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine("AdminPDL event detected. Starting cleanup operations...");
                        SendToastNotification("AdminPDL Event", "AdminPDL event detected. Processing targets...");
                        ProcessSpecificTargets();
                    }
                }
            };

            Console.WriteLine("Event Log watcher initialized.");
            Logger.Log("Event Log watcher initialized");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error initializing Event Log watcher: {ex.Message}");
            SendToastNotification("Event Log Error", $"Failed to initialize Event Log watcher: {ex.Message}");
        }
    }

    /// <summary>
    /// Checks if installer processes are still running (msiexec, setup, install, etc.)
    /// </summary>
    static bool IsInstallerRunning()
    {
        try
        {
            string[] installerProcesses = new[] { "msiexec", "setup", "install", "uninst", "nsis", "wix" };
            var runningProcesses = Process.GetProcesses();
            
            foreach (var proc in runningProcesses)
            {
                try
                {
                    string procName = proc.ProcessName.ToLower();
                    foreach (var installer in installerProcesses)
                    {
                        if (procName.Contains(installer))
                        {
                            Console.WriteLine($"[IsInstallerRunning] Found installer process: {procName}");
                            return true;
                        }
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[IsInstallerRunning] Error checking processes: {ex.Message}");
        }
        return false;
    }

    /// <summary>
    /// Processes specific targets: moves desktop shortcuts to Temp and deletes app folders.
    /// Waits for installers to finish and adds delay before deletion.
    /// Uses lock to prevent concurrent processing and disables watchers during processing.
    /// </summary>
    static void ProcessSpecificTargets()
    {
        // Prevent concurrent processing and too-frequent calls
        lock (lockObject)
        
        {
            // Skip if called within last 5 minutes
            if ((DateTime.Now - lastProcessTime).TotalSeconds < 300)
            {
                Console.WriteLine("[ProcessSpecificTargets] Skipped - processed too recently");
                return;
            }
            lastProcessTime = DateTime.Now;
        }

        DisableWatchers();
        try
        {
            string debugPath = @"C:\Users\NoAdmin\AppData\Local\Temp\ToastChecker_DEBUG.txt";
            Console.WriteLine("[ProcessSpecificTargets] Starting...");
            File.AppendAllText(debugPath, $"{DateTime.Now:O} ProcessSpecificTargets() start{Environment.NewLine}");
            
            Logger.Log("ProcessSpecificTargets started");
            int processed = 0;
            string noAdminDesktop = Path.Combine(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:", "Users", "NoAdmin", "Desktop");
            string noAdminTemp = Path.Combine(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:", "Users", "NoAdmin", "AppData", "Local", "Temp");

            Console.WriteLine($"[ProcessSpecificTargets] Desktop: {noAdminDesktop}");
            Console.WriteLine($"[ProcessSpecificTargets] Temp: {noAdminTemp}");
            File.AppendAllText(debugPath, $"Desktop: {noAdminDesktop}{Environment.NewLine}");
            File.AppendAllText(debugPath, $"Temp: {noAdminTemp}{Environment.NewLine}");

            // Wait for installers to finish before proceeding
            Console.WriteLine("[ProcessSpecificTargets] Checking for running installers...");
            int maxWaitIterations = 24; // 24 * 5 sec = 2 minutes max wait
            int waitIteration = 0;
            while (IsInstallerRunning() && waitIteration < maxWaitIterations)
            {
                Console.WriteLine($"[ProcessSpecificTargets] Installer still running... waiting (attempt {waitIteration + 1}/{maxWaitIterations})");
                File.AppendAllText(debugPath, $"Waiting for installer... attempt {waitIteration + 1}{Environment.NewLine}");
                Thread.Sleep(5000); // Wait 5 seconds between checks
                waitIteration++;
            }
            
            if (IsInstallerRunning())
            {
                Console.WriteLine("[ProcessSpecificTargets] Installer still running after 2 minutes, proceeding anyway...");
                File.AppendAllText(debugPath, $"Timeout waiting for installer, proceeding anyway{Environment.NewLine}");
            }
            else if (waitIteration > 0)
            {
                Console.WriteLine($"[ProcessSpecificTargets] Installer finished. Waiting additional 30 seconds for file operations...");
                File.AppendAllText(debugPath, $"Installer finished, waiting 30 sec...{Environment.NewLine}");
                Thread.Sleep(30000); // Extra 30 seconds after installer finishes
            }

            // List of shortcuts to move from Desktop to Temp
            // Portail d'entreprise - Centre de logiciel.lnk is deleted
            // Centre Logiciel, Pays de la Loire - le media orientation.lnk, NosEmplois.lnk, LibreOffice 25.8, Media Player Classic is not delete
            string[] shortcutsToMove = new[]
            {
                "Centre logiciels.lnk",
                "Portail d'entreprise - Centre de logiciel.lnk",
                "Pays de la Loire - le media orientation.url",
                "NosEmplois.url",
                "LibreOffice 25.8.lnk",
                "Media Player Classic.lnk"
            };

            // Move shortcuts from Desktop to Temp
            Console.WriteLine($"[ProcessSpecificTargets] Checking {shortcutsToMove.Length} shortcuts...");
            File.AppendAllText(debugPath, $"Checking {shortcutsToMove.Length} shortcuts{Environment.NewLine}");
            
            foreach (string shortcut in shortcutsToMove)
            {
                try
                {
                    string sourcePath = Path.Combine(noAdminDesktop, shortcut);
                    string destPath = Path.Combine(noAdminTemp, shortcut);
                    string LibreOfficeShortcutTest = Path.Combine("C:\\Users\\Public\\Desktop", "LibreOffice 25.8.lnk");
                    string LibreOfficeShortcutAdmin = Path.Combine("C:\\Users\\NoAdmin\\Desktop", "LibreOffice 25.8.lnk");

                    Console.WriteLine($"[ProcessSpecificTargets] Checking: {sourcePath}");
                    File.AppendAllText(debugPath, $"Checking: {shortcut}... ");

                    try
                    {
                        Console.WriteLine(LibreOfficeShortcutAdmin);
                        Console.WriteLine(LibreOfficeShortcutTest);
                        File.Delete(LibreOfficeShortcutTest);
                        File.Delete(LibreOfficeShortcutAdmin);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[ProcessSpecificTargets] Error deleting test shortcut: {ex.Message}");
                    }                    


                    if (File.Exists(sourcePath))
                    {
                        Console.WriteLine($"[ProcessSpecificTargets] FOUND: {shortcut}");
                        File.AppendAllText(debugPath, $"FOUND!");
                        
                        // If destination already exists, delete it first
                        if (File.Exists(destPath))
                        {
                            File.Delete(destPath);
                        }

                        try
                        {
                            Console.WriteLine(LibreOfficeShortcutAdmin);
                            Console.WriteLine(LibreOfficeShortcutTest);
                            File.Delete(LibreOfficeShortcutTest);
                            File.Delete(LibreOfficeShortcutAdmin);

                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[ProcessSpecificTargets] Error deleting test shortcut: {ex.Message}");
                        }

                        File.Move(sourcePath, destPath);
                        DebugLog.Success($"Moved shortcut: {shortcut}");
                        Logger.Log($"Moved shortcut: {sourcePath} -> {destPath}");
                        Console.WriteLine($"Moved shortcut: {shortcut}");
                        File.AppendAllText(debugPath, $" OK{Environment.NewLine}");
                        processed++;
                    }
                    else
                    {
                        Console.WriteLine($"[ProcessSpecificTargets] NOT FOUND: {sourcePath}");
                        File.AppendAllText(debugPath, $"not found{Environment.NewLine}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to move shortcut {shortcut}: {ex.Message}");
                    File.AppendAllText(debugPath, $"ERROR: {ex.Message}{Environment.NewLine}");
                    Logger.Log($"Failed to move shortcut {shortcut}: {ex.Message}");
                }
            }

            // Match app folders by substring, not exact path, to handle different installer folder names
            string systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
            string[] appFolderSubstrings = new[] { "LibreOffice", "MPC-HC64", "K-Lite Codec Pack" };
            string[] rootsToSearch = new[] { Path.Combine(systemDrive, "Program Files"), Path.Combine(systemDrive, "Program Files (x86)") };

            foreach (string root in rootsToSearch)
            {
                try
                {
                    Console.WriteLine($"[ProcessSpecificTargets] Scanning: {root}");
                    File.AppendAllText(debugPath, $"Scanning: {root}{Environment.NewLine}");
                    
                    if (!Directory.Exists(root))
                    {
                        Console.WriteLine($"[ProcessSpecificTargets] Path does not exist: {root}");
                        File.AppendAllText(debugPath, $"Path does not exist{Environment.NewLine}");
                        continue;
                    }

                    var dirs = Directory.GetDirectories(root);
                    Console.WriteLine($"[ProcessSpecificTargets] Found {dirs.Length} directories in {root}");
                    File.AppendAllText(debugPath, $"Found {dirs.Length} dirs{Environment.NewLine}");
                    
                    foreach (var dir in dirs)
                    {
                        string dirName = Path.GetFileName(dir) ?? dir;
                        
                        foreach (var substring in appFolderSubstrings)
                        {
                            if (dirName.IndexOf(substring, StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                Console.WriteLine($"[ProcessSpecificTargets] TARGET FOUND: {dirName}");
                                File.AppendAllText(debugPath, $"TARGET: {dirName}{Environment.NewLine}");
                                
                                try
                                {
                                    Directory.Delete(dir, recursive: true);
                                    DebugLog.Success($"Deleted: {dirName}");
                                    Logger.Log($"Deleted application folder: {dir}");
                                    Console.WriteLine($"Deleted application folder: {dir}");
                                    File.AppendAllText(debugPath, $"Deleted OK{Environment.NewLine}");
                                    processed++;
                                }
                                catch (UnauthorizedAccessException ex)
                                {
                                    Console.WriteLine($"Permission denied for {dir}: {ex.Message}");
                                    File.AppendAllText(debugPath, $"Permission denied, moving...{Environment.NewLine}");
                                    Logger.Log($"Permission denied for {dir}: {ex.Message}");
                                    // Try to move to ToDelete folder as fallback
                                    try
                                    {
                                        string moveDestinationDir = Path.Combine(noAdminTemp, "ToDelete", dirName);
                                        Directory.CreateDirectory(Path.GetDirectoryName(moveDestinationDir)!);
                                        if (Directory.Exists(moveDestinationDir))
                                        {
                                            Directory.Delete(moveDestinationDir, recursive: true);
                                        }
                                        Directory.Move(dir, moveDestinationDir);
                                        Console.WriteLine($"Force moved app folder: {dir} -> {moveDestinationDir}");
                                        File.AppendAllText(debugPath, $"Moved to ToDelete OK{Environment.NewLine}");
                                        Logger.Log($"Force moved app folder: {dir} -> {moveDestinationDir}");
                                        processed++;
                                    }
                                    catch (Exception moveEx)
                                    {
                                        Console.WriteLine($"Failed to move app folder: {moveEx.Message}");
                                        File.AppendAllText(debugPath, $"Move failed: {moveEx.Message}{Environment.NewLine}");
                                        Logger.Log($"Failed to move app folder: {moveEx.Message}");
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"Error deleting app folder {dir}: {ex.Message}");
                                    File.AppendAllText(debugPath, $"Delete error: {ex.Message}{Environment.NewLine}");
                                    Logger.Log($"Error deleting app folder {dir}: {ex.Message}");
                                }
                                break; // Found match for this dir, move to next dir
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error scanning {root}: {ex.Message}");
                    File.AppendAllText(debugPath, $"Scan error: {ex.Message}{Environment.NewLine}");
                }
            }

            Console.WriteLine($"Target processing complete. Processed {processed} items.");
            File.AppendAllText(debugPath, $"ProcessSpecificTargets complete: {processed} items{Environment.NewLine}");
            SendToastNotification("Cleanup Complete", $"Processed {processed} shortcuts and applications");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error in ProcessSpecificTargets: {ex.Message}");
            File.AppendAllText(@"C:\Users\NoAdmin\AppData\Local\Temp\ToastChecker_DEBUG.txt", $"Exception in ProcessSpecificTargets: {ex}{Environment.NewLine}");
            SendToastNotification("Cleanup Error", $"Error during target processing: {ex.Message}");
        }
        finally
        {
            EnableWatchers();
        }
    }

    /// <summary>
    /// Sends a Windows Toast notification to the user using RunAs.
    /// Executes PowerShell in the context of the current user to display toasts.
    /// </summary>

    static void SendToastNotification(string title, string message)
    {
        try
        {
            // Escape special characters for PowerShell
            string escapedTitle = title.Replace("\"", "`\"").Replace("$", "`$");
            string escapedMessage = message.Replace("\"", "`\"").Replace("$", "`$");

            // PowerShell command to show Windows Toast notification using native approach
            string psCommand = $@"
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null

$bodyText = ""{escapedTitle}`n{escapedMessage}""

$ToastText01 = [Windows.UI.Notifications.ToastTemplateType]::ToastText01
$TemplateContent = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($ToastText01)
$TemplateContent.SelectSingleNode('//text[@id=""1""]').InnerText = $bodyText

$AppId = '{{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}}\WindowsPowerShell\v1.0\powershell.exe'

# Création de la notification (obligatoire)
$toast = [Windows.UI.Notifications.ToastNotification]::new($TemplateContent)

# Affichage de la notification
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId).Show($toast)
";


            byte[] commandBytes = System.Text.Encoding.Unicode.GetBytes(psCommand);
            string encodedCommand = Convert.ToBase64String(commandBytes);

            try
            {
                uint sessionId = SessionProcessLauncher.WTSGetActiveConsoleSessionId();
                string args = $"-NoProfile -EncodedCommand {encodedCommand}";
                bool started = SessionProcessLauncher.StartProcessInSession(sessionId, "powershell.exe", args);
                if (!started)
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = $"-NoProfile -EncodedCommand {encodedCommand}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };

                    using (Process process = Process.Start(psi)!)
                    {
                        if (!process.WaitForExit(5000))
                        {
                            Logger.Log("Fallback PowerShell did not exit within timeout");
                        }
                        string outp = process.StandardOutput.ReadToEnd();
                        string err = process.StandardError.ReadToEnd();
                        if (!string.IsNullOrEmpty(outp)) Logger.Log("Fallback stdout: " + outp.Trim());
                        if (!string.IsNullOrEmpty(err)) Logger.Log("Fallback stderr: " + err.Trim());
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Session launch failed, falling back: {ex.Message}");
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -EncodedCommand {encodedCommand}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                using (Process process = Process.Start(psi)!)
                {
                    process.WaitForExit(5000);
                }
            }

            Console.WriteLine($"[Toast] {title}: {message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error sending toast notification: {ex.Message}");
        }
    }
}

static class SessionProcessLauncher
{
    [DllImport("kernel32.dll")]
    public static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        int ImpersonationLevel,
        int TokenType,
        out IntPtr phNewToken);

    [DllImport("userenv.dll", SetLastError = true)]
    static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    [DllImport("userenv.dll", SetLastError = true)]
    static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string? lpApplicationName,
        string? lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    const uint TOKEN_ALL_ACCESS = 0xF01FF;
    const int SecurityImpersonation = 2;
    const int TokenPrimary = 1;
    const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    const uint CREATE_NO_WINDOW = 0x08000000;

    public static bool StartProcessInSession(uint sessionId, string appPath, string arguments, string? workingDirectory = null)
    {
        IntPtr userToken = IntPtr.Zero;
        IntPtr primaryToken = IntPtr.Zero;
        IntPtr envBlock = IntPtr.Zero;
            try
            {
                if (!WTSQueryUserToken(sessionId, out userToken))
                {
                    Logger.Log($"WTSQueryUserToken failed for session {sessionId}: {Marshal.GetLastWin32Error()}");
                    return false;
                }

            bool dupOk = DuplicateTokenEx(
                userToken,
                TOKEN_ALL_ACCESS,
                IntPtr.Zero,
                SecurityImpersonation,
                TokenPrimary,
                out primaryToken);
            if (!dupOk)
            {
                Logger.Log($"DuplicateTokenEx failed: {Marshal.GetLastWin32Error()}");
                return false;
            }

            if (!CreateEnvironmentBlock(out envBlock, primaryToken, false))
            {
                Logger.Log($"CreateEnvironmentBlock failed: {Marshal.GetLastWin32Error()}, continuing without environment block");
                envBlock = IntPtr.Zero; // not fatal
            }

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.lpDesktop = "winsta0\\default";

            PROCESS_INFORMATION pi;
            // To avoid ERROR_INVALID_NAME (123) from CreateProcessAsUser, pass the
            // full command line (including the quoted executable path) as
            // lpCommandLine and pass NULL for lpApplicationName. This is a common
            // pattern accepted by CreateProcess* APIs and avoids ambiguous name
            // parsing during process creation.
            string argsPart = arguments ?? string.Empty;
            string fullCmdLine = $"\"{appPath}\" {argsPart}".Trim();
            uint creationFlags = CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW;

            // lpCurrentDirectory may be null; pass null to the native call by
            // converting C# null to IntPtr.Zero via an overload expectation (P/Invoke
            // accepts null for string parameters). Here we pass null directly.
            bool ok = CreateProcessAsUser(
                primaryToken,
                (string?)null,      // lpApplicationName: pass NULL and put exe in cmd line
                fullCmdLine,        // lpCommandLine: full command line (quoted exe + args)
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                creationFlags,
                envBlock,
                (string?)null,      // lpCurrentDirectory: null
                ref si,
                out pi);

            if (!ok)
            {
                Logger.Log($"CreateProcessAsUser failed (session {sessionId}): {Marshal.GetLastWin32Error()}");
                return false;
            }

            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);

            return true;
        }
        finally
        {
            if (envBlock != IntPtr.Zero) DestroyEnvironmentBlock(envBlock);
            if (primaryToken != IntPtr.Zero) CloseHandle(primaryToken);
            if (userToken != IntPtr.Zero) CloseHandle(userToken);
        }
    }
}

static class Logger
{
    // Target user whose Temp folder should receive the log file when the process
    // runs as SYSTEM. Adjust this username if needed.
    static readonly string TargetUser = "NoAdmin";
    // Candidate log locations (ordered). We'll try each until one succeeds.
    static IEnumerable<string> GetCandidateLogPaths()
    {
        var list = new List<string>();
        string systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";

        // 1) NoAdmin Desktop
        list.Add(Path.Combine(systemDrive, "Users", TargetUser, "Desktop", "ToastChecker.log"));

        // 2) NoAdmin Temp
        list.Add(Path.Combine(systemDrive, "Users", TargetUser, "AppData", "Local", "Temp", "ToastChecker.log"));

        // 3) Current user's TEMP
        try { list.Add(Path.Combine(Path.GetTempPath(), "ToastChecker.log")); } catch { }

        // 4) Application folder (where exe runs)
        try { list.Add(Path.Combine(AppContext.BaseDirectory ?? ".", "ToastChecker.log")); } catch { }

        // 5) Common AppData
        try { list.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ToastChecker.log")); } catch { }

        // 6) Fallback relative
        list.Add("ToastChecker.log");

        return list;
    }

    // Try writing the log message to the first writable candidate path. Returns the path used or null.
    public static string? Log(string message)
    {
        string line = $"{DateTime.Now:O} {message}{Environment.NewLine}";
        Exception? lastEx = null;

        // Force write to NoAdmin Temp ONLY (skip Desktop and other paths)
        string noAdminTempPath = Path.Combine(
            Environment.GetEnvironmentVariable("SystemDrive") ?? "C:",
            "Users", TargetUser, "AppData", "Local", "Temp", "ToastChecker.log"
        );

        try
        {
            string? dir = Path.GetDirectoryName(noAdminTempPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            File.AppendAllText(noAdminTempPath, line, Encoding.UTF8);
            // Also write a small console note to help debugging interactively
            try { Console.WriteLine($"[Logger] Wrote to {noAdminTempPath}"); } catch { }
            return noAdminTempPath;
        }
        catch (Exception ex)
        {
            lastEx = ex;
        }

        // If NoAdmin Temp failed, try other paths as fallback
        foreach (var path in GetCandidateLogPaths())
        {
            try
            {
                string? dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                File.AppendAllText(path, line, Encoding.UTF8);
                try { Console.WriteLine($"[Logger] FALLBACK wrote to {path}"); } catch { }
                return path;
            }
            catch (Exception ex)
            {
                lastEx = ex;
            }
        }

        // If none succeeded, write to console error and return null
        try
        {
            Console.Error.WriteLine($"[Logger] Failed to write log. Last error: {lastEx?.Message}");
        }
        catch { }

        return null;
    }
}

static class DebugLog
{
    public static void Success(string message)
    {
#if DEBUG
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"✓ {message}");
        Console.ResetColor();
#endif
    }

    public static void Error(string message)
    {
#if DEBUG
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"✗ {message}");
        Console.ResetColor();
#endif
    }

    public static void Info(string message)
    {
#if DEBUG
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"ℹ {message}");
        Console.ResetColor();
#endif
    }
}
