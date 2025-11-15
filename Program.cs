using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.DirectoryServices.AccountManagement;
using Microsoft.Toolkit.Uwp.Notifications;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;
using System;

class Program
{
    static void Main(string[] args)
    {
        try
        {
            bool isAdmin = CheckAndElevateAdminStatus();
            
            if (!isAdmin)
            {
                Console.WriteLine("Failed to elevate to administrator. Exiting.");
                return;
            }

            InitializeEventLogWatcher();

            Console.WriteLine("ToastChecker is running. Monitoring for AdminPDL events...");
            Console.WriteLine("Press Ctrl+C to exit.");
            
            while (true)
            {
                Thread.Sleep(1000);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error in Main: {ex.Message}");
            SendToastNotification("ToastChecker Error", $"An error occurred: {ex.Message}");
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
                        Console.WriteLine("AdminPDL event detected. Starting folder processing loop...");
                        SendToastNotification("AdminPDL Event", "AdminPDL event detected. Processing folders...");
                        ProcessFolderBatch();
                    }
                }
            };

            Console.WriteLine("Event Log watcher initialized.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error initializing Event Log watcher: {ex.Message}");
            SendToastNotification("Event Log Error", $"Failed to initialize Event Log watcher: {ex.Message}");
        }
    }

    /// <summary>
    /// Processes exactly 3 folders from %temp% directory - deletes or moves them. /// Don't forget to get the name of the files from desktop. 
    /// </summary>
    static void ProcessFolderBatch()
    {
        try
        {
            string tempPath = Path.Combine(Path.GetTempPath());
            DirectoryInfo tempDir = new DirectoryInfo(tempPath);
            
            DirectoryInfo[] folders = tempDir.GetDirectories();
            
            if (folders.Length == 0)
            {
                Console.WriteLine("No folders found in %temp% directory.");
                SendToastNotification("Folder Processing", "No folders to process in %temp%");
                return;
            }

            int processed = 0;
            int toProcess = Math.Min(3, folders.Length);

            foreach (DirectoryInfo folder in folders.Take(toProcess))
            {
                try
                {
                    if (Directory.Exists(folder.FullName))
                    {
                        Directory.Delete(folder.FullName, recursive: true);
                        Console.WriteLine($"Deleted folder: {folder.FullName}");
                        processed++;
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    Console.WriteLine($"Permission denied for {folder.FullName}: {ex.Message}");
                    try
                    {
                        string moveDestination = Path.Combine(Path.GetTempPath(), "ToDelete", folder.Name);
                        Directory.CreateDirectory(Path.GetDirectoryName(moveDestination)!);
                        if (Directory.Exists(moveDestination))
                        {
                            Directory.Delete(moveDestination, recursive: true);
                        }
                        Directory.Move(folder.FullName, moveDestination);
                        Console.WriteLine($"Force moved folder: {folder.FullName} -> {moveDestination}");
                        processed++;
                    }
                    catch (Exception moveEx)
                    {
                        Console.WriteLine($"Failed to move folder: {moveEx.Message}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error processing folder {folder.FullName}: {ex.Message}");
                }
            }

            Console.WriteLine($"Batch processing complete. Processed {processed} folders.");
            SendToastNotification("Folder Processing Complete", $"Processed {processed} out of {toProcess} folders");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error in ProcessFolderBatch: {ex.Message}");
            SendToastNotification("Folder Processing Error", $"Error during batch processing: {ex.Message}");
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
    static readonly string LogPath = GetNoAdminLogPath();

    static string GetNoAdminLogPath()
    {
        try
        {
            string systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";
            string dir = Path.Combine(systemDrive, "Users", TargetUser, "AppData", "Local", "Temp");

            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "ToastChecker.log");
        }
        catch
        {
            try
            {
                return Path.Combine(Path.GetTempPath(), "ToastChecker.log");
            }
            catch
            {
                return "ToastChecker.log";
            }
        }
    }

    public static void Log(string message)
    {
        try
        {
            string? dir = Path.GetDirectoryName(LogPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            string line = $"{DateTime.Now:O} {message}{Environment.NewLine}";
            File.AppendAllText(LogPath, line, Encoding.UTF8);
        }
        catch { }
    }
}
