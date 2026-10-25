using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Windows.Forms;

// Installer for the RTD129x flash tool.
//
// Two modes, same binary:
//   * app.zip sits next to the exe  -> use it (portable/CI packaging where files
//     are not embedded);
//   * otherwise                     -> extract the copy embedded as the
//     "app.zip" manifest resource (the single-file Setup exe built by
//     packaging/build-installer.ps1).
//
// Everything installs per-user, no admin:
//   %LOCALAPPDATA%\Programs\RTD-Flasher
// plus Desktop and Start-Menu shortcuts. The USB driver is an optional,
// admin-only step exposed as its own Start-Menu shortcut.
class Installer
{
    static string TargetDir()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            @"Programs\RTD-Flasher");
    }

    [STAThread]
    static int Main(string[] args)
    {
        try
        {
            string here = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string zip = Path.Combine(here, "app.zip");
            bool cleanup = false;

            if (!File.Exists(zip))
            {
                Stream res = Assembly.GetExecutingAssembly().GetManifestResourceStream("app.zip");
                if (res == null)
                    throw new Exception("安装包缺少 app.zip（既不在 exe 旁边，也没有内嵌）。");
                zip = Path.Combine(Path.GetTempPath(), "rtd-flasher-" + Guid.NewGuid().ToString("N") + ".zip");
                using (FileStream fs = File.Create(zip))
                {
                    res.CopyTo(fs);
                }
                cleanup = true;
            }

            string target = TargetDir();

            // Stop an old instance so its files are not locked.
            foreach (Process p in Process.GetProcessesByName("rtd-gui"))
            {
                try { p.Kill(); } catch { }
            }
            System.Threading.Thread.Sleep(300);

            if (Directory.Exists(target))
                Directory.Delete(target, true);
            Directory.CreateDirectory(target);
            ZipFile.ExtractToDirectory(zip, target);
            if (cleanup)
            {
                try { File.Delete(zip); } catch { }
            }

            string exe = Path.Combine(target, "rtd-gui.exe");
            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            string sm = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                @"Microsoft\Windows\Start Menu\Programs\RTD-Flasher");
            Directory.CreateDirectory(sm);

            CreateShortcut(Path.Combine(desktop, "RTD129x 线刷工具.lnk"), exe, target, "");
            CreateShortcut(Path.Combine(sm, "RTD129x 线刷工具.lnk"), exe, target, "");

            string drv = Path.Combine(target, "install-driver.ps1");
            if (File.Exists(drv))
                CreateShortcut(Path.Combine(sm, "安装 USB 驱动（管理员）.lnk"), "powershell.exe", target,
                    "-NoProfile -ExecutionPolicy Bypass -File \"" + drv + "\"");

            string un = Path.Combine(target, "uninstall.ps1");
            if (File.Exists(un))
                CreateShortcut(Path.Combine(sm, "卸载 RTD-Flasher.lnk"), "powershell.exe", target,
                    "-NoProfile -ExecutionPolicy Bypass -File \"" + un + "\"");

            if (Environment.GetEnvironmentVariable("RTD_SILENT") != "1")
            {
                string ver = Assembly.GetExecutingAssembly().GetName().Version.ToString();
                MessageBox.Show(
                    "RTD129x 线刷工具 " + ver + " 已安装到：\r\n" + target + "\r\n\r\n" +
                    "桌面和开始菜单已创建快捷方式。\r\n\r\n" +
                    "提示：本程序不需要任何运行库（只用 Windows 自带 DLL）。\r\n" +
                    "首次在另一台电脑使用前，如果设备管理器里看不到\r\n" +
                    "“Realtek generic USB Device”，请先运行开始菜单里的\r\n" +
                    "「安装 USB 驱动（管理员）」。",
                    "安装完成", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            return 0;
        }
        catch (Exception e)
        {
            MessageBox.Show(e.ToString(), "安装失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }

    static void CreateShortcut(string lnkPath, string targetPath, string workDir, string arguments)
    {
        Type shellType = Type.GetTypeFromProgID("WScript.Shell");
        object shell = Activator.CreateInstance(shellType);
        object shortcut = shellType.InvokeMember(
            "CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { lnkPath });
        Type sc = shortcut.GetType();
        sc.InvokeMember("TargetPath", BindingFlags.SetProperty, null, shortcut, new object[] { targetPath });
        sc.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, shortcut, new object[] { workDir });
        sc.InvokeMember("IconLocation", BindingFlags.SetProperty, null, shortcut, new object[] { targetPath + ",0" });
        if (arguments != null && arguments.Length > 0)
            sc.InvokeMember("Arguments", BindingFlags.SetProperty, null, shortcut, new object[] { arguments });
        sc.InvokeMember("Save", BindingFlags.InvokeMethod, null, shortcut, null);
    }
}
