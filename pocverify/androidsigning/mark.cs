using System;
using System.IO;
class Mark {
    static int Main(string[] argv) {
        string id = Environment.GetEnvironmentVariable("POC_MARKER_ID");
        if (String.IsNullOrEmpty(id)) id = "nomarkerid";
        string f = "PWNED-" + id + ".txt";
        File.WriteAllText(f, "marker written by mark.exe at " + DateTime.UtcNow.ToString("o") + Environment.NewLine +
                             "cwd=" + Directory.GetCurrentDirectory() + Environment.NewLine +
                             "cmdline=" + Environment.CommandLine + Environment.NewLine);
        Console.WriteLine("MARK.EXE RAN, wrote " + Path.GetFullPath(f));
        return 0;
    }
}
