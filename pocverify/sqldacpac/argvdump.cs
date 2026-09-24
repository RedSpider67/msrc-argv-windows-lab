using System;
class ArgvDump {
    static int Main(string[] argv) {
        Console.WriteLine("RAWCMDLINE=" + Environment.CommandLine);
        Console.WriteLine("ARGC=" + argv.Length);
        for (int i = 0; i < argv.Length; i++) Console.WriteLine("ARGV[" + i + "]=" + argv[i]);
        return 0;
    }
}
