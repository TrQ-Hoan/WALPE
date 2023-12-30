using Mono.Options;
using System;
using System.ComponentModel.Design;
using System.Linq;

namespace SharpWALPE
{
    internal class Program
    {
        public static bool wrapTickets = false;
        public static bool verbosity = false;
        public static bool showHelp = false;
        public static string appName = "";
        static int Main(string[] args)
        {
            appName = System.Reflection.Assembly.GetExecutingAssembly().GetName().Name;
            int err = 0;
            CommandSet commands = new CommandSet("SharpWALPE")
            {
                "",
                string.Format("Usage: {0} COMMAND [OPTIONS]", appName),
                "",
                " Abuses Windows Authentication",
                "",
                "Commands:",
                new Commands.Rbcd(),
                new Commands.Tgtdeleg(),
                new Command ("krbscm", string.Format("Abuse kerberos ticket create service usage scm.\n- Usage: {0} krbscm <service command>", appName)) {
                    Run = cmd => KrbSCM.Execute(string.Join(" ", cmd)),
                },
                /* Standalone now not working - current it usage for create service in rbcd without command */
                new Command ("system", "Abuse kerberos ticket create process with session-id.") {
                    Run = sid => KrbSCM.RunSystemProcess(Convert.ToInt32(sid.ElementAt(0))),
                },
                "",
                "Global options:",
                { "v|verbose", "Verbose output", v => verbosity = v != null },
                { "w|wrap", "Wrapline tickets", w => wrapTickets = w != null },
                { "h|?|help", "Show this message and exit", h => showHelp = h != null },
            };
            err = commands.Run(args);
            return err;
        }
    }
}
