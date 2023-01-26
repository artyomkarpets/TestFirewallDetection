using System;
using System.Collections.Generic;
using System.Management;
using System.Text;
using WindowsFirewallHelper;

namespace MyApp // Note: actual namespace depends on the project name.
{
    internal class Program
    {
        static void Main(string[] args)
        {
            try
            {
                ChaeckFirewall();
                GetFirewallList();

            }
            catch (Exception e)
            {
                Console.WriteLine(String.Format("Exception {0} Trace {1}", e.Message, e.StackTrace));
            }

            Console.WriteLine("Press Enter to exit");
            //select the proper wmi namespace depending of the windows version
            Console.Read();
        }

        private static bool ChaeckFirewall()
        {
            if (!FirewallManager.IsServiceRunning)
            {
                Console.WriteLine("Windows firewall is not runing");
                return false;
            }

            Console.WriteLine("Windows firewall process is runing");


            var inst = FirewallManager.Instance;

            foreach (var firewallProfile in inst.Profiles)
            {
                if (!firewallProfile.Enable)
                {
                    Console.WriteLine($"firewall profile {firewallProfile.Type} is  disabled");
                }
                else
                {
                    Console.WriteLine($"firewall profile {firewallProfile.Type} is  enabled");

                }
            }

            if (inst.Profiles.Any(x => !x.Enable))
                return false;

            return true;
        }
        /*
         *  AVG Internet Security 2012 (from antivirusproduct WMI)

            262144 (040000) = disabled and up to date

            266240 (041000) = enabled and up to date

            AVG Internet Security 2012 (from firewallproduct WMI)

            266256 (041010) = firewall enabled - (last two blocks not relevant it seems for firewall)

            262160 (040010) = firewall disabled - (last two blocks not relevant it seems for firewall)

            Windows Defender

            393472 (060100) = disabled and up to date

            397584 (061110) = enabled and out of date

            397568 (061100) = enabled and up to date

            Microsoft Security Essentials

            397312 (061000) = enabled and up to date

            393216 (060000) = disabled and up to date
         */
        private static void GetFirewallList()
        {
            string WMINameSpace = System.Environment.OSVersion.Version.Major > 5 ? "SecurityCenter2" : "SecurityCenter";


            var machineName = Environment.MachineName;



            Console.WriteLine("MachineName is " + machineName);
            Console.WriteLine("WMINameSpace is " + WMINameSpace);

            ManagementScope Scope;


            Scope = new ManagementScope(String.Format("\\\\{0}\\root\\{1}", machineName, WMINameSpace), null);

            // Scope = new ManagementScope(String.Format("\\\\{0}\\root\\{1}", machineName, WMINameSpace), null);


            Scope.Connect();
            ObjectQuery Query = new ObjectQuery("SELECT * FROM FirewallProduct");
            ManagementObjectSearcher Searcher = new ManagementObjectSearcher(Scope, Query);

            foreach (ManagementObject WmiObject in Searcher.Get())
            {
                Console.WriteLine("{0,-35} {1,-40}", "Firewall Name", WmiObject["displayName"]);
                if (System.Environment.OSVersion.Version.Major < 6) //is XP ?
                {
                    Console.WriteLine("{0,-35} {1,-40}", "Enabled", WmiObject["enabled"]);
                }
                else
                {
                    Console.WriteLine("{0,-35} {1,-40}", "State", WmiObject["productState"].ToString() == "397312" ? "enabled and up to date" : $"disabled(status code: {WmiObject["productState"].ToString()})");
                }
            }
        }
    }
}