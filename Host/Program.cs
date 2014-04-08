using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.Text;

//using securityDLL;

namespace ConsoleApplication1
{
    class Program
    {
        public static void StartHost()
        {       
            using (System.ServiceModel.ServiceHost mServiceHost = new ServiceHost(typeof(WcfServiceLibrary.Service1)))
            {
                mServiceHost.Open();
                Console.WriteLine("The service is ready.");
                Console.WriteLine("Press <ENTER> to terminate service.");
                Console.ReadLine();
                mServiceHost.Close();
            }
        }
        static void Main(string[] args)
        {
            StartHost();
            Console.WriteLine(" WFC SErvice Has Been Started.  Press Enter to end program.");
            Console.ReadLine();
        }
    }
}
