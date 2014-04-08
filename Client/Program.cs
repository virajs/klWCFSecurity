using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ConsoleApplication2
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                Service1Client client = new Service1Client();
                string ans = client.GetData(42);
                client.Close();
                Console.WriteLine(ans);
                Console.Read();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                Console.WriteLine(e.InnerException.Message);
               
                throw;
            }

        }
    }
}
