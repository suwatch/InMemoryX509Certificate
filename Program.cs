using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace InMemoryX509Certificate
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var pfx = args[0];
                var pwd = args[1];
                if (File.Exists(pwd))
                {
                    pwd = File.ReadAllText(pwd.Trim());
                }

                for (int i = 0; i < 3; ++i)
                {
                    using (var inmem = new InMemoryX509Certificate(pfx, pwd))
                    using (var cert = new X509Certificate2(inmem.Handle))
                    {
                        Console.WriteLine($"{i + 1}. Thumbprint: {cert.Thumbprint}, HasPrivateKey: {cert.HasPrivateKey}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);

            }
        }
    }
}
