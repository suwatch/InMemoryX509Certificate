using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace InMemoryX509Certificate
{
    static class Program
    {
        static void Main(string[] args)
        {
            try
            {
                if (args.Length == 0)
                {
                    Console.WriteLine("Usage: InMemoryX509Certificate.exe [pfxFile] [password]");
                    return;
                }

                var pfx = args[0];
                var pwd = args.Length > 1 ? args[1] : $"{pfx}.txt";
                if (File.Exists(pwd))
                {
                    pwd = File.ReadAllText(pwd);
                }

                pwd = pwd.Trim();
                using (var fileCert = new X509Certificate2(pfx, pwd))
                using (var inmem = new InMemoryX509Certificate(pfx, pwd))
                using (var memCert = new X509Certificate2(inmem.Handle))
                {
                    EncryptionTests(fileCert, memCert);
                    SigningTests(fileCert, memCert);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);

            }
        }

        static void EncryptionTests(X509Certificate2 fileCert, X509Certificate2 memCert)
        {
            var rnd = new Random();
            var rawData = new byte[64];
            rnd.NextBytes(rawData);

            using (var fileCertPrivateKey = fileCert.GetRSAPrivateKey())
            using (var memCertPrivateKey = memCert.GetRSAPrivateKey())
            using (var fileCertPublicKey = fileCert.GetRSAPublicKey())
            using (var memCertPublicKey = memCert.GetRSAPublicKey())
            {
                var padding = RSAEncryptionPadding.OaepSHA1;

                var encryptedUsingFileCert = fileCertPublicKey.Encrypt(rawData, padding);
                var encryptedUsingMemoryCert = memCertPublicKey.Encrypt(rawData, padding);

                var decryptedUsingFileCert = fileCertPrivateKey.Decrypt(encryptedUsingFileCert, padding);
                var decryptedUsingMemoryCert = memCertPrivateKey.Decrypt(encryptedUsingFileCert, padding);

                var decryptedUsingFileCert1 = fileCertPrivateKey.Decrypt(encryptedUsingMemoryCert, padding);
                var decryptedUsingMemoryCert1 = memCertPrivateKey.Decrypt(encryptedUsingMemoryCert, padding);

                // Assert
                AssertAreEqual(rawData, decryptedUsingFileCert);
                AssertAreEqual(rawData, decryptedUsingMemoryCert);
                AssertAreEqual(rawData, decryptedUsingFileCert1);
                AssertAreEqual(rawData, decryptedUsingMemoryCert1);
            }

            Console.WriteLine($"EncryptionTests passed");
        }

        static void SigningTests(X509Certificate2 fileCert, X509Certificate2 memCert)
        {
            var rnd = new Random();
            var rawData = new byte[256];
            rnd.NextBytes(rawData);

            using (var fileCertPrivateKey = fileCert.GetRSAPrivateKey())
            using (var memCertPrivateKey = memCert.GetRSAPrivateKey())
            using (var fileCertPublicKey = fileCert.GetRSAPublicKey())
            using (var memCertPublicKey = memCert.GetRSAPublicKey())
            {
                var signatureUsingFileCert = fileCertPrivateKey.HashAndSign(rawData);
                var signatureUsingMemoryCert = memCertPrivateKey.HashAndSign(rawData);

                // Assert
                fileCertPublicKey.HashAndVerifySignature(rawData, signatureUsingFileCert);
                fileCertPublicKey.HashAndVerifySignature(rawData, signatureUsingMemoryCert);
                memCertPublicKey.HashAndVerifySignature(rawData, signatureUsingFileCert);
                memCertPublicKey.HashAndVerifySignature(rawData, signatureUsingMemoryCert);
            }

            Console.WriteLine($"SigningTests passed");
        }

        static byte[] HashAndSign(this RSA rsa, byte[] rawData)
        {
            using (var hash = new SHA1Managed())
            {
                byte[] hashedData;
                hashedData = hash.ComputeHash(rawData);
                return rsa.SignHash(hashedData, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
            }
        }

        static void HashAndVerifySignature(this RSA rsa, byte[] rawData, byte[] signature)
        {
            using (var hash = new SHA1Managed())
            {
                byte[] hashedData;
                hashedData = hash.ComputeHash(rawData);
                if (!rsa.VerifyHash(hashedData, signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1))
                {
                    throw new Exception($"Fail verify signature");
                }
            }
        }

        static void AssertAreEqual(byte[] src, byte[] dst)
        {
            if (src.Length == 0)
            {
                throw new Exception($"Invalid zero length");
            }

            if (src.Length != dst.Length)
            {
                throw new Exception($"Length not equals {src.Length} != {dst.Length}");
            }

            for (int i = 0; i < src.Length; ++i)
            {
                if (src[i] != dst[i])
                {
                    throw new Exception($"Byte[{i}] not equals {src[i]} != {dst[i]}");
                }
            }
        }
    }
}
