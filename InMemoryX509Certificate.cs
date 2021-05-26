using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace InMemoryX509Certificate
{
    public class InMemoryX509Certificate : X509Certificate
    {
        const uint EphemeralKeySetFlag = 0x8200;
        static readonly Type X509UtilsType = typeof(X509Certificate).Assembly.GetType("System.Security.Cryptography.X509Certificates.X509Utils", throwOnError: true);
        static readonly MethodInfo LoadCertFromFile = X509UtilsType.GetMethod("_LoadCertFromFile", BindingFlags.Static | BindingFlags.NonPublic);
        static readonly MethodInfo LoadCertFromBlob = X509UtilsType.GetMethod("_LoadCertFromBlob", BindingFlags.Static | BindingFlags.NonPublic);
        static readonly FieldInfo SafeCertContextField = typeof(X509Certificate).GetField("m_safeCertContext", BindingFlags.Instance | BindingFlags.NonPublic);

        readonly WeakReference m_safeCertContext;

        public InMemoryX509Certificate(byte[] rawData, string password, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
        {
            m_safeCertContext = new WeakReference(SafeCertContextField.GetValue(this));
            LoadCertificateFromBlob(rawData, password, keyStorageFlags);
        }

        public InMemoryX509Certificate(string fileName, string password, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
        {
            m_safeCertContext = new WeakReference(SafeCertContextField.GetValue(this));
            LoadCertificateFromFile(fileName, password, keyStorageFlags);
        }

        private void LoadCertificateFromBlob(byte[] rawData, string password, X509KeyStorageFlags keyStorageFlags)
        {
            uint flags = MapKeyStorageFlags(keyStorageFlags);
            IntPtr intPtr = IntPtr.Zero;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                intPtr = Marshal.StringToHGlobalUni(password);
                LoadCertFromBlob.Invoke(null, new object[] { rawData, intPtr, flags, false, m_safeCertContext.Target });
            }
            finally
            {
                if (intPtr != IntPtr.Zero)
                {
                    Marshal.ZeroFreeGlobalAllocUnicode(intPtr);
                }
            }
        }

        private void LoadCertificateFromFile(string fileName, string password, X509KeyStorageFlags keyStorageFlags)
        {
            uint flags = MapKeyStorageFlags(keyStorageFlags);
            IntPtr intPtr = IntPtr.Zero;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                intPtr = Marshal.StringToHGlobalUni(password);
                LoadCertFromFile.Invoke(null, new object[] { fileName, intPtr, flags, false, m_safeCertContext.Target });
            }
            finally
            {
                if (intPtr != IntPtr.Zero)
                {
                    Marshal.ZeroFreeGlobalAllocUnicode(intPtr);
                }
            }
        }

        private static uint MapKeyStorageFlags(X509KeyStorageFlags keyStorageFlags)
        {
            if (X509KeyStorageFlags.PersistKeySet == (keyStorageFlags & X509KeyStorageFlags.PersistKeySet))
            {
                throw new ArgumentException("X509KeyStorageFlags.PersistKeySet is not supported for InMemoryX509Certificate");
            }

            // always ephemeral
            uint flags = EphemeralKeySetFlag;
            if ((keyStorageFlags & X509KeyStorageFlags.UserKeySet) == X509KeyStorageFlags.UserKeySet)
            {
                flags |= 0x1000;
            }
            else if ((keyStorageFlags & X509KeyStorageFlags.MachineKeySet) == X509KeyStorageFlags.MachineKeySet)
            {
                flags |= 0x20;
            }

            if ((keyStorageFlags & X509KeyStorageFlags.Exportable) == X509KeyStorageFlags.Exportable)
            {
                flags |= 1;
            }
            if ((keyStorageFlags & X509KeyStorageFlags.UserProtected) == X509KeyStorageFlags.UserProtected)
            {
                flags |= 2;
            }

            return flags;
        }
    }
}
