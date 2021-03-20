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

        public InMemoryX509Certificate(byte[] rawData, string password)
        {
            m_safeCertContext = new WeakReference(SafeCertContextField.GetValue(this));
            LoadCertificateFromBlob(rawData, password);
        }

        public InMemoryX509Certificate(string fileName, string password)
        {
            m_safeCertContext = new WeakReference(SafeCertContextField.GetValue(this));
            LoadCertificateFromFile(fileName, password);
        }

        private void LoadCertificateFromBlob(byte[] rawData, string password)
        {
            IntPtr intPtr = IntPtr.Zero;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                intPtr = Marshal.StringToHGlobalUni(password);
                LoadCertFromBlob.Invoke(null, new object[] { rawData, intPtr, EphemeralKeySetFlag, false, m_safeCertContext.Target });
            }
            finally
            {
                if (intPtr != IntPtr.Zero)
                {
                    Marshal.ZeroFreeGlobalAllocUnicode(intPtr);
                }
            }
        }

        private void LoadCertificateFromFile(string fileName, string password)
        {
            IntPtr intPtr = IntPtr.Zero;
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                intPtr = Marshal.StringToHGlobalUni(password);
                LoadCertFromFile.Invoke(null, new object[] { fileName, intPtr, EphemeralKeySetFlag, false, m_safeCertContext.Target });
            }
            finally
            {
                if (intPtr != IntPtr.Zero)
                {
                    Marshal.ZeroFreeGlobalAllocUnicode(intPtr);
                }
            }
        }
    }
}
