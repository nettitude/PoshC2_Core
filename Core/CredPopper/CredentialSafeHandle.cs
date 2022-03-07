using System;
using System.Runtime.InteropServices;
using Core.WindowsInternals;
using Microsoft.Win32.SafeHandles;

namespace Core.CredPopper
{
    internal abstract class CredentialSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        protected CredentialSafeHandle()
            : base(true)
        {
        }

        public Internals.Credential GetCredential()
        {
            if (!IsInvalid)
            {
                return (Internals.Credential) Marshal.PtrToStructure(handle, typeof(Credential));
            }

            throw new InvalidOperationException("Invalid CriticalHandle!");
        }

        protected override bool ReleaseHandle()
        {
            return Internals.CredFree(handle);
        }
    }
}