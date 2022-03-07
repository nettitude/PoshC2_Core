using System;
using System.Runtime.InteropServices;
using System.Text;
using Core.WindowsInternals;

namespace Core.CredPopper
{
    internal static class CredentialManager
    {
        internal static CredentialResult PromptForCredentials(IntPtr owner = new(), string messageText = null, string captionText = null, string userName = null,
            Internals.CredentialSaveOption saveCredential = Internals.CredentialSaveOption.Unselected)
        {
            var credUi = new Internals.CredentialUiInfo
            {
                hwndParent = owner,
                pszMessageText = messageText,
                pszCaptionText = captionText,
                hbmBanner = IntPtr.Zero,
            };

            var save = saveCredential == Internals.CredentialSaveOption.Selected;

            // Setup the flags and variables
            credUi.cbSize = Marshal.SizeOf(credUi);
            const int errorCode = 0;
            uint authPackage = 0;

            var flags = Internals.PromptForWindowsCredentialsFlags.GenericCredentials | Internals.PromptForWindowsCredentialsFlags.EnumerateCurrentUser;
            if (saveCredential != Internals.CredentialSaveOption.Hidden)
            {
                flags |= Internals.PromptForWindowsCredentialsFlags.ShowCheckbox;
            }

            // Prefill username
            GetInputBuffer(userName, out var inCredBuffer, out var inCredSize);

            // Setup the flags and variables
            var result = Internals.CredUIPromptForWindowsCredentials(ref credUi, errorCode, ref authPackage, inCredBuffer, inCredSize, out var outCredBuffer, out var outCredSize,
                ref save, flags);

            FreeCoTaskMem(inCredBuffer);

            if (result == 0 && GetCredentialsFromOutputBuffer(outCredBuffer, outCredSize, out userName, out var password, out var domain))
            {
                return new CredentialResult(userName, password, domain);
            }

            return null;
        }

        private static void GetInputBuffer(string user, out IntPtr inCredBuffer, out int inCredSize)
        {
            if (!string.IsNullOrEmpty(user))
            {
                var usernameBuf = new StringBuilder(user);
                var passwordBuf = new StringBuilder();

                inCredSize = 1024;
                inCredBuffer = Marshal.AllocCoTaskMem(inCredSize);
                if (Internals.CredPackAuthenticationBuffer(0, usernameBuf, passwordBuf, inCredBuffer, ref inCredSize))
                    return;
            }

            inCredBuffer = IntPtr.Zero;
            inCredSize = 0;
        }

        private static bool GetCredentialsFromOutputBuffer(IntPtr outCredBuffer, uint outCredSize, out string userName, out string password, out string domain)
        {
            var maxUserName = Internals.CREDUI_MAX_USERNAME_LENGTH;
            var maxDomain = Internals.CREDUI_MAX_USERNAME_LENGTH;
            var maxPassword = Internals.CREDUI_MAX_USERNAME_LENGTH;
            var usernameBuf = new StringBuilder(maxUserName);
            var passwordBuf = new StringBuilder(maxDomain);
            var domainBuf = new StringBuilder(maxPassword);
            try
            {
                if (Internals.CredUnPackAuthenticationBuffer(0, outCredBuffer, outCredSize, usernameBuf, ref maxUserName, domainBuf, ref maxDomain, passwordBuf, ref maxPassword))
                {
                    userName = usernameBuf.ToString();
                    password = passwordBuf.ToString();
                    domain = domainBuf.ToString();

                    if (string.IsNullOrWhiteSpace(domain))
                    {
                        usernameBuf.Clear();
                        domainBuf.Clear();

                        var returnCode = Internals.CredUIParseUserName(userName, usernameBuf, usernameBuf.Capacity, domainBuf, domainBuf.Capacity);
                        switch (returnCode)
                        {
                            case Internals.CredentialUiReturnCodes.Success:
                                userName = usernameBuf.ToString();
                                domain = domainBuf.ToString();
                                break;

                            case Internals.CredentialUiReturnCodes.InvalidAccountName:
                                break;

                            case Internals.CredentialUiReturnCodes.InsufficientBuffer:
                                throw new OutOfMemoryException();

                            case Internals.CredentialUiReturnCodes.InvalidParameter:
                                throw new ArgumentException();

                            default:
                                throw new ArgumentOutOfRangeException();
                        }
                    }

                    return true;
                }
                else
                {
                    userName = null;
                    password = null;
                    domain = null;
                    return false;
                }
            }
            finally
            {
                //mimic SecureZeroMem function to make sure buffer is zeroed out. SecureZeroMem is not an exported function, neither is RtlSecureZeroMemory
                var zeroBytes = new byte[outCredSize];
                Marshal.Copy(zeroBytes, 0, outCredBuffer, (int) outCredSize);
                FreeCoTaskMem(outCredBuffer);
            }
        }

        private static void FreeCoTaskMem(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero)
                return;

            Marshal.FreeCoTaskMem(ptr);
        }
    }
}