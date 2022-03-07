using Core.WindowsInternals;

namespace Core.CredPopper
{
    internal sealed class Credential
    {
        private Internals.CredentialType CredentialType { get; }
        private string ApplicationName { get; }
        private string UserName { get; }
        private string Password { get; }
        private string Comment { get; }

        internal Credential(Internals.CredentialType credentialType, string applicationName, string userName, string password, string comment)
        {
            ApplicationName = applicationName;
            UserName = userName;
            Password = password;
            CredentialType = credentialType;
            Comment = comment;
        }

        public override string ToString()
        {
            return $"CredentialType: {CredentialType}, ApplicationName: {ApplicationName}, UserName: {UserName}, Password: {Password}, Comment: {Comment}";
        }
    }
}