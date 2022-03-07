namespace Core.CredPopper
{
    internal class CredentialResult
    {
        internal CredentialResult(string userName, string password, string domain)
        {
            UserName = userName;
            Password = password;
            Domain = domain;
        }

        internal string UserName { get; }
        internal string Password { get; }
        internal string Domain { get; }
    }
}