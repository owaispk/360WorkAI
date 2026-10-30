namespace WorkAI360.Api.Email;

public sealed class EmailOptions
{
    public const string Section = "Email";

    /// <summary>"dev" keeps messages in memory (Development only); "smtp" sends them for real.</summary>
    public string Provider { get; set; } = "dev";

    /// <summary>The From address, e.g. "OpenWork &lt;no-reply@example.com&gt;".</summary>
    public string From { get; set; } = "OpenWork <no-reply@localhost>";

    public SmtpOptions Smtp { get; set; } = new();

    public sealed class SmtpOptions
    {
        public string Host { get; set; } = "";
        public int Port { get; set; } = 587;
        public string? User { get; set; }
        public string? Password { get; set; }
        /// <summary>"auto" negotiates STARTTLS when offered; "none" is for local test servers only.</summary>
        public string Security { get; set; } = "auto";
    }
}
