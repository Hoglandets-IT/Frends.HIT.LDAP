namespace Frends.LDAP.DeleteUser.Definitions;

/// <summary>
/// Input parameters.
/// </summary>
public class Input
{
    /// <summary>
    /// Directory path.
    /// </summary>
    /// <example>CN=Users,DC=Example,DC=Com</example>
    public string Path { get; set; }

    /// <summary>
    /// Common name (CN).
    /// </summary>
    /// <example>Firstname Lastname</example>
    public string CommonName { get; set; }
}

