using System.ComponentModel;

namespace Frends.HIT.LDAP.AddUserToGroups.Definitions;

/// <summary>
/// Input parameters.
/// </summary>
public class Input
{
    /// <summary>
    /// User's distinguished name (DN)
    /// </summary>
    /// <example>CN=Tes Tuser,ou=users,dc=wimpi,dc=net</example>
    public string UserDistinguishedName { get; set; }

    /// <summary>
    /// Group's distinguished name (DN)
    /// </summary>
    /// <example>cn=admin,ou=roles,dc=wimpi,dc=net</example>
    public string GroupDistinguishedName { get; set; }

    /// <summary>
    /// Handle user exists exception.
    /// </summary>
    /// <example>UserExistsAction.Throw</example>
    [DefaultValue(UserExistsAction.Throw)]
    public UserExistsAction UserExistsAction { get; set; }
}
