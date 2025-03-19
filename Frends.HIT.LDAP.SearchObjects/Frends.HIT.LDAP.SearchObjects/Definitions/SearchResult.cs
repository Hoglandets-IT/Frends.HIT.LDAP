using System.Collections.Generic;
namespace Frends.HIT.LDAP.SearchObjects.Definitions;

/// <summary>
/// Search result.
/// </summary>
public class SearchResult
{
    /// <summary>
    /// Distinguished name of the entry.
    /// </summary>
    /// <example>CN=Foo Bar,ou=users,dc=wimpi,dc=net</example>
    public string DistinguishedName { get; set; }

    /// <summary>
    /// Search result's attributes.
    /// </summary>
    /// <example>{ Key = "sn", Value = "Bar" }, DistinguishedName = "CN=Foo Bar,ou=users,dc=wimpi,dc=net" }</example>
    public List<AttributeSet> AttributeSet { get; set; }
}

/// <summary>
/// AttributeSet values.
/// </summary>
public class AttributeSet
{
    /// <summary>
    /// Key.
    /// </summary>
    public string Key { get; set; }

    /// <summary>
    /// Value.
    /// </summary>
    public dynamic Value { get; set; }
}
