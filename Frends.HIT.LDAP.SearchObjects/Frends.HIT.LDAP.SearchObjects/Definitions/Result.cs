using System.Collections.Generic;
namespace Frends.HIT.LDAP.SearchObjects.Definitions;

/// <summary>
/// Task's results.
/// </summary>
public class Result
{
    /// <summary>
    /// Search completed.
    /// </summary>
    /// <example>true</example>
    public bool Success { get; private set; }

    /// <summary>
    /// LDAP Error message.
    /// </summary>
    /// <example>Entry Already Exists</example>
    public string Error { get; private set; }

    /// <summary>
    /// Results.
    /// </summary>
    /// <example>{ AttributeSet { Key = "sn", Value = "Bar" }, DistinguishedName = "CN=Foo Bar,ou=users,dc=wimpi,dc=net" }</example>
    public List<SearchResult> SearchResult { get; private set; }

    internal Result(bool success, string error, List<SearchResult> searchResult)
    {
        Success = success;
        Error = error;
        SearchResult = searchResult;
    }
}
