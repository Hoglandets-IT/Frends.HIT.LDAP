using Frends.HIT.LDAP.SearchObjects.Definitions;
using System.ComponentModel;
using Novell.Directory.Ldap;
using Novell.Directory.Ldap.Controls;
using System;
using System.Collections.Generic;
using System.Threading;

namespace Frends.HIT.LDAP.SearchObjects;

/// <summary>
/// LDAP task.
/// </summary>
public class LDAP
{
    /// <summary>
    /// Search objects from Active Directory with paginated results.
    /// </summary>
    /// <param name="input">Input parameters.</param>
    /// <param name="connection">Connection parameters.</param>
    /// <param name="cancellationToken">Token to stop the task.</param>
    /// <returns>Object { bool Success, string Error, List&lt;SearchResult&gt; SearchResult }</returns>
    public static Result SearchObjects([PropertyTab] Input input, [PropertyTab] Connection connection, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(connection.Host))
            throw new Exception("Host is missing.");

        if (string.IsNullOrEmpty(connection.User) && !connection.AnonymousBind)
            throw new Exception("Username is missing.");

        if (string.IsNullOrEmpty(connection.Password) && !connection.AnonymousBind)
            throw new Exception("Password is missing.");

        var ldapConnectionOptions = new LdapConnectionOptions();
        if (connection.IgnoreCertificates)
            ldapConnectionOptions.ConfigureRemoteCertificateValidationCallback((sender, certificate, chain, errors) => true);

        using var conn = new LdapConnection(ldapConnectionOptions);
        conn.SecureSocketLayer = connection.SecureSocketLayer;
        conn.Connect(connection.Host, connection.Port == 0 ? 389 : connection.Port);
        if (connection.TLS) conn.StartTls();

        if (connection.AnonymousBind)
            conn.Bind(3, null, null);
        else
            conn.Bind(3, connection.User, connection.Password ?? string.Empty); // Fixa bind-fel

        var searchResults = new List<SearchResult>();
        var cookie = new byte[0]; // För paginering
        var pageSize = input.PageSize > 0 ? input.PageSize : 500;
        var pageControl = new LdapPagedResultsControl(pageSize, true);

        int pageCounter = 0;

        try
        {
            do
            {
                pageCounter++;
                Console.WriteLine($"📄 Fetching page {pageCounter}...");

                var searchConstraints = new LdapSearchConstraints
                {
                    BatchSize = pageSize
                };
                conn.Constraints = searchConstraints;
                conn.Constraints.SetControls(pageControl); // Rätt sätt att lägga till kontroll

                var searchQueue = conn.Search(
                    input.SearchBase,
                    SetScope(input),
                    string.IsNullOrEmpty(input.Filter) ? null : input.Filter,
                    GetAttributeArray(input),
                    input.TypesOnly,
                    null,
                    searchConstraints);

                int resultsOnPage = 0;
                LdapMessage message;
                while ((message = searchQueue.GetResponse()) != null)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (message is LdapSearchResult ldapSearchResult)
                    {
                        var entry = ldapSearchResult.Entry;
                        var attributes = GetAttributeSet(entry, input.Attributes);

                        searchResults.Add(new SearchResult { DistinguishedName = entry.Dn, AttributeSet = attributes });
                        resultsOnPage++;
                    }
                }

                Console.WriteLine($"✅ Page {pageCounter} returned {resultsOnPage} objects");

                var response = searchQueue.GetResponse() as LdapResponse; // Korrekt ersättning för LdapSearchResultDone
                var pagedControlResponse = response?.GetControls()[0] as LdapPagedResultsResponse;

                cookie = pagedControlResponse?.Cookie ?? Array.Empty<byte>();
                pageControl = new LdapPagedResultsControl(pageSize, true, cookie);

            } while (cookie.Length > 0);
        }
        finally
        {
            if (connection.TLS) conn.StopTls();
            conn.Disconnect();
        }

        Console.WriteLine($"✅ Total objects retrieved: {searchResults.Count}");
        return new Result(true, null, searchResults);
    }


    /// <summary>
    /// Converts requested attributes into an array.
    /// </summary>
    private static string[] GetAttributeArray(Input input)
    {
        if (input.Attributes == null || input.Attributes.Length == 0)
            return null;

        var attributeList = new List<string>();
        foreach (var attr in input.Attributes)
        {
            attributeList.Add(attr.Key);
        }
        return attributeList.ToArray();
    }

    /// <summary>
    /// Extracts attributes from an LDAP entry based on requested attribute definitions.
    /// </summary>
    private static List<AttributeSet> GetAttributeSet(LdapEntry entry, AttributeDefinition[] requestedAttributes)
    {
        var attributeList = new List<AttributeSet>();
        var attributeSet = entry.GetAttributeSet();
        var enumerator = attributeSet.GetEnumerator();

        while (enumerator.MoveNext())
        {
            var attribute = enumerator.Current as LdapAttribute;
            if (attribute == null) continue;

            var attributeName = attribute.Name;
            object attributeValue = attribute.StringValue;

            var attributeDefinition = requestedAttributes != null
                ? Array.Find(requestedAttributes, d => d.Key.Equals(attributeName, StringComparison.OrdinalIgnoreCase))
                : null;

            if (attributeDefinition != null)
            {
                switch (attributeDefinition.ReturnType)
                {
                    case AttributeReturnType.Byte:
                        attributeValue = BitConverter.ToString(attribute.ByteValue).Replace("-", "");
                        break;
                    case AttributeReturnType.Guid:
                        attributeValue = new Guid(attribute.ByteValue).ToString();
                        break;
                    default:
                        attributeValue = attribute.StringValue;
                        break;
                }
            }

            attributeList.Add(new AttributeSet { Key = attributeName, Value = attributeValue });
        }

        return attributeList;
    }

    /// <summary>
    /// Converts input search scope to LDAP integer values.
    /// </summary>
    internal static int SetScope(Input input)
    {
        return input.Scope switch
        {
            Scopes.ScopeBase => LdapConnection.ScopeBase,
            Scopes.ScopeOne => LdapConnection.ScopeOne,
            Scopes.ScopeSub => LdapConnection.ScopeSub,
            _ => throw new Exception("SetScope error: Invalid scope."),
        };
    }
}
