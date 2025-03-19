using Frends.HIT.LDAP.SearchObjects.Definitions;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Threading;

namespace Frends.HIT.LDAP.SearchObjects;

/// <summary>
/// LDAP task with Microsoft DirectoryServices.
/// </summary>
public class LDAP
{
    /// <summary>
    /// Search objects from Active Directory with paginated results.
    /// </summary>
    public static Result SearchObjects(Input input, Connection connection, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(connection.Host))
            throw new Exception("Host is missing.");

        if (string.IsNullOrEmpty(connection.User) && !connection.AnonymousBind)
            throw new Exception("Username is missing.");

        if (string.IsNullOrEmpty(connection.Password) && !connection.AnonymousBind)
            throw new Exception("Password is missing.");

        using var conn = new LdapConnection(new LdapDirectoryIdentifier(connection.Host, connection.Port == 0 ? 389 : connection.Port));

        if (connection.IgnoreCertificates)
            conn.SessionOptions.VerifyServerCertificate = (sender, cert) => true;

        conn.AuthType = connection.AnonymousBind ? AuthType.Anonymous : AuthType.Basic;
        conn.Bind(new NetworkCredential(connection.User, connection.Password ?? string.Empty));

        var searchResults = new List<SearchResult>();
        var pageSize = input.PageSize > 0 ? input.PageSize : 500;
        var requestControl = new PageResultRequestControl(pageSize);
        SearchRequest request = new(input.SearchBase, input.Filter, SearchScope.Subtree);

        request.Controls.Add(requestControl);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var response = (SearchResponse)conn.SendRequest(request);
            foreach (SearchResultEntry entry in response.Entries)
            {
                var attributes = new List<AttributeSet>();
                foreach (DirectoryAttribute attr in entry.Attributes.Values)
                {
                    attributes.Add(new AttributeSet { Key = attr.Name, Value = attr.GetValues(typeof(string)) });
                }
                searchResults.Add(new SearchResult { DistinguishedName = entry.DistinguishedName, AttributeSet = attributes });
            }

            var responseControl = response.Controls[0] as PageResultResponseControl;
            if (responseControl == null || responseControl.Cookie.Length == 0)
                break;

            requestControl.Cookie = responseControl.Cookie;
        }

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
