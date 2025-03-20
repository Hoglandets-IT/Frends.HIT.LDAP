using Frends.HIT.LDAP.GetObjects.Definitions;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Threading;

namespace Frends.HIT.LDAP.GetObjects;

/// <summary>
/// LDAP task using System.DirectoryServices.Protocols.
/// </summary>
public class LDAP
{
    /// <summary>
    /// Search objects from Active Directory with paginated results.
    /// </summary>
    public static Result GetObjects([PropertyTab] Input input, [PropertyTab] Connection connection, CancellationToken cancellationToken)
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
        SearchRequest request = new(input.SearchBase, input.Filter, ConvertScope(input.Scope), new string[0]);

        request.Controls.Add(requestControl);
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var response = (SearchResponse)conn.SendRequest(request);
            foreach (SearchResultEntry entry in response.Entries)
            {
                var attributes = ExtractAttributes(entry, input.Attributes);
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
    /// Extracts attributes from an LDAP entry based on requested attribute definitions.
    /// </summary>
    private static List<AttributeSet> ExtractAttributes(SearchResultEntry entry, AttributeDefinition[] requestedAttributes)
    {
        var attributeList = new List<AttributeSet>();

        foreach (string attrName in entry.Attributes.AttributeNames)
        {
            var attr = entry.Attributes[attrName];

            object attributeValue;
            if (attr.Count == 1)
            {
                attributeValue = attr[0];
            }
            else
            {
                var values = new List<string>();
                foreach (var value in attr.GetValues(typeof(string)))
                {
                    values.Add(value.ToString());
                }
                attributeValue = values;
            }

            var attributeDefinition = requestedAttributes != null
                ? Array.Find(requestedAttributes, d => d.Key.Equals(attrName, StringComparison.OrdinalIgnoreCase))
                : null;

            if (attributeDefinition != null)
            {
                switch (attributeDefinition.ReturnType)
                {
                    case AttributeReturnType.Byte:
                        attributeValue = BitConverter.ToString((byte[])attr.GetValues(typeof(byte[]))[0]).Replace("-", "");
                        break;
                    case AttributeReturnType.Guid:
                        attributeValue = new Guid((byte[])attr.GetValues(typeof(byte[]))[0]).ToString();
                        break;
                }
            }

            attributeList.Add(new AttributeSet { Key = attrName, Value = attributeValue });
        }

        return attributeList;
    }

    /// <summary>
    /// Converts input search scope to LDAP integer values.
    /// </summary>
    private static SearchScope ConvertScope(Scopes scope)
    {
        return scope switch
        {
            Scopes.ScopeBase => SearchScope.Base,
            Scopes.ScopeOne => SearchScope.OneLevel,
            Scopes.ScopeSub => SearchScope.Subtree,
            _ => throw new Exception("ConvertScope error: Invalid scope."),
        };
    }
}
