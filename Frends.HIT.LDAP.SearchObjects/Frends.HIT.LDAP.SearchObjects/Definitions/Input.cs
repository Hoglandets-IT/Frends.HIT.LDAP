﻿using System;
using System.ComponentModel;

namespace Frends.LDAP.SearchObjects.Definitions;

public class Input
{
        /// <summary>
        /// The search base parameter specifies the DN of the entry where you want to begin the search.
        /// If you want the search to begin at the tree root pass an empty string.
        /// </summary>
        /// <example>"ou=users,dc=wimpi,dc=net"</example>
        public string SearchBase { get; set; }

        /// <summary>
        /// The search scope parameter specifies the depth of the search.
        /// </summary>
        /// <example>Scopes.ScopeBase</example>
        public Scopes Scope { get; set; }

        /// <summary>
        /// The search filter defines the entries that will be returned by the search.
        /// </summary>
        /// <example>(title=engineer)</example>
        public string Filter { get; set; }

        /// <summary>
        /// The maximum time in milliseconds to wait for results. The default is 0 (no limit).
        /// </summary>
        /// <example>0</example>
        [DefaultValue(0)]
        public int MsLimit { get; set; }

        /// <summary>
        /// The maximum time in seconds that the server should spend returning search results. The default is 0 (no limit).
        /// </summary>
        /// <example>0</example>
        [DefaultValue(0)]
        public int ServerTimeLimit { get; set; }

        /// <summary>
        /// Specifies when aliases should be dereferenced.
        /// </summary>
        /// <example>SearchDereference.DerefNever</example>
        [DefaultValue(SearchDereference.DerefNever)]
        public SearchDereference SearchDereference { get; set; }

        /// <summary>
        /// The maximum number of search results to return for a search request.
        /// </summary>
        /// <example>1000</example>
        [DefaultValue(1000)]
        public int MaxResults { get; set; }

        /// <summary>
        /// The number of results to return in a batch.
        /// </summary>
        /// <example>1</example>
        [DefaultValue(1)]
        public int BatchSize { get; set; }

        /// <summary>
        /// If true, returns only the attribute names and not their values.
        /// </summary>
        /// <example>false</example>
        [DefaultValue(false)]
        public bool TypesOnly { get; set; }

        /// <summary>
        /// List of attributes to retrieve along with an option to choose om deras returtyp.
        /// Exempel: Key = "objectGUID", ReturnType = AttributeReturnType.Byte
        /// </summary>
        public AttributeDefinition[] Attributes { get; set; } = Array.Empty<AttributeDefinition>();
    }

    /// <summary>
    /// Definition for an attribute to retrieve.
    /// </summary>
    public class AttributeDefinition
    {
        /// <summary>
        /// The name/key of the attribute (e.g. "cn", "objectGUID", etc.).
        /// </summary>
        /// <example>cn</example>
        public string Key { get; set; }

        /// <summary>
        /// Specifies if value returns as string or byte array om 
        /// String is default.
        /// </summary>
        /// <example>AttributeReturnType.String</example>
        [DefaultValue(AttributeReturnType.String)]
        public AttributeReturnType ReturnType { get; set; } = AttributeReturnType.String;
    }

    /// <summary>
    /// Enum tells wich format attribute will be returned as.
    /// </summary>
    public enum AttributeReturnType
    {
        String,
        Byte
    }


