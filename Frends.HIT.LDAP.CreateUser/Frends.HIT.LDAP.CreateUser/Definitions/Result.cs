﻿namespace Frends.LDAP.CreateUser.Definitions;

/// <summary>
/// Task's result.
/// </summary>
public class Result
{
    /// <summary>
    /// User created.
    /// </summary>
    /// <example>true</example>
    public bool Success { get; private set; }

    /// <summary>
    /// LDAP Error message.
    /// </summary>
    /// <example>Entry Already Exists</example>
    public string Error { get; private set; }

    /// <summary>
    /// Common name.
    /// </summary>
    /// <example>Firstname Lastname</example>
    public string CommonName { get; private set; }

    /// <summary>
    /// Password set.
    /// </summary>
    /// <example>true</example>
    public bool PasswordSet { get; private set; }

    /// <summary>
    /// Path.
    /// </summary>
    /// <example>CN=Users,DC=Example,DC=Com</example>
    public string Path { get; private set; }

    internal Result(bool success, string error, string commonName, bool passwordSet, string path)
    {
        Success = success;
        Error = error;
        CommonName = commonName;
        PasswordSet = passwordSet;
        Path = path;
    }
}

