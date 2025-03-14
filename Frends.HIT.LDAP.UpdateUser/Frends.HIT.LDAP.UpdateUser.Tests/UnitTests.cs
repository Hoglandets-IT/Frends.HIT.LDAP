using Microsoft.VisualStudio.TestTools.UnitTesting;
using Frends.HIT.LDAP.UpdateUser.Definitions;
using Novell.Directory.Ldap;
namespace Frends.HIT.LDAP.UpdateUser.Tests;

[TestClass]
public class UnitTests
{

    /*
        Create a simple LDAP server to docker
        docker run -d -it --rm -p 10389:10389 dwimberger/ldap-ad-it
    */

    private readonly string? _host = "127.0.0.1";
    private readonly int _port = 10389;
    private readonly string? _user = "uid=admin,ou=system";
    private readonly string? _pw = "secret";
    private readonly string _path = "ou=users,dc=wimpi,dc=net";

    Input? input;
    Connection? connection;

    [TestCleanup]
    public void CleanUp()
    {
        DeleteUser();
    }

    [TestMethod]
    public void Update_HandleLDAPError_Test()
    {
        CreateTestUsers(false);

        input = new()
        {
            Path = "CN=qw,DC=er,DC=ty",
            CommonName = "FAil" + new Guid(),
            ModificationMethod = ModificationMethod.Add,
            CreateDN = true,
            Attributes = new[] { new Attributes { Key = "title", Value = "senior coffee maker" } }
        };
        connection = new()
        {
            Host = _host,
            User = _user,
            Password = _pw,
            SecureSocketLayer = false,
            Port = _port,
            TLS = false,
        };

        var result = LDAP.UpdateUser(input, connection);
        Assert.IsTrue(result.Success.Equals(false) && result.Error.Contains("No Such Object"));
    }

    [TestMethod]
    public void UpdateUser_Add_New_CreateDNFalse_Test()
    {
        CreateTestUsers(false);

        input = new()
        {
            DistinguishedName = "CN=Tes TUser,ou=users,dc=wimpi,dc=net",
            ModificationMethod = ModificationMethod.Add,
            CreateDN = false,
            Attributes = new[] { new Attributes { Key = "title", Value = "senior coffee maker" } }

        };
        connection = new()
        {
            Host = _host,
            User = _user,
            Password = _pw,
            SecureSocketLayer = false,
            Port = _port,
            TLS = false,
        };

        var result = LDAP.UpdateUser(input, connection);
        Assert.IsTrue(result.Success.Equals(true));
    }

    [TestMethod]
    public void UpdateUser_Add_New_Test()
    {
        CreateTestUsers(false);

        input = new()
        {
            Path = "ou=users,dc=wimpi,dc=net",
            CommonName = "Tes TUser",
            ModificationMethod = ModificationMethod.Add,
            CreateDN = true,
            Attributes = new[] { new Attributes { Key = "title", Value = "senior coffee maker" } }

        };
        connection = new()
        {
            Host = _host,
            User = _user,
            Password = _pw,
            SecureSocketLayer = false,
            Port = _port,
            TLS = false,
        };

        var result = LDAP.UpdateUser(input, connection);
        Assert.IsTrue(result.Success.Equals(true));
    }

    [TestMethod]
    public void UpdateUser_Add_AlreadyHaveValue_Test()
    {
        CreateTestUsers(true);

        input = new()
        {
            Path = "ou=users,dc=wimpi,dc=net",
            CommonName = "Tes TUser",
            ModificationMethod = ModificationMethod.Add,
            CreateDN = true,
            Attributes = new[] { new Attributes { Key = "title", Value = "senior coffee maker" } }
        };
        connection = new()
        {
            Host = _host,
            User = _user,
            Password = _pw,
            SecureSocketLayer = false,
            Port = _port,
            TLS = false,
        };

        var result = LDAP.UpdateUser(input, connection);
        Assert.IsTrue(result.Success.Equals(true));
    }

    [TestMethod]
    public void UpdateUser_Delete_WithValue_DoesntExistsFail_Test()
    {
        CreateTestUsers(false);

        input = new()
        {
            Path = "ou=users,dc=wimpi,dc=net",
            CommonName = "Tes TUser",
            ModificationMethod = ModificationMethod.Delete,
            CreateDN = true,
            Attributes = new[] { new Attributes { Key = "title", Value = "coffee maker" } }

        };
        connection = new()
        {
            Host = _host,
            User = _user,
            Password = _pw,
            SecureSocketLayer = false,
            Port = _port,
            TLS = false,
        };

        var result = LDAP.UpdateUser(input, connection);
        Assert.IsTrue(result.Success.Equals(false) && result.Error.Contains("No Such Attribute"));
    }

    [TestMethod]
    public void UpdateUser_Delete_WithValue_Success_Test()
    {
        CreateTestUsers(true);

        input = new()
        {
            Path = "ou=users,dc=wimpi,dc=net",
            CommonName = "Tes TUser",
            ModificationMethod = ModificationMethod.Delete,
            CreateDN = true,
            Attributes = new[] { new Attributes { Key = "title", Value = "coffee maker" } }

        };
        connection = new()
        {
            Host = _host,
            User = _user,
            Password = _pw,
            SecureSocketLayer = false,
            Port = _port,
            TLS = false,
        };

        var result = LDAP.UpdateUser(input, connection);
        Assert.IsTrue(result.Success.Equals(true));
    }

    [TestMethod]
    public void UpdateUser_Delete_WithoutValue_Test()
    {
        CreateTestUsers(true);

        input = new()
        {
            Path = "ou=users,dc=wimpi,dc=net",
            CommonName = "Tes TUser",
            ModificationMethod = ModificationMethod.Add,
            CreateDN = true,
            Attributes = new[] { new Attributes { Key = "title", Value = "" } }
        };
        connection = new()
        {
            Host = _host,
            User = _user,
            Password = _pw,
            SecureSocketLayer = false,
            Port = _port,
            TLS = false,
        };

        var result = LDAP.UpdateUser(input, connection);
        Assert.IsTrue(result.Success.Equals(true));
    }

    [TestMethod]
    public void UpdateUser_Replace_WithValue_Test()
    {
        CreateTestUsers(false);

        input = new()
        {
            Path = "ou=users,dc=wimpi,dc=net",
            CommonName = "Tes TUser",
            ModificationMethod = ModificationMethod.Replace,
            CreateDN = true,
            Attributes = new[] { new Attributes { Key = "title", Value = "senior coffee maker" } }

        };
        connection = new()
        {
            Host = _host,
            User = _user,
            Password = _pw,
            SecureSocketLayer = false,
            Port = _port,
            TLS = false,
        };

        var result = LDAP.UpdateUser(input, connection);
        Assert.IsTrue(result.Success.Equals(true));
    }


    [TestMethod]
    public void UpdateUser_Replace_WithoutValue_Test()
    {
        CreateTestUsers(true);

        input = new()
        {
            Path = "ou=users,dc=wimpi,dc=net",
            CommonName = "Tes TUser",
            ModificationMethod = ModificationMethod.Replace,
            CreateDN = true,
            Attributes = new[] { new Attributes { Key = "title", Value = "" } }
        };
        connection = new()
        {
            Host = _host,
            User = _user,
            Password = _pw,
            SecureSocketLayer = false,
            Port = _port,
            TLS = false,
        };

        var result = LDAP.UpdateUser(input, connection);
        Assert.IsTrue(result.Success.Equals(true));
    }

    public void CreateTestUsers(bool setTitle)
    {
        LdapConnection conn = new();
        conn.Connect(_host, _port);
        conn.Bind(_user, _pw);

        var attributeSet = new LdapAttributeSet
        {
            new LdapAttribute("objectclass", "inetOrgPerson"),
            new LdapAttribute("cn", "Tes Tuser"),
            new LdapAttribute("givenname", "Tes"),
            new LdapAttribute("sn", "Tuser")
        };

        if (setTitle)
            attributeSet.Add(new LdapAttribute("title", "coffee maker"));

        var entry = $"CN=Tes Tuser,{_path}";
        LdapEntry newEntry = new(entry, attributeSet);
        conn.Add(newEntry);
        conn.Disconnect();
    }

    public void DeleteUser()
    {
        LdapConnection conn = new();
        conn.Connect(_host, _port);
        conn.Bind(_user, _pw);
        conn.Delete($"CN=Tes Tuser,{_path}");
        conn.Disconnect();
    }
}
