using Microsoft.VisualStudio.TestTools.UnitTesting;
using Frends.HIT.LDAP.RemoveUserFromGroups.Definitions;
using Novell.Directory.Ldap;
namespace Frends.HIT.LDAP.RemoveUserFromGroups.Tests;

[TestClass]
public class UnitTests
{
    /*
        LDAP server to docker.
        docker run -d -it --rm -p 10389:10389 dwimberger/ldap-ad-it
    */
    private readonly string? _host = "127.0.0.1";
    private readonly int _port = 10389;
    private readonly string? _user = "uid=admin,ou=system";
    private readonly string? _pw = "secret";
    private readonly string _path = "ou=users,dc=wimpi,dc=net";
    private readonly string? _groupDn = "cn=admin,ou=roles,dc=wimpi,dc=net";

    Input? input;
    Connection? connection;

    [TestMethod]
    public void Update_HandleLDAPError_Throw_Test()
    {
        var tuser = "Tes Tuser" + Guid.NewGuid().ToString();
        var dn = $"CN={tuser},{_path}";
        CreateTestUsers(tuser);

        input = new()
        {
            UserDistinguishedName = dn,
            GroupDistinguishedName = _groupDn,
            HandleLDAPError = HandleLDAPError.Throw
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

        var ex = Assert.ThrowsException<Exception>(() => LDAP.RemoveUserFromGroups(input, connection));
        Assert.IsTrue(ex.Message != null);
    }

    [TestMethod]
    public void Update_HandleLDAPError_Skip_Test()
    {
        var tuser = "Tes Tuser" + Guid.NewGuid().ToString();
        var dn = $"CN={tuser},{_path}";
        CreateTestUsers(tuser);

        input = new()
        {
            UserDistinguishedName = dn,
            GroupDistinguishedName = _groupDn,
            HandleLDAPError = HandleLDAPError.Skip
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

        var result = LDAP.RemoveUserFromGroups(input, connection);
        Assert.IsTrue(result.Success.Equals(false) && result.Error != null);
    }

    [TestMethod]
    public void RemoveUserFromGroups_Test()
    {
        var tuser = "Tes Tuser" + Guid.NewGuid().ToString();
        var dn = $"CN={tuser},{_path}";
        CreateTestUsers(tuser);
        AddUserToGroup(dn);

        input = new()
        {
            UserDistinguishedName = dn,
            GroupDistinguishedName = _groupDn
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

        var result = LDAP.RemoveUserFromGroups(input, connection);
        Assert.IsTrue(result.Success.Equals(true));
    }

    public void CreateTestUsers(string tuser)
    {
        try
        {
            LdapConnection conn = new();
            conn.Connect(_host, _port);
            conn.Bind(_user, _pw);

            var attributeSet = new LdapAttributeSet();
            attributeSet.Add(new LdapAttribute("objectclass", "inetorgperson"));
            attributeSet.Add(new LdapAttribute("cn", tuser));
            attributeSet.Add(new LdapAttribute("givenname", "Tes"));
            attributeSet.Add(new LdapAttribute("sn", tuser.Split(' ', 1)));

            var entry = $"CN={tuser},{_path}";
            LdapEntry newEntry = new(entry, attributeSet);
            conn.Add(newEntry);
            conn.Disconnect();
        }
        catch (Exception)
        {
        }
    }

    public void AddUserToGroup(string dn)
    {
        try
        {
            LdapConnection conn = new();
            conn.Connect(_host, _port);
            conn.Bind(_user, _pw);

            LdapModification[] mods = new LdapModification[1];
            var member = new LdapAttribute("member", dn);
            mods[0] = new LdapModification(LdapModification.Add, member);
            conn.Modify(_groupDn, mods);
            conn.Disconnect();
        }
        catch (Exception)
        {
        }
    }
}
