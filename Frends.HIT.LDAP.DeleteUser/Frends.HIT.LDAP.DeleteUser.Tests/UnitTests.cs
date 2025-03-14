using Microsoft.VisualStudio.TestTools.UnitTesting;
using Frends.LDAP.DeleteUser.Definitions;
using Novell.Directory.Ldap;
namespace Frends.LDAP.DeleteUser.Tests;

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
    private readonly string _commonName = "Test User";

    Input? input;
    Connection? connection;

    [TestMethod]
    public void Create_HandleLDAPError_Test()
    {
        input = new()
        {
            Path = _path,
            CommonName = "Fail" + new Guid(),
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

        var result = LDAP.DeleteUser(input, connection);
        Assert.IsTrue(result.Success.Equals(false) && result.Error.Contains("No Such Object"));
    }

    [TestMethod]
    public void DeleteUser_Test()
    {
        CreateTestUser();

        input = new()
        {
            Path = _path,
            CommonName = _commonName,
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

        var result = LDAP.DeleteUser(input, connection);
        Assert.IsTrue(result.Success.Equals(true));
    }

    public void CreateTestUser()
    {
        var entry = $"CN={_commonName},{_path}";

        LdapConnection conn = new();
        conn.Connect(_host, _port);
        conn.Bind(_user, _pw);

        LdapAttributeSet attributeSet = new();
        attributeSet.Add(new LdapAttribute("objectclass", "inetOrgPerson"));
        attributeSet.Add(new LdapAttribute("cn", _commonName));
        attributeSet.Add(new LdapAttribute("givenname", "Test"));
        attributeSet.Add(new LdapAttribute("sn", "User"));

        LdapEntry newEntry = new(entry, attributeSet);
        conn.Add(newEntry);
        conn.Disconnect();
    }
}

