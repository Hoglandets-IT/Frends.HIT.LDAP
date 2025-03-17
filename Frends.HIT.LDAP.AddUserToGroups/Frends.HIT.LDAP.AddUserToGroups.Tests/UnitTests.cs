namespace Frends.HIT.LDAP.AddUserToGroups.Tests;

using NUnit.Framework;
using Frends.HIT.LDAP.AddUserToGroups.Definitions;
using Novell.Directory.Ldap;

[TestFixture]
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
    private readonly string? _groupDn = "cn=admin,ou=roles,dc=wimpi,dc=net";
    private readonly string _testUserDn = "CN=Test User,ou=users,dc=wimpi,dc=net";

    private Input? input;
    private Connection? connection;

    [SetUp]
    public void SetUp()
    {
        connection = new()
        {
            Host = _host,
            User = _user,
            Password = _pw,
            SecureSocketLayer = false,
            Port = _port,
            TLS = false,
        };

        CreateTestUser(_testUserDn);
    }

    [TearDown]
    public void Teardown()
    {
        DeleteTestUsers(_testUserDn, "CN=admin,ou=roles,dc=wimpi,dc=net");
    }

    [Test]
    public void Update_HandleLDAPError_Test()
    {
        input = new()
        {
            UserDistinguishedName = "CN=Common Name,CN=Users,DC=Example,DC=Com",
            GroupDistinguishedName = "CN=Admins,DC=Example,DC=Com",
            UserExistsAction = UserExistsAction.Throw,
        };

        var ex = Assert.Throws<Exception>(() => LDAP.AddUserToGroups(input, connection, default));
        Assert.IsTrue(ex.Message.Contains("No Such Object"));
    }

    [Test]
    public void AddUserToGroups_Test()
    {
        input = new()
        {
            UserDistinguishedName = _testUserDn,
            GroupDistinguishedName = _groupDn,
            UserExistsAction = UserExistsAction.Throw,
        };

        var result = LDAP.AddUserToGroups(input, connection, default);
        Assert.IsTrue(result.Success);
    }

    [Test]
    public void AddUserToGroups_TestWithUserExisting()
    {
        input = new()
        {
            UserDistinguishedName = _testUserDn,
            GroupDistinguishedName = _groupDn,
            UserExistsAction = UserExistsAction.Throw,
        };

        var result = LDAP.AddUserToGroups(input, connection, default);
        Assert.IsTrue(result.Success);

        var ex = Assert.Throws<Exception>(() => LDAP.AddUserToGroups(input, connection, default));
        Assert.AreEqual("AddUserToGroups LDAP error: Attribute Or Value Exists", ex.Message);
    }

    [Test]
    public void AddUserToGroups_TestWithUserExistingWithSkip()
    {
        input = new()
        {
            UserDistinguishedName = _testUserDn,
            GroupDistinguishedName = _groupDn,
            UserExistsAction = UserExistsAction.Skip,
        };

        var result = LDAP.AddUserToGroups(input, connection, default);
        Assert.IsTrue(result.Success);

        input.UserExistsAction = UserExistsAction.Skip;

        result = LDAP.AddUserToGroups(input, connection, default);
        Assert.IsFalse(result.Success);
    }

    private void CreateTestUser(string userDn)
    {
        using LdapConnection conn = new()
        {
            SecureSocketLayer = false,
        };
        conn.Connect(_host, _port);
        conn.Bind(_user, _pw);

        var attributeSet = new LdapAttributeSet
        {
            new LdapAttribute("objectclass", "inetOrgPerson"),
            new LdapAttribute("cn", "Test User"),
            new LdapAttribute("givenname", "Test"),
            new LdapAttribute("sn", "User"),
        };

        LdapEntry newEntry = new(userDn, attributeSet);
        conn.Add(newEntry);
        conn.Disconnect();
    }

    private void DeleteTestUsers(string userDn, string groupDn)
    {
        using LdapConnection conn = new();
        conn.Connect(_host, _port);
        conn.Bind(_user, _pw);

        ILdapSearchResults searchResults = conn.Search(
                groupDn,
                LdapConnection.ScopeSub,
                "(objectClass=*)",
                null,
                false);

        LdapEntry groupEntry = searchResults.Next();

        var remove = false;

        LdapAttribute memberAttr = groupEntry.GetAttribute("member");
        var currentMembers = memberAttr.StringValueArray;
        if (currentMembers.Where(e => e == userDn).Any())
            remove = true;

        if (remove)
        {
            // Remove the user from the group
            var mod = new LdapModification(LdapModification.Delete, new LdapAttribute("member", userDn));
            conn.Modify(groupDn, mod);
        }

        conn.Delete(userDn);

        // Disconnect from the LDAP server
        conn.Disconnect();
    }
}
