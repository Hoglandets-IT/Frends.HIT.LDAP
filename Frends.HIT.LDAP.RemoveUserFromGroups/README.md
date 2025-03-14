# Frends.HIT.LDAP.RemoveUserFromGroups
Frends LDAP task to remove a user from Active Directory groups.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT) 
[![Build](https://github.com/FrendsPlatform/Frends.HIT.LDAP/actions/workflows/RemoveUserFromGroups_build_and_test_on_main.yml/badge.svg)](https://github.com/FrendsPlatform/Frends.HIT.LDAP/actions)
![MyGet](https://img.shields.io/myget/frends-tasks/v/Frends.HIT.LDAP.RemoveUserFromGroups)
![Coverage](https://app-github-custom-badges.azurewebsites.net/Badge?key=FrendsPlatform/Frends.HIT.LDAP/Frends.HIT.LDAP.RemoveUserFromGroups|main)

# Installing

You can install the Task via Frends UI Task View or you can find the NuGet package from the following NuGet feed https://www.myget.org/F/frends-tasks/api/v2.

## Building


Rebuild the project

`dotnet build`

Run tests

 Create a simple LDAP server to docker:
 `docker run -d -it --rm -p 10389:10389 dwimberger/ldap-ad-it`
 
`dotnet test`


Create a NuGet package

`dotnet pack --configuration Release`
