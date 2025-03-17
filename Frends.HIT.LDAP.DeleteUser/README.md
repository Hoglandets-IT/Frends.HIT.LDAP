# Frends.LDAP.DeleteUser
Frends LDAP task to delete a user from Active Directory.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT) 
[![Build](https://github.com/FrendsPlatform/Frends.LDAP/actions/workflows/DeleteUser_build_and_test_on_main.yml/badge.svg)](https://github.com/FrendsPlatform/Frends.LDAP/actions)
![MyGet](https://img.shields.io/myget/frends-tasks/v/Frends.LDAP.DeleteUser)
![Coverage](https://app-github-custom-badges.azurewebsites.net/Badge?key=FrendsPlatform/Frends.LDAP/Frends.LDAP.DeleteUser|main)

# Installing

You can install the Task via frends UI Task View or you can find the NuGet package from the following NuGet feed https://www.myget.org/F/frends-tasks/api/v2.

## Building


Rebuild the project

`dotnet build`

Run tests

 Create a simple LDAP server to docker:
 `docker run -d -it --rm -p 10389:10389 dwimberger/ldap-ad-it`
 
`dotnet test`


Create a NuGet package

`dotnet pack --configuration Release`