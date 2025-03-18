# Changelog

## [2.1.0] - 2025-01-02
### Fixed
- Fixed issue with AttributeSet not having all values that were returned from LDAP search.

## [2.0.0] - 2024-11-06
### Added
- [Breaking] Parameter for AnonymousBind to enable to connect without credentials.
- [Breaking] Parameter for LDAPProtocolVersion to choose what LDAP version should be used.
- Default values for new parameters are:
  - AnonymousBind: false
  - LDAPProtocolVersion: 3
- Use the default parameters if you want the Task to work as before.

- Check for Filter parameter that it's not empty and set null to it if it is so that the library sets objectClass=* as the filter.

## [1.0.0] - 2022-10-03
### Added
- Initial implementation