# TYPO3 OpenID Connect integration changelog

## Version 3.x

* Dropped direct felogin-integration.
  Please use the `OidcLinkViewHelper` instead, if you previously relied on the `{openidConnectUri}` variable in your template.

## Version 2.x

* Enhanced events to include a reference to the AuthenticationService [#136](https://github.com/xperseguers/t3ext-oidc/issues/136)
