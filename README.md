[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![GitHub Issues](https://img.shields.io/github/issues/Kronos-Integration/service-authenticator.svg?style=flat-square)](https://github.com/Kronos-Integration/service-authenticator/issues)
[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2FKronos-Integration%2Fservice-authenticator%2Fbadge\&style=flat)](https://actions-badge.atrox.dev/Kronos-Integration/service-authenticator/goto)
[![Styled with prettier](https://img.shields.io/badge/styled_with-prettier-ff69b4.svg)](https://github.com/prettier/prettier)
[![Commitizen friendly](https://img.shields.io/badge/commitizen-friendly-brightgreen.svg)](http://commitizen.github.io/cz-cli/)
[![Known Vulnerabilities](https://snyk.io/test/github/Kronos-Integration/service-authenticator/badge.svg)](https://snyk.io/test/github/Kronos-Integration/service-authenticator)
[![Coverage Status](https://coveralls.io/repos/Kronos-Integration/service-authenticator/badge.svg)](https://coveralls.io/github/Kronos-Integration/service-authenticator)

# @kronos-integration/service-authentication

authentication providing service

# usage

# API

<!-- Generated by documentation.js. Update this documentation by updating the source code. -->

### Table of Contents

*   [JWTResponse](#jwtresponse)
    *   [Properties](#properties)
*   [ServiceAuthenticator](#serviceauthenticator)
    *   [changePasswordEndpoints](#changepasswordendpoints)
    *   [authEndpoints](#authendpoints)
    *   [accessTokenGenerator](#accesstokengenerator)
        *   [Parameters](#parameters)
    *   [name](#name)

## JWTResponse

Type: [Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)

### Properties

*   `access_token` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)**&#x20;
*   `refresh_token` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)**&#x20;
*   `token_type` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** always "Bearer"
*   `expires_in` **[number](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Number)** seconds the access token is valid

## ServiceAuthenticator

**Extends Service**

### changePasswordEndpoints

Endpoints used to send password change requests to.

### authEndpoints

Endpoints used to send authentication requests to.

### accessTokenGenerator

Generate a request handler to deliver JWT access tokens.

#### Parameters

*   `credentials` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)**&#x20;

    *   `credentials.username` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)**&#x20;
    *   `credentials.password` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)**&#x20;

Returns **[JWTResponse](#jwtresponse)** jwt

### name

Returns **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** 'authenticator'
