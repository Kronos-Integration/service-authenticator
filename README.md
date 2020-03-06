[![npm](https://img.shields.io/npm/v/@kronos-integration/service-authenticator.svg)](https://www.npmjs.com/package/@kronos-integration/service-authenticator)
[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)
[![minified size](https://badgen.net/bundlephobia/min/@kronos-integration/service-authenticator)](https://bundlephobia.com/result?p=@kronos-integration/service-authenticator)
[![downloads](http://img.shields.io/npm/dm/@kronos-integration/service-authenticator.svg?style=flat-square)](https://npmjs.org/package/@kronos-integration/service-authenticator)
[![GitHub Issues](https://img.shields.io/github/issues/Kronos-Integration/service-authenticator.svg?style=flat-square)](https://github.com/Kronos-Integration/service-authenticator/issues)
[![Build Status](https://secure.travis-ci.org/Kronos-Integration/service-authenticator.png)](http://travis-ci.org/Kronos-Integration/service-authenticator)
[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/Kronos-Integration/service-authenticator)
[![styled with prettier](https://img.shields.io/badge/styled_with-prettier-ff69b4.svg)](https://github.com/prettier/prettier)
[![Commitizen friendly](https://img.shields.io/badge/commitizen-friendly-brightgreen.svg)](http://commitizen.github.io/cz-cli/)
[![Known Vulnerabilities](https://snyk.io/test/github/Kronos-Integration/service-authenticator/badge.svg)](https://snyk.io/test/github/Kronos-Integration/service-authenticator)
[![codecov.io](http://codecov.io/github/Kronos-Integration/service-authenticator/coverage.svg?branch=master)](http://codecov.io/github/Kronos-Integration/service-authenticator?branch=master)
[![Coverage Status](https://coveralls.io/repos/Kronos-Integration/service-authenticator/badge.svg)](https://coveralls.io/r/Kronos-Integration/service-authenticator)

# @kronos-integration/service-authentication

authentication providing service

# usage

# API

<!-- Generated by documentation.js. Update this documentation by updating the source code. -->

### Table of Contents

-   [JWTResponse](#jwtresponse)
    -   [Properties](#properties)
-   [ServiceAuthenticator](#serviceauthenticator)
    -   [accessTokenGenerator](#accesstokengenerator)
        -   [Parameters](#parameters)

## JWTResponse

Type: [Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)

### Properties

-   `acess_token` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** 
-   `token_type` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** always "Bearer"

## ServiceAuthenticator

**Extends Service**

### accessTokenGenerator

Generate a request handler to deliver JWT access tokens

#### Parameters

-   `credentials` **[Object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)** 
    -   `credentials.username` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** 
    -   `credentials.password` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** 

Returns **[JWTResponse](#jwtresponse)** jwt
