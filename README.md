# DAuth

This project contains commonly used authentication packages of DEXPRO services.
Most of the code you find here is probably only usable in the context of DEXPRO applications.

We do not recommend using anything from this module if you are not working on an official project
of the DEXPRO software development team.

## Motivation

Generally, using OAuth 2 to secure an application is possible with well-known and maintained packages
in the Golang ecosystem. There should not be a need to maintain a custom OAuth solution for securing an API.

This package however solves a problem which is specific to DEXPRO software: **Securing an API with multiple OAuth servers**

The current OAuth archictecture of DEXPRO relies on Keycloak Realms, separating customers with one realm per customer.
The challenge with this is that each realm has a dedicated cryptography key used for JWT token signing and validation.
Implementing an API middleware which still allows access to all customers is why this package was created.

The second use case for this package is sharing _Claim_ types across applications.
