# Texas 🤠

Texas is _Token Exchange as a Service_.

```text
       ____
      !     !
      !     !
      !      `-  _ _    _ 
      |              ```  !      _
 _____!                   !     | |
 \,                        \    | |_ _____  ____ _ ___
   l    _                  ;    | __/ _ \ \/ / _` / __|
    \ _/  \.              /     | ||  __/>  < (_| \__ \
            \           .’       \__\___/_/\_\__,_|___/
             .       ./’
              `.    ,
                \   ;
                  ``’
```

Texas implements various OAuth 2 flows and grants for relying parties, so that you don't have to.
It supports (a subset of):

- [RFC 6749, section 4.4: OAuth 2.0 Client Credentials Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)
- [RFC 8693: OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) / [Entra ID On-Behalf-Of flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow)
- [RFC 7662: OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [RFC 7523: OAuth 2.0 JWT Profile for Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523)

It is designed to run as a [sidecar container](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/) in Kubernetes environments.

> [!TIP]
> Looking for something that handles OpenID Connect (OIDC) for end-user authentication?
> 
> Check out [nais/wonderwall](https://github.com/nais/wonderwall).

## Quick start

See [the `.env.example` file](.env.example) for available configuration options.
To set up a local environment based on this, run:

```shell
make setup
```

Start a mock OAuth 2 server with:

```shell
docker-compose up -d
```

Run Texas:

```shell
make local
```

[The `hack/` directory](./hack) contains example snippets with requests that you can run with `curl`.
Run all of them with:

```shell
make test_roundtrip
```

> [!TIP]
> See [nais/wonderwalled](https://github.com/nais/wonderwalled) for an example downstream application that uses Texas.

## Supported providers

Texas is currently tailored for use with a subset of authorization servers and providers, namely:

- [Entra ID (formerly known as Azure AD)](https://learn.microsoft.com/en-us/entra/identity-platform/v2-overview)
- [ID-porten](https://docs.digdir.no/docs/idporten/idporten/idporten_overordnet.html)
- [Maskinporten](https://docs.digdir.no/docs/Maskinporten/maskinporten_overordnet)
- [TokenX / Tokendings](https://github.com/nais/tokendings)

Support for other providers currently requires changes to the codebase.

## How it works

Texas abstracts away and handles the boring parts of OAuth 2 and JWTs.
It does this by offering a simple API for acquiring, exchanging, and introspecting tokens.

For further details, see the [OpenAPI specification](./doc/openapi-spec.json)
([view in Swagger Editor](https://editor-next.swagger.io/?url=https://raw.githubusercontent.com/nais/texas/refs/heads/master/doc/openapi-spec.json)).

### `/api/v1/token`

Acquires a access token for machine-to-machine use.
The grant used depends on the identity provider:

- For Entra ID, the [client credentials grant](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow) is used.
- For Maskinporten, the [JWT authorization grant](https://docs.digdir.no/docs/Maskinporten/maskinporten_protocol_token) is used.

Example request:

```http
POST /api/v1/token
Content-Type: application/json

{
  "identity_provider": "maskinporten",
  "target": "some-scope"
}
```

Example response:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "access_token": "<some-access-token>",
  "expires_in": 3599,
  "token_type": "Bearer"
}
```

### `/api/v1/token/exchange`

Exchanges a subject token (typically an access token for an end-user) for a new machine token.
The grant used depends on the identity provider:

- For Entra ID, the [on-behalf-of flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow) (which is loosely based on the token exchange grant) is used.
- For TokenX / Tokendings, the [token exchange grant](https://github.com/nais/tokendings?tab=readme-ov-file#usage) is used.

```http
POST /api/v1/token/exchange
Content-Type: application/json

{
  "identity_provider": "tokenx",
  "user_token": "<some-subject-token>",
  "target": "some-other-client"
}
```

Example response:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "access_token": "<some-access-token>",
  "expires_in": 3599,
  "token_type": "Bearer"
}
```

### `/api/v1/introspect`

Introspects a token in JWT form by performing validation of its standard claims and signature.
Loosely based on [RFC 7662, section 2](https://datatracker.ietf.org/doc/html/rfc7662#section-2).

If valid, the token's claims are returned as JSON.

```http
POST /api/v1/introspect
Content-Type: application/json

{
  "identity_provider": "tokenx",
  "token": "<some-access-token>"
}
```

Example response:

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "active": true,
  "aud": "my-target",
  "azp": "yolo",
  "exp": 1730980893,
  "iat": 1730977293,
  "iss": "http://localhost:8080/tokenx",
  "jti": "e7cbadc3-6bda-49c0-a196-c47328da880e",
  "nbf": 1730977293,
  "sub": "e015542c-0f81-40f5-bbd9-7c3d9366298f",
  "tid": "tokenx"
}
```

Only the standard claims defined in [RFC 7519, section 4.1](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1) are validated.
Validation of other claims is the responsibility of the downstream application.

The following claims must always be present and valid:

- The `iss` claim must exist and must match the expected issuer.
- The `iat` claim must exist and its value be in the past.
- The `exp` claim must exist and its value be in the future.

For most providers, the `aud` claim must be present and match the expected audience (often the client ID).
The `aud` claim is not validated for tokens from Maskinporten, as they do not contain the `aud` claim by default.

The `nbf` claim, if set, must be in the past.

### Client authentication

Texas handles client authentication with the identity provider for you.
Your application doesn't need to know about or handle any credentials.

Texas uses JWTs for client authentication with the respective authorization servers, as defined in [RFC 7523, section 2.2](https://datatracker.ietf.org/doc/html/rfc7523#section-2.2).
This is also known as the `private_key_jwt` client authentication method.
Using client secrets is not supported.

## Development

### Run tests

```shell
make check
```

### Generate OpenAPI spec

If you've modified the API specifications, you should regenerate the OpenAPI spec:

```shell
make openapi
```

Commit and push the changes.
