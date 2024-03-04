
<img align="right" width="50" height="50" src="docs/image.png">

# Grafana Auth Reverse Proxy


## Overview
Grafana Auth Reverse Proxy is a tool designed to enhance the authentication and authorization mechanisms of Grafana. It integrates OpenID Connect (OIDC) for authentication and manages user access and roles within Grafana based on JWT tokens (oAuth2). This proxy serves as a secure gateway, controlling access to Grafana dashboards and data.

## Features
- **OIDC Authentication**: Integrates with OIDC providers for secure user authentication.
- **Reverse Proxy Functionality**: Forwards requests to Grafana, adding enhanced authentication and authorization.
- **Grafana User and Organization Synchronization**: Syncs user and organization data between OIDC and Grafana.
- **Environment Variable Configuration**: Offers flexible configuration through environment variables.

## Getting Started

### Prerequisites
- Go (version 1.x or later)
- Basic understanding OIDC, oAuth2 and Reverse Proxy
- Grafana instance configured with Auth Proxy

### Installation
Clone the repository:
```bash
git clone https://gitlab.pnet.ch/zengeriv/grafana-auth-reverse-proxy.git
```
Navigate to the project directory and build the project:
```bash
cd grafana-auth-reverse-proxy
go build .
```

### Configuration
Configure the application using environment variables or a configuration file. The main configurations include:

- **Server Configuration**: Set endpoints, port, and other server-related settings.
- **Token Configuration**: Configure token path and access token cookie name.
- **OIDC Configuration**: Set up the OIDC redirect URL, client ID, client secret, issuer, and scopes.
- **Proxy Configuration**: Define the target URL for the reverse proxy.

Refer to the struct field descriptions in the source code for detailed configuration options.

To provide a comprehensive overview of all configuration options across different structs (`Server`, `TokenConfig`, `Oidc`, `Proxy`, `Grafana`), I will create tables for each struct that outline the available options, including their corresponding command-line flags, environment variables, descriptions, default values, and requirements.


## Usage
Start the application with the configured environment variables:
```bash
./grafana-auth-reverse-proxy
```

### Global Command Arguments
<details> 
<summary>Click to expand</summary>

| Command Line Flag | Environment Variable | Description | Default Value | Required |
| ----------------- | -------------------- | ----------- | ------------- | -------- |
| (No direct flag for `Run`) | (No direct ENV for `Run`) | Start the Grafana Auth Reverse Proxy server with the specified configurations. | (Not applicable) | No |
| --debug | GLOBALS_DEBUG | Set debug log level. | `false` | No |
| --version | GLOBALS_VERSION | Show version information and exit. | (Not applicable) | No |

</details>

### `./grafana-auth-reverse-proxy run`

To run the Grafana Auth Reverse Proxy, use the `run` command with appropriate flags or environment variables.

#### Synopsis

```sh
./grafana-auth-reverse-proxy run [flags]
```

#### Examples

```sh
# Start with default settings
./grafana-auth-reverse-proxy run

# Start with a custom port and debug mode enabled
./grafana-auth-reverse-proxy run --port=8085 --debug

# Using environment variables
export PORT=8085
export DEBUG=true
./grafana-auth-reverse-proxy run
```

### Command Arguments

<details>
<summary>Click to expand</summary>

#### Server Struct

| Command Line Flag | Environment Variable     | Description | Default Value | Required |
| ----------------- |--------------------------| ----------- | ------------- | -------- |
| --callback-endpoint | SERVER_CALLBACK_ENDPOINT | Endpoint for OIDC callback. | `/callback` | No |
| --auth-endpoint | SERVER_AUTH_ENDPOINT            | Endpoint for initiating authentication. | `/auth` | No |
| --port | SERVER_PORT                     | The port on which the server listens. | `8082` | No |
| --secure | SERVER_SECURE                   | Flag to enable secure cookies. | `true` | No |
| --root-url | SERVER_ROOT_URL                 | The root URL of the server. | `http://e1-zengeriv-alsu001:8082/` | No |
| --sleep-before-redirect | SERVER_SLEEP_BEFORE_REDIRECT    | Delay before redirecting after authentication. | `1` (second) | No |

#### TokenConfig Struct

| Command Line Flag | Environment Variable | Description | Default Value | Required |
| ----------------- | -------------------- | ----------- | ------------- | -------- |
| --token-path | TOKEN_CONFIG_TOKEN_PATH | Path to the token in the authentication response. | `id_token` | No |
| --access-token-cookie-name | TOKEN_CONFIG_ACCESS_TOKEN_COOKIE_NAME | Name of the cookie to store the access token. | `x-access-token` | No |

#### Oidc Struct

| Command Line Flag | Environment Variable | Description | Default Value | Required |
| ----------------- | -------------------- | ----------- | ------------- | -------- |
| --redirect-url | OIDC_REDIRECT_URL | URL to redirect after successful OIDC authentication. | `http://localhost:8082/callback` | No |
| --client-id | OIDC_CLIENT_ID | Client ID for OIDC provider. | `grafana` | No |
| --client-secret | OIDC_CLIENT_SECRET | Client Secret for OIDC provider. | `Z7J9KjZUI1LiUDMKKrNCLuewY7DWgDsU` | Yes |
| --issuer | OIDC_ISSUER | URL of the OIDC issuer. | `http://e1-zengeriv-alsu001:8080/realms/master` | No |
| --scopes | OIDC_SCOPES | Scopes requested from OIDC provider. | `openid,email,roles,profile` | No |
| --jwks-url | OIDC_JWKS_URL | URL to the JWKS endpoint for token validation. | `http://e1-zengeriv-alsu001.pnet.ch:8080/realms/master/protocol/openid-connect/certs` | No |

#### Proxy Struct

| Command Line Flag | Environment Variable | Description | Default Value | Required |
| ----------------- | -------------------- | ----------- | ------------- | -------- |
| --target | PROXY_TARGET | Target URL for the reverse proxy. | `http://e1-zengeriv-alsu001:8081/` | No |

#### Grafana Struct

| Command Line Flag | Environment Variable | Description | Default Value | Required |
| ----------------- | -------------------- | ----------- | ------------- | -------- |
| --admin-user | PROXY_ADMIN_USER | Admin username for Grafana. | `admin` | No |
| --org-attribute-path | PROXY_ORG_ATTRIBUTE_PATH | Path to the organization attribute in the token. | `groups` | No |
| --mapping-config-file | PROXY_MAPPING_CONFIG_FILE | Path to the organization mapping configuration file. | `./testdata/mapping.yml` | No |
| --role-attribute-path | PROXY_ROLE_ATTRIBUTE_PATH | JMESPath expression for role extraction from token. | `contains(groups[*], 'auth.strong') && 'Admin' || 'Editor' || 'Viewer'` | No |
| --sync-login-or-email-claim-attribute | PROXY_SYNC_LOGIN_OR_EMAIL_CLAIM_ATTRIBUTE | Claim attribute for syncing login or email. | `preferred_username` | No |
| --sync-email-claim-attribute | PROXY_SYNC_EMAIL_CLAIM_ATTRIBUTE | Claim attribute for syncing email. | `email` | No |
| --sync-name-claim-attribute | PROXY_SYNC_NAME_CLAIM_ATTRIBUTE | Claim attribute for syncing name. | `name` | No |
| --header-name-login-or-email | PROXY_HEADER_NAME_LOGIN_OR_EMAIL | Header name for passing login or email. | `X-WEBAUTH-USER` | No |
| --header-name-name | PROXY_HEADER_NAME_NAME | Header name for passing the user's name. | `X-WEBAUTH-NAME` | No |
| --header-name-email | PROXY_HEADER_NAME_EMAIL | Header name for passing the user's email. | `X-WEBAUTH-EMAIL` | No |
| --header-name-role | PROXY_HEADER_NAME_ROLE | Header name for passing the user's role.|

</details>

## Development and Contribution
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a feature branch: `git checkout -b new-feature`
3. Commit your changes: `git commit -am 'Add a new feature'`
4. Push to the branch: `git push origin new-feature`
5. Submit a pull request.

### Code Structure
- `cmd`: CLI command definitions and handling.
- `config`: Configuration structs and loaders.
- `grafana`: Grafana API integration and utilities.
- `jwks`: JWT token parsing and JWKS handling.
- `middleware`: Echo server middleware functions.
- `proxy`: Reverse proxy setup and handling.
- `utlis`: Utility functions for common operations.

