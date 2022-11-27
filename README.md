# Auth using Biscuit

> Example application using biscuit

## Endpoints

1. `login` -> authenticate and receive a biscuit token in a cookie
1. `validate` -> check if token is valid
1. `register` -> create user
1. `test/is_auth` -> returns 401 when no token present, 403 invalid creds or 200
1. `test/is_anon` -> returns always 200
1. `test/anon_and_auth` -> returns user if auth


## Login workflow

```mermaid
sequenceDiagram
    actor user
    participant browser
    user->>+auth: POST /login (user+pass)
    auth->>-browser: set session cookie
    browser->>+auth: /hello (with cookie)
    auth->>-browser: ok
```