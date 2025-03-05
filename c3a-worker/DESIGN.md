# C3A Design

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant DB as Database

    C->>C: Generate Dilithium5 client keypair (public, private)
    S->>S: Generate Dilithium5 C3A keypair (public, private)
    C->>S: POST /login (username, password, client's public key, token_preference=cookies|headers)
    S->>DB: Verify credentials
    DB-->>S: Credentials valid
    S->>DB: Store client's public key with client_id
    S->>S: Generate MPAAT' access and refresh tokens and sign with C3A private key
    S->>DB: Store refresh_token (client_id, expires_at)
    alt token_preference = "cookies"
        S-->>C: 200 OK, Set-Cookie: access_token=<MPAAT>, refresh_token=<new>
    else token_preference = "headers"
        S-->>C: 200 OK (MsgPack: access_token=<MPAAT>, refresh_token=<new>)
    end
```

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant DB as Database
    
    C->>S: GET /authorized (Authorization: Bearer <access_token>|Cookie <access_token>)
    S->>S: Check authorization scheme for this site path
    S->>S: Verify only access_token (MPAAT's sign, expiry)
    S-->>C: 200 OK (protected data)
```

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant DB as Database
    
    C->>C: Sign request hash with client's private key (4595 bytes)
    C->>S: GET /protected (Authorization: Bearer <access_token>|Cookie <access_token>, C3A-Sign: <client's signature>)
    S->>S: Check authorization scheme for this site path
    S->>S: Verify access_token (MPAAT's sign, expiry)
    S->>DB: Get Dilithium5 public key for client
    DB-->>S: Public key
    S->>S: Verify Dilithium5 signature
    S-->>C: 200 OK (highly protected data)
```

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant DB as Database
    
    C->>S: POST /refresh (Authorization: Bearer <refresh-token>)
    S->>DB: Check refresh_token (valid, not revoked)
    DB-->>S: Refresh token valid
    S-->>C: 200 OK (new access_token, [new refresh_token])
```

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant DB as Database
    
    C->>S: POST /some-request (Authorization: Cookie <access_token>, Cookie <refresh-token>)
    S->>S: Check authorization scheme for this site path
    S->>S: Verify access_token (MPAAT's sign, expiry) - EXPIRED
    S->>DB: Check refresh_token (valid, not revoked)
    DB-->>S: Refresh token valid
    S-->>C: 200 OK, Set-Cookie: access_token=<MPAAT>, refresh_token=<new>
```

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant DB as Database
    
    C->>S: POST /logout (C3A-Refresh: <token>|Cookie <refresh-token>)
    S->>DB: Revoke refresh_token and client's public key
    DB-->>S: Revoked
    S-->>C: 200 OK (logged out)
```

1. Процесс регистрации.

Пользователь должен получить:

- способ идентификации
- возможные варианты формирования потока аутентификации

Пользователь должен предоставить:

- email или никнейм (в зависимости от настроек приложения) ([x] в настройках сделано)
- набор факторов аутентификации (настройки приложения определяют число + число разных, обязательные варианты и варианты на выбор)
