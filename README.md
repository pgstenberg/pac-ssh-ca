# Simple SSH CA

Simple SSH CA is a lightweight OpenSSH certificate authority written in golang.
Simple SSH CA can issue both _user_ and _host_ certificate types according to the [openssh specification](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?rev=1.8) using a policy-based authorization control.
Currently the following policy engines are supported.

- [Open Policy Agent](https://www.openpolicyagent.org/)

## Motivation

Using certificates for openssh is unarguably the safest way of handling ssh permissions.
But issuing OpenSSH Certificates are hard, especially with a dedicated certificate authority.
By creating an application that makes this process as simple and effective as possible will reduce the risk that the use of openssh certificate is ignored.

The key components for a simple yet effective openssh certificate implementation:

- The solution should be lightweight and stateless.
- Existing solutions should be used in order to distribute and authorize the access.
- The client and hosts should **not** require any additional cli or tools to be installed.

## How it works

### Host Certificates

```mermaid
sequenceDiagram
    participant Host
    participant CA
    participant CM

    CM->>CA: Public Key (Trusted Delegate) + Host
    activate CM
    activate CA
    CA-->>CM: Ticket (Host bound)
    deactivate CA
    CM->>Host: Ticket
    deactivate CM
    activate Host
    loop Renew Certificate
        Host->>CA: Public Key (Host) + Ticket
        activate CA
        Note right of CA: Policy Enforcement
        CA-->>Host: Host Certificate
        deactivate CA
    end
    deactivate Host
```

### User Certificates

```mermaid
sequenceDiagram
    participant User
    participant CA
    participant OIDCP

    User->>CA: Public Key
    activate CA
    activate User
    CA-->>User: Login URL + State (Public Key Bound)
    deactivate CA
    User->>OIDCP: Login
    activate OIDCP
    Note over User,OIDCP: Web Browser (SSO)
    OIDCP-->>CA: Identity
    deactivate OIDCP
    activate CA
    CA-->>User: Ticket (State bound)
    User->>CA: Ticket + Public Key
    Note right of CA: Policy Enforcement
    CA-->>User: User Certificate
    deactivate CA
    deactivate User
```

## Examples

- [Ansible](examples/ansible/README.md)