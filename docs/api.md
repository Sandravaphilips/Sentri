# Sentri API Overview

This document provides a **high-level overview** of Sentri’s API for programmatic use. It is intentionally minimal.

## Authentication

Sentri APIs require authenticated access.

Depending on the endpoint, clients authenticate using:
- access tokens, or
- API keys intended for programmatic access

Authentication and authorization are enforced per endpoint. Error responses are generic.

## API Keys

API keys support non-interactive access.

At a high level:
- Keys are created by authenticated users
- Keys may have scopes and expiration
- Keys can be revoked
- Secrets are shown only at creation time

Keys cannot be retrieved after creation.

## Public API Surface

The following endpoints represent Sentri’s intended public API surface:

| Endpoint | Purpose |
|--------|--------|
| `/api/auth/login/` | Authenticate and obtain access |
| `/api/keys/` | Manage API keys |
| `/api/security/events/` | View security-related events |

Endpoints not listed here are considered internal.

## Requests & Errors

- Requests and responses use JSON
- Standard HTTP status codes are used
- Error messages avoid exposing security details

## Scope

The Sentri API is part of a personal learning project and may change over time.
