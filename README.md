# Sentri
Sentri is a security-focused Django project I built while exploring how real systems handle authentication, API access, and security events.

The goal was to learn by building and to experiment with security patterns in a realistic setup.

## What it covers

Sentri focuses on a few core ideas:

- User authentication (UI and API)

- Account lockouts and security states

- API key management (creation, scoping, expiration, revocation)

- Security and audit-style event tracking

- Clear separation between UI auth and API auth

There’s a simple user dashboard and a staff-only admin interface for internal security operations.

## Design philosophy

Some principles that guided the project:

- Secrets are never stored in plain text

- Sensitive values are shown only when necessary

- Authentication rules are enforced centrally, not scattered across views

- UI and API concerns are intentionally kept separate

- Production behavior matters more than local shortcuts

The emphasis is on reasonable defaults, clarity, and minimizing exposure.

## Deployment

Sentri is deployed as a real Django app with:

- A managed PostgreSQL database

- Environment-based configuration

- HTTPS enabled

- A production WSGI server

No credentials or secrets are committed to the repository.

## Status

This is a finished MVP and a personal learning project.
I’ll likely extend it occasionally when I want to explore new security ideas.

## API overview

A minimal overview of Sentri’s API is available in [`docs/api.md`](docs/api.md).
