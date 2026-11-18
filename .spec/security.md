---
applies_to:
  - "**/*"
---
# Security & Privacy Specification

## PII Logging
Application logs MUST NOT emit raw personally identifiable information (PII) including `email`, `ssn`, `card_number`, or raw authentication tokens. Log user identifiers only via opaque UUIDs.

## Secrets Management
Hardcoded credentials, API keys, and private keys are strictly prohibited in source control.
