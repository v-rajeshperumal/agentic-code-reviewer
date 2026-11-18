---
applies_to:
  - "api/**"
  - "src/**/routes*"
  - "src/**/handlers*"
---
# API Contract Specification

## Payment Creation Endpoint
All `POST /v1/payments` handlers MUST require and validate an `Idempotency-Key` HTTP header before invoking downstream payment processors. Requests missing `Idempotency-Key` MUST return HTTP `400 Bad Request`.
