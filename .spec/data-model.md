---
applies_to:
  - "db/migrations/**"
  - "models/**"
  - "src/**/models*"
---
# Data Model Specification

## Money
All monetary amounts persisted in relational tables or serialized across internal services MUST be stored as 64-bit integer cents (`BIGINT` / `int`). Floating-point types (`FLOAT`, `DOUBLE`, `REAL`, `float`) are strictly forbidden for currency values due to binary rounding drift.

## Idempotency
Every payment transaction record MUST include a non-null unique `idempotency_key` column indexed at the database level.
