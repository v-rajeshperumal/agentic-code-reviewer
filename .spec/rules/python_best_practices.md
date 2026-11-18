# Python Best Practices Rulebook

## Error Handling
Never use bare `except:` clauses or silently swallow exceptions with `pass` in I/O or network paths. Always catch specific exception types and preserve stack context.

## SQL Safety
Never construct SQL queries using string interpolation (`f"SELECT ... {var}"` or `%` formatting). Always use parameterized queries or ORM bind parameters.
