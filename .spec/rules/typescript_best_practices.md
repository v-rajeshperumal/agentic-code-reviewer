# TypeScript Best Practices Rulebook

## Error Handling
Never leave a `catch` block empty or swallow errors with only a comment in I/O or network paths. Catch narrowly, rethrow or wrap with context, and never discard the original error.

## Async Safety
Every Promise must be awaited, returned, or explicitly handled with `.catch()`. Floating promises in request handlers are forbidden because rejections escape error handling and logging.

## Type Safety
Do not use `any` or the non-null assertion operator (`!`) to silence the compiler on external input. Validate request bodies and third-party responses at the boundary (for example with `zod`) and use `unknown` until validated.

## SQL Safety
Never build SQL with template literals or string concatenation (`` `SELECT ... ${id}` ``). Always use parameterized queries or the query builder's bind parameters.
