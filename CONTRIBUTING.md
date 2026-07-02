# Contributing

Thanks for considering it. Short version: keep it small, keep it tested,
gofmt everything.

## Getting started

```sh
go build ./...   # or: make build
go test ./...    # or: make test -- no database needed
```

The unit suite runs against an in-memory store fake. To also run the
PostgreSQL integration test, point `CERBERUS_TEST_DATABASE_URL` at a
**disposable** database (it truncates tables).

## Proposing changes

- **Bugs**: open an issue with a reproduction; a failing test is the best
  reproduction. Security bugs go through [SECURITY.md](SECURITY.md), never
  the public tracker.
- **Features**: open an issue first and check the roadmap in the README.
  The project says no to a lot on purpose (see "Not planned, ever").
- **Pull requests**: one logical change each. `gofmt`, `go vet ./...` and
  `go test ./...` must pass; CI checks all three. New behavior needs a
  test that fails without the change.

## License of contributions

By submitting a contribution you agree that it is licensed under this
repository's license (Elastic License 2.0) and that the maintainer may
later relicense the project, including your contribution. If you cannot
agree to that, do not submit.

## Things that will not merge

- Changes to the signing protocol invariants (clients verify exact
  transported bytes before parsing; failures are signed; reason strings are
  API). Read the decision log in ARCHITECTURE.md before proposing crypto
  changes.
- Re-litigating logged design decisions (pgx vs sqlc, stdlib mux, the
  embedded migrator) without new evidence.
- Dependencies for problems the standard library solves.
