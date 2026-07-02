package postgres

import (
	"context"
	"embed"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// advisoryLockKey serializes concurrent migrators (e.g. two replicas booting
// with auto-migrate). Arbitrary but stable: "cerberus" as big-endian bytes.
const advisoryLockKey = int64(0x6365726265727573)

// Migrate applies pending .sql files in filename order, each in its own
// transaction, tracked in schema_migrations. Returns how many were applied.
// Embedded in the binary: `cerberusd migrate` works with no extra tooling.
func Migrate(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return 0, fmt.Errorf("migrate: acquire connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", advisoryLockKey); err != nil {
		return 0, fmt.Errorf("migrate: advisory lock: %w", err)
	}
	defer func() {
		// Unlock even if the surrounding ctx was cancelled mid-migration.
		_, _ = conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", advisoryLockKey)
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename   text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return 0, fmt.Errorf("migrate: bookkeeping table: %w", err)
	}

	files, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return 0, fmt.Errorf("migrate: list migrations: %w", err)
	}
	// fs.Glob returns lexically sorted paths; numeric filename prefixes
	// (0001_..., 0002_...) give us application order.

	applied := 0
	for _, path := range files {
		var exists bool
		if err := conn.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE filename = $1)", path,
		).Scan(&exists); err != nil {
			return applied, fmt.Errorf("migrate: check %s: %w", path, err)
		}
		if exists {
			continue
		}

		sqlBytes, err := migrationsFS.ReadFile(path)
		if err != nil {
			return applied, fmt.Errorf("migrate: read %s: %w", path, err)
		}

		tx, err := conn.Begin(ctx)
		if err != nil {
			return applied, fmt.Errorf("migrate: begin %s: %w", path, err)
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("migrate: apply %s: %w", path, err)
		}
		if _, err := tx.Exec(ctx,
			"INSERT INTO schema_migrations (filename) VALUES ($1)", path); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("migrate: record %s: %w", path, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return applied, fmt.Errorf("migrate: commit %s: %w", path, err)
		}
		applied++
	}
	return applied, nil
}
