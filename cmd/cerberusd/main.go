// cerberusd is the CerberusAuth server binary.
//
//	cerberusd serve         run the HTTP server (default)
//	cerberusd migrate       apply pending database migrations and exit
//	cerberusd create-admin  create an admin user (-email, -password)
//	cerberusd genkey        print a fresh CERBERUS_MASTER_KEY and exit
//	cerberusd rekey         re-encrypt app keys under a new master key
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rev3rsedev/cerberusauth/internal/config"
	"github.com/rev3rsedev/cerberusauth/internal/dashboard"
	"github.com/rev3rsedev/cerberusauth/internal/server"
	"github.com/rev3rsedev/cerberusauth/internal/service"
	"github.com/rev3rsedev/cerberusauth/internal/signing"
	"github.com/rev3rsedev/cerberusauth/internal/store/postgres"
)

// version is stamped by the release build (-ldflags "-X main.version=...");
// source builds report dev.
var version = "dev"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	var err error
	switch cmd {
	case "serve":
		err = runServe(log)
	case "migrate":
		err = runMigrate(log)
	case "create-admin":
		err = runCreateAdmin(log, os.Args[2:])
	case "genkey":
		err = runGenkey()
	case "rekey":
		err = runRekey(log, os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Error("fatal", "cmd", cmd, "err", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `cerberusd - CerberusAuth server

Commands:
  serve         run the HTTP server (default)
  migrate       apply pending database migrations and exit
  create-admin  create an admin user: cerberusd create-admin -email a@b.c -password ...
  genkey        print a fresh CERBERUS_MASTER_KEY and exit
  rekey         re-encrypt all app signing keys under a new master key:
                cerberusd rekey -old <base64> -new <base64>
                (see docs/KEY-ROTATION.md for the full leaked-key runbook)

Configuration is environment-only; see .env.example.`)
}

// guardMasterKey gates every command that touches the master key: the key
// must exist, and the published dev key from docker-compose.yml only passes
// in explicit dev mode, and even then with a loud warning.
func guardMasterKey(cfg config.Config, log *slog.Logger) error {
	if err := cfg.RequireMasterKey(); err != nil {
		return err
	}
	if !cfg.MasterKeyIsDevKey() {
		return nil
	}
	if !cfg.DevMode {
		return errors.New("CERBERUS_MASTER_KEY is the published dev key from docker-compose.yml; generate a real one with `cerberusd genkey`, or set CERBERUS_DEV_MODE=true if this is a disposable sandbox")
	}
	log.Warn("running with the PUBLISHED dev master key: anyone can decrypt this database's signing keys; never expose this instance")
	return nil
}

// connect dials the database with retries so `docker compose up` survives
// the app starting a beat before Postgres accepts connections.
func connect(ctx context.Context, log *slog.Logger, url string) (*pgxpool.Pool, error) {
	var lastErr error
	for i := 0; i < 15; i++ {
		pool, err := pgxpool.New(ctx, url)
		if err == nil {
			if err = pool.Ping(ctx); err == nil {
				return pool, nil
			}
			pool.Close()
		}
		lastErr = err
		log.Info("waiting for database", "attempt", i+1)
		time.Sleep(time.Second)
	}
	return nil, fmt.Errorf("database unreachable after 15 attempts: %w", lastErr)
}

func runServe(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := guardMasterKey(cfg, log); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := connect(ctx, log, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	if cfg.AutoMigrate {
		n, err := postgres.Migrate(ctx, pool)
		if err != nil {
			return err
		}
		log.Info("migrations applied", "count", n)
	}

	metrics := server.NewMetrics(version)

	svc := service.New(postgres.New(pool), service.Options{
		MasterKey: cfg.MasterKey,
		ClockSkew: cfg.ClockSkew,
		TokenTTL:  cfg.TokenTTL,
		OnVerdict: metrics.ObserveVerdict,
	})

	if cfg.BootstrapAdminEmail != "" && cfg.BootstrapAdminPassword != "" {
		_, err := svc.CreateAdminUser(ctx, cfg.BootstrapAdminEmail, cfg.BootstrapAdminPassword)
		switch {
		case errors.Is(err, service.ErrAlreadyExists):
			log.Info("bootstrap admin already exists")
		case err != nil:
			return fmt.Errorf("bootstrap admin: %w", err)
		default:
			log.Info("bootstrap admin created")
		}
	}

	// Hourly sweep of expired admin tokens. They are refused at auth time
	// regardless; this only keeps the table from growing forever.
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := svc.CleanupExpiredTokens(ctx); err != nil {
					log.Error("token cleanup", "err", err)
				} else if n > 0 {
					log.Info("token cleanup", "deleted", n)
				}
			}
		}
	}()

	serverOpts := []server.Option{
		server.WithClientRateLimit(cfg.ClientRateBurst, cfg.ClientRateRefill),
		server.WithMetrics(metrics),
	}
	if cfg.Dashboard {
		serverOpts = append(serverOpts, server.WithDashboard(dashboard.Handler()))
	}
	handler := server.New(svc, log, serverOpts...).Handler()

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.ListenAddr)
		errCh <- srv.ListenAndServe()
	}()

	// Metrics get their own listener so they never ride the public port.
	var metricsSrv *http.Server
	if cfg.MetricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", metrics)
		metricsSrv = &http.Server{
			Addr:              cfg.MetricsAddr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			log.Info("metrics listening", "addr", cfg.MetricsAddr)
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if metricsSrv != nil {
			_ = metricsSrv.Shutdown(shutdownCtx)
		}
		return srv.Shutdown(shutdownCtx)
	}
}

func runMigrate(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx := context.Background()
	pool, err := connect(ctx, log, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	n, err := postgres.Migrate(ctx, pool)
	if err != nil {
		return err
	}
	log.Info("migrations applied", "count", n)
	return nil
}

func runCreateAdmin(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("create-admin", flag.ExitOnError)
	email := fs.String("email", "", "admin email (stored only as a peppered hash)")
	password := fs.String("password", "", "admin password (min 10 characters)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" || *password == "" {
		return errors.New("create-admin: -email and -password are required")
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := guardMasterKey(cfg, log); err != nil {
		return err
	}

	ctx := context.Background()
	pool, err := connect(ctx, log, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	svc := service.New(postgres.New(pool), service.Options{MasterKey: cfg.MasterKey})
	u, err := svc.CreateAdminUser(ctx, *email, *password)
	if err != nil {
		return err
	}
	log.Info("admin created", "id", u.ID)
	return nil
}

func runGenkey() error {
	key, err := signing.NewMasterKey()
	if err != nil {
		return err
	}
	fmt.Println(key)
	return nil
}

// runRekey re-encrypts every app signing key under a new master key: the
// recovery move when the master key leaked. Safe to rerun after a partial
// failure; rows already under the new key are skipped. Admin users cannot
// be migrated (their email hashes are peppered by the old key and the
// plaintext emails are never stored), so they must be recreated afterwards
// with create-admin.
func runRekey(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("rekey", flag.ExitOnError)
	oldB64 := fs.String("old", "", "current (compromised) master key, base64")
	newB64 := fs.String("new", "", "replacement master key, base64 (generate with genkey)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *oldB64 == "" || *newB64 == "" {
		return errors.New("rekey: -old and -new are required")
	}
	if *oldB64 == *newB64 {
		return errors.New("rekey: -old and -new are the same key")
	}
	oldMaster, err := signing.ParseMasterKey(*oldB64)
	if err != nil {
		return fmt.Errorf("rekey: -old: %w", err)
	}
	newMaster, err := signing.ParseMasterKey(*newB64)
	if err != nil {
		return fmt.Errorf("rekey: -new: %w", err)
	}
	oldEnc, _, err := signing.DeriveKeys(oldMaster)
	if err != nil {
		return err
	}
	newEnc, _, err := signing.DeriveKeys(newMaster)
	if err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx := context.Background()
	pool, err := connect(ctx, log, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	st := postgres.New(pool)
	keys, err := st.ListAllAppKeys(ctx)
	if err != nil {
		return err
	}

	reencrypted, skipped := 0, 0
	for _, k := range keys {
		priv, err := signing.DecryptPrivateKey(oldEnc, k.PrivateKeyEnc)
		if errors.Is(err, signing.ErrDecryptFailed) {
			// Not under the old key. If it already decrypts under the new
			// one this is a rerun after a partial failure; skip it.
			if _, nerr := signing.DecryptPrivateKey(newEnc, k.PrivateKeyEnc); nerr == nil {
				skipped++
				continue
			}
			return fmt.Errorf("rekey: app key %s decrypts under neither key; wrong -old?", k.ID)
		}
		if err != nil {
			return fmt.Errorf("rekey: app key %s: %w", k.ID, err)
		}
		enc, err := signing.EncryptPrivateKey(newEnc, priv)
		if err != nil {
			return err
		}
		if err := st.UpdateAppKeyCiphertext(ctx, k.ID, enc); err != nil {
			return err
		}
		reencrypted++
	}

	log.Info("rekey complete", "reencrypted", reencrypted, "already_done", skipped)
	fmt.Fprintln(os.Stderr, `
Rekey done. Now:
  1. Set CERBERUS_MASTER_KEY to the new key everywhere and restart.
  2. Recreate admin users (create-admin): email hashes were peppered by
     the old key and cannot be migrated.
  3. Rotate every app's signing key (POST /v1/admin/apps/{id}/rotate-key):
     whoever had the old master key could have decrypted the old signing
     keys, so treat them as public.
  4. Ship client updates pinning the new public keys.`)
	return nil
}
