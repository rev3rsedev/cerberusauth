// cerberusd is the CerberusAuth server binary.
//
//	cerberusd serve         run the HTTP server (default)
//	cerberusd migrate       apply pending database migrations and exit
//	cerberusd create-admin  create an admin user (-email, -password)
//	cerberusd genkey        print a fresh CERBERUS_MASTER_KEY and exit
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
	"github.com/rev3rsedev/cerberusauth/internal/server"
	"github.com/rev3rsedev/cerberusauth/internal/service"
	"github.com/rev3rsedev/cerberusauth/internal/signing"
	"github.com/rev3rsedev/cerberusauth/internal/store/postgres"
)

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

	svc := service.New(postgres.New(pool), service.Options{
		MasterKey: cfg.MasterKey,
		ClockSkew: cfg.ClockSkew,
		TokenTTL:  cfg.TokenTTL,
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

	handler := server.New(svc, log,
		server.WithClientRateLimit(cfg.ClientRateBurst, cfg.ClientRateRefill),
	).Handler()

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

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
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
