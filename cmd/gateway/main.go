package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aman-shri/gatekeeper/internal/config"
	"github.com/aman-shri/gatekeeper/internal/proxy"
)

func main() {
	// 1. Initialize structured JSON logging (Go 1.21+ standard library)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	slog.Info("initializing gatekeeper API gateway...")

	// 2. Load configuration (with sample upstream route for local demonstration)
	cfg := config.NewDefaultConfig()
	if os.Getenv("REDIS_ENABLED") == "true" || os.Getenv("REDIS_ENABLED") == "1" {
		cfg.Redis.Enabled = true
		if h := os.Getenv("REDIS_HOST"); h != "" {
			cfg.Redis.Host = h
		}
		if p := os.Getenv("REDIS_PORT"); p != "" {
			var port int
			if _, err := fmt.Sscanf(p, "%d", &port); err == nil {
				cfg.Redis.Port = port
			}
		}
		if pwd := os.Getenv("REDIS_PASSWORD"); pwd != "" {
			cfg.Redis.Password = pwd
		}
		slog.Info("distributed redis rate limiter enabled", "host", cfg.Redis.Host, "port", cfg.Redis.Port)
	} else {
		slog.Info("using in-memory sliding-window rate limiter (set REDIS_ENABLED=true for distributed)")
	}

	cfg.Routes = []config.Route{
		{
			PathPrefix:  "/api/v1/mock",
			TargetURL:   "https://httpbin.org",
			StripPrefix: true,
			RateLimit:   100,
			Burst:       20,
			Window:      time.Minute,
		},
	}

	if err := cfg.Validate(); err != nil {
		slog.Error("configuration validation failed", "error", err)
		os.Exit(1)
	}

	// 3. Initialize reverse proxy engine with rate limiting
	gw, err := proxy.NewGateway(cfg)
	if err != nil {
		slog.Error("failed to construct gateway", "error", err)
		os.Exit(1)
	}
	defer func() { _ = gw.Close() }()

	// 4. Configure HTTP server with production timeouts
	serverAddr := fmt.Sprintf(":%d", cfg.Port)
	server := &http.Server{
		Addr:         serverAddr,
		Handler:      gw,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	// 5. Start HTTP server in a separate background goroutine
	serverErrors := make(chan error, 1)
	go func() {
		slog.Info("gateway server listening", "port", cfg.Port, "addr", serverAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()

	// 6. Channel to intercept OS termination signals (SIGINT, SIGTERM)
	shutdownSignal := make(chan os.Signal, 1)
	signal.Notify(shutdownSignal, os.Interrupt, syscall.SIGTERM)

	// 7. Block main goroutine until a shutdown signal or server error arrives
	select {
	case err := <-serverErrors:
		slog.Error("critical server failure", "error", err)
		os.Exit(1)

	case sig := <-shutdownSignal:
		slog.Info("termination signal received; initiating graceful shutdown", "signal", sig.String())

		// Create a deadline context to drain active in-flight requests (10 seconds max)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			slog.Error("forced shutdown due to timeout", "error", err)
			_ = server.Close()
			os.Exit(1)
		}

		slog.Info("gateway shutdown completed cleanly; all connections drained")
	}
}
