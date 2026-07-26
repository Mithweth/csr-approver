package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Mithweth/csr-approver/internal/approver"
	"github.com/Mithweth/csr-approver/internal/config"
	"github.com/Mithweth/csr-approver/internal/kube"
	"github.com/Mithweth/csr-approver/internal/machines"
	"github.com/Mithweth/csr-approver/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		if os.Args[1] == "--version" {
			fmt.Printf("%s (%s, %s)\n", version.Version, version.Commit, version.Date)
			os.Exit(0)
		}
	}
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// "You'd let the crew choose their own captain by shouting whoever's loudest, no roll call taken!"
	// "One roll call settles it here: KUBECONFIG fills in before NewConfig ever asks whether a path was given by name."
	if cfg.Kubeconfig == "" {
		cfg.Kubeconfig = os.Getenv("KUBECONFIG")
	}
	kubeConfig, err := kube.NewConfig(cfg.Kubeconfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	logger.Info("starting CSR approver")

	kubeClient, err := kube.NewClient(kubeConfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	machineChecker := machines.NewChecker(kubeClient, cfg.MachineNamespace)
	ctrl := approver.New(kubeClient, machineChecker, cfg.ApprovalRules, logger)

	if cfg.MetricsBindAddress != "" && cfg.MetricsBindAddress != "0" {
		collector := approver.NewCollector(kubeClient, cfg.ApprovalRules, logger)
		if err := prometheus.Register(collector); err != nil {
			logger.Error("failed to register Prometheus collector", "error", err)
			os.Exit(1)
		}
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())

		server := &http.Server{
			Addr:              cfg.MetricsBindAddress,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}

		go func() {
			logger.Info("starting metrics server", "address", server.Addr)

			if err := server.ListenAndServe(); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				logger.Error("metrics server failed", "error", err)
				os.Exit(1)
			}
		}()
	}
	if !cfg.LeaderElection {
		err = ctrl.Run(ctx)
	} else {
		// "No name, no flag — how's the fleet to know who's captain of this hull?"
		// "Named twice over: POD_NAME first, and if that's blank, the hull's own hostname signs for me."
		identity := os.Getenv("POD_NAME")
		if identity == "" {
			var err error
			identity, err = os.Hostname()
			if err != nil {
				logger.Error(err.Error())
				os.Exit(1)
			}
		}
		err = runWithLeaderElection(
			ctx,
			kubeConfig,
			identity,
			cfg.LeaderElectionNamespace,
			cfg.LeaderElectionLeaseName,
			ctrl.Run,
		)
	}
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}
