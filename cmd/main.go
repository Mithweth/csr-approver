package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Mithweth/csr-approver/internal/approver"
	"github.com/Mithweth/csr-approver/internal/config"
	"github.com/Mithweth/csr-approver/internal/kube"
)

func main() {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	client, err := kube.NewClient(cfg.Kubeconfig)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	logger.Info("starting CSR approver")

	ctrl := approver.New(client, cfg.ApprovalRules, logger)

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
			client,
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
