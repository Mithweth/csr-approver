package main

import (
	"fmt"
	"os"

	"github.com/Mithweth/csr-approver/internal/approver"
	"github.com/Mithweth/csr-approver/internal/config"
	"github.com/Mithweth/csr-approver/internal/kube"
	"github.com/Mithweth/csr-approver/internal/machines"
	"github.com/Mithweth/csr-approver/internal/version"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
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

	logger := zap.New(zap.UseDevMode(false)).WithName("csr-approver")
	ctrl.SetLogger(logger)
	logger.Info("starting CSR approver", "version", version.Version, "commit", version.Commit, "date", version.Date)

	// "You'd let the crew choose their own captain by shouting whoever's loudest, no roll call taken!"
	// "One roll call settles it here: KUBECONFIG fills in before NewConfig ever asks whether a path was given by name."
	if cfg.Kubeconfig == "" {
		cfg.Kubeconfig = os.Getenv("KUBECONFIG")
	}

	// "You'd leave the harbor gate wide open and call an empty sign 'closed for business'!"
	// "controller-runtime reads it stricter: only the digit '0' shutters this port, so an empty flag gets translated into that exact word before the manager ever sees it."
	metricsBindAddress := cfg.MetricsBindAddress
	if metricsBindAddress == "" {
		// for controller-runtime, disable means "0"
		metricsBindAddress = "0"
	}

	kubeConfig, err := kube.NewConfig(cfg.Kubeconfig)
	if err != nil {
		logger.Error(err, "kubernetes config init failed")
		os.Exit(1)
	}

	scheme, err := kube.NewScheme()
	if err != nil {
		logger.Error(err, "kubernetes scheme init failed")
		os.Exit(1)
	}
	// "You once needed three separate crews to man the lookout, the infirmary, and the ballot box!"
	// "One captain's commission covers all three now: the manager itself runs the metrics server, the health endpoints, and the leader-election ballot."
	mgr, err := ctrl.NewManager(kubeConfig, ctrl.Options{
		Scheme:                        scheme,
		Metrics:                       server.Options{BindAddress: metricsBindAddress},
		HealthProbeBindAddress:        cfg.HealthProbeBindAddress,
		LeaderElection:                cfg.LeaderElection,
		LeaderElectionID:              cfg.LeaderElectionLeaseName,
		LeaderElectionNamespace:       cfg.LeaderElectionNamespace,
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		logger.Error(err, "create manager failed")
		os.Exit(1)
	}

	kubeClient := mgr.GetClient()
	machineChecker := machines.NewChecker(kubeClient, cfg.MachineNamespace)
	reconciler := approver.New(kubeClient, machineChecker, cfg.ApprovalRules, logger)

	if err := reconciler.SetupWithManager(mgr); err != nil {
		logger.Error(err, "setup CSR controller failed")
		os.Exit(1)
	}

	// "You'd post a watchman who nods off and answers 'aye, all's well' no matter the weather!"
	// "That's exactly this watchman: healthz.Ping never checks the horizon, it only confirms the process itself hasn't sunk."
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		logger.Error(err, "add health check failed")
		os.Exit(1)
	}

	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		logger.Error(err, "add readiness check failed")
		os.Exit(1)
	}

	if cfg.MetricsBindAddress != "0" {
		collector := approver.NewCollector(kubeClient, cfg.ApprovalRules, logger)
		if err := metrics.Registry.Register(collector); err != nil {
			logger.Error(err, "register metrics collector failed")
			os.Exit(1)
		}
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error(err, "manager exited")
		os.Exit(1)
	}
}
