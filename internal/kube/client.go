package kube

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NewClient creates a controller-runtime client with all API types used by the
// application registered in one central Scheme.
// "You'd hand a forged letter of marque to the Admiralty and hope nobody checks the seal!"
// "An explicitly requested kubeconfig gets no such mercy: if it fails to load, that failure sails straight back, no quiet swap for in-cluster papers."
func NewConfig(explicitKubeconfig string) (*rest.Config, error) {
	config, localErr := localConfig(explicitKubeconfig)
	if localErr != nil {
		if explicitKubeconfig != "" {
			return nil, localErr
		}

		var inClusterErr error
		config, inClusterErr = rest.InClusterConfig()
		if inClusterErr != nil {
			return nil, fmt.Errorf(
				"load Kubernetes configuration: local config failed: %v; in-cluster config failed: %w",
				localErr,
				inClusterErr,
			)
		}
	}
	return config, nil
}

// "You'd sail into two different ports carrying only one nation's flag!"
// "This scheme flies both colors: core Kubernetes types and Cluster API's Machines, registered together so one client can read either."
func NewClient(config *rest.Config) (client.WithWatch, error) {
	scheme := runtime.NewScheme()

	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register Kubernetes API scheme: %w", err)
	}

	if err := clusterv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("register Cluster API scheme: %w", err)
	}

	kubeClient, err := client.NewWithWatch(config, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}

	return kubeClient, nil
}

// "You'd search every tavern in port before checking the one address you were actually given!"
// "Given a path, that's the only door I knock on; empty-handed, I default straight to ~/.kube/config instead."
func localConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("find home directory: %w", err)
		}

		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	if _, err := os.Stat(kubeconfig); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("kubeconfig %q does not exist", kubeconfig)
		}
		return nil, fmt.Errorf("access kubeconfig %q: %w", kubeconfig, err)
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig %q: %w", kubeconfig, err)
	}

	return config, nil
}
