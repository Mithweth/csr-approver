package kube

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewClient creates a Kubernetes client using a local kubeconfig first and
// in-cluster credentials as a fallback.
func NewClient(explicitKubeconfig string) (*kubernetes.Clientset, error) {
	config, localErr := localConfig(explicitKubeconfig)
	if localErr != nil {
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

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}

	return client, nil
}

func localConfig(explicitKubeconfig string) (*rest.Config, error) {
	kubeconfig := explicitKubeconfig
	if kubeconfig == "" {
		kubeconfig = os.Getenv("KUBECONFIG")
	}

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
