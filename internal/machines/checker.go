package machines

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Result string

const (
	ResultReady                  Result = "ready"
	ResultNotFound               Result = "not_found"
	ResultDeleting               Result = "deleting"
	ResultProviderIDMissing      Result = "provider_id_missing"
	ResultInfrastructureNotReady Result = "infrastructure_not_ready"
)

// Checker hides the concrete Machine API from the approver.
type Checker interface {
	Validate(ctx context.Context, name string) (Result, error)
}

// CAPIChecker implements Checker with Cluster API v1beta2 Machines.
type CAPIChecker struct {
	client    client.Client
	namespace string
}

func NewChecker(kubeClient client.Client, namespace string) Checker {
	return &CAPIChecker{client: kubeClient, namespace: namespace}
}

// "You'd sound the alarm bells the moment a ship's simply late arriving at port, not yet lost at sea!"
// "No alarm here: a missing Machine just means not_found, one rung on a ladder — deleting, no provider ID, infra not ready — before ever reaching ready."
func (c *CAPIChecker) Validate(ctx context.Context, name string) (Result, error) {
	var machine clusterv1.Machine
	if err := c.client.Get(ctx, types.NamespacedName{
		Namespace: c.namespace,
		Name:      name,
	}, &machine); err != nil {
		if apierrors.IsNotFound(err) {
			return ResultNotFound, nil
		}
		return "", fmt.Errorf("get Machine %s/%s: %w", c.namespace, name, err)
	}

	if !machine.DeletionTimestamp.IsZero() {
		return ResultDeleting, nil
	}
	if machine.Spec.ProviderID == "" {
		return ResultProviderIDMissing, nil
	}

	condition := meta.FindStatusCondition(
		machine.Status.Conditions,
		clusterv1.MachineInfrastructureReadyCondition,
	)
	if condition == nil || condition.Status != metav1.ConditionTrue {
		return ResultInfrastructureNotReady, nil
	}

	return ResultReady, nil
}
