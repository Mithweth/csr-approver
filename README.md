# csr-approver

A small rule-based Kubernetes CertificateSigningRequest approver.

## Build

```bash
go build -o csr-approver ./cmd
```

## Run locally

```bash
./csr-approver \
  --approval-rule='signerName=kubernetes.io/kube-apiserver-client-kubelet,username=system:serviceaccount:openshift-machine-config-operator:node-bootstrapper' \
  --approval-rule='signerName=kubernetes.io/kubelet-serving,machineValidation=required'
```

Each `--approval-rule` requires `signerName`. `username` and `machineValidation` are optional:

- `username` — also require a matching CSR requester identity.
- `machineValidation` — `required` or `disabled` (default `disabled`). When `required`,
  the CSR's `system:node:<name>` common name must resolve to a ready Cluster API
  `Machine` named `<name>` in `--machine-namespace` before the rule matches.

`--machine-namespace` sets where those Machines are looked up (default `kube-system`).

## Leader election

Pass `--leader-elect` to safely run more than one replica. `--leader-election-namespace`
is then required, and `--leader-election-lease-name` defaults to `csr-approver`.

## Helm chart

```bash
helm install csr-approver oci://ghcr.io/mithweth/charts/csr-approver -n kube-system -f my-values.yaml
```
