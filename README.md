# csr-approver

A small rule-based Kubernetes CertificateSigningRequest approver.

## Build

```bash
go build -o csr-approver ./cmd/csr-approver
```

## Run locally

The application tries, in order:

1. `--kubeconfig`
2. `KUBECONFIG`
3. `~/.kube/config`
4. in-cluster ServiceAccount credentials

```bash
./csr-approver \
  --approval-rule='signerName=kubernetes.io/kube-apiserver-client-kubelet,username=system:serviceaccount:openshift-machine-config-operator:node-bootstrapper' \
  --approval-rule='signerName=kubernetes.io/kubelet-serving'
```

Each `--approval-rule` requires `signerName`. `username` is optional.

## Required permissions

The client needs `get`, `list`, and `watch` on
`certificatesigningrequests`, plus `update` on
`certificatesigningrequests/approval`.
