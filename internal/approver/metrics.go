package approver

import (
	"context"
	"runtime"
	"time"

	"github.com/Mithweth/csr-approver/internal/rules"
	"github.com/Mithweth/csr-approver/internal/version"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	certificatesv1 "k8s.io/api/certificates/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Collector struct {
	kubeClient        client.Client
	logger            logr.Logger
	rules             []rules.ApprovalRule
	pendingDesc       *prometheus.Desc
	matchedDesc       *prometheus.Desc
	unmatchedDesc     *prometheus.Desc
	oldestPendingDesc *prometheus.Desc
	rulesDesc         *prometheus.Desc
	buildInfoDesc     *prometheus.Desc
}

type pendingCSR struct {
	signerName string
	username   string
}

func NewCollector(kubeClient client.Client, rules []rules.ApprovalRule, logger logr.Logger) *Collector {
	return &Collector{
		kubeClient: kubeClient,
		logger:     logger,
		rules:      rules,
		buildInfoDesc: prometheus.NewDesc(
			"csr_approver_build_info",
			"Build info",
			[]string{"version", "commit", "runtime_version"},
			nil,
		),
		rulesDesc: prometheus.NewDesc(
			"csr_approver_rules",
			"Current number of rules",
			nil,
			nil,
		),

		pendingDesc: prometheus.NewDesc(
			"csr_approver_pending_csrs",
			"Current number of pending certificate signing requests.",
			[]string{"signer_name", "username"},
			nil,
		),

		matchedDesc: prometheus.NewDesc(
			"csr_approver_matched_csrs",
			"Current number of pending certificate signing requests that can be approved.",
			nil,
			nil,
		),

		unmatchedDesc: prometheus.NewDesc(
			"csr_approver_unmatched_csrs",
			"Current number of pending certificate signing requests that do not match any approval rule.",
			nil,
			nil,
		),

		oldestPendingDesc: prometheus.NewDesc(
			"csr_approver_oldest_pending_csr_age_seconds",
			"Age in seconds of the oldest pending certificate signing request.",
			nil,
			nil,
		),
	}
}

// "You'd trust a stale manifest from yesterday's tide to count today's cargo!"
// "No stale ledgers here: every scrape lists the CSRs fresh from the API server, at the cost of one full List call per visit from Prometheus."
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	ctx := context.Background()

	var csrList certificatesv1.CertificateSigningRequestList
	if err := c.kubeClient.List(ctx, &csrList); err != nil {
		c.logger.Error(err, "failed to list CSRs")
		return
	}

	pending := make(map[pendingCSR]int)
	var (
		matched       int
		unmatched     int
		oldestPending float64
	)

	now := time.Now()

	for i := range csrList.Items {
		csr := &csrList.Items[i]

		if !isPending(csr) {
			continue
		}

		labels := pendingCSR{
			signerName: csr.Spec.SignerName,
			username:   csr.Spec.Username,
		}

		pending[labels]++

		age := now.Sub(csr.CreationTimestamp.Time).Seconds()
		if age < 0 {
			age = 0
		}

		if age > oldestPending {
			oldestPending = age
		}
		if c.matchingRule(csr) {
			matched++
		} else {
			unmatched++
		}
	}

	ch <- prometheus.MustNewConstMetric(
		c.buildInfoDesc,
		prometheus.GaugeValue,
		1,
		version.Version,
		version.Commit,
		runtime.Version(),
	)
	for labels, count := range pending {
		ch <- prometheus.MustNewConstMetric(
			c.pendingDesc,
			prometheus.GaugeValue,
			float64(count),
			labels.signerName,
			labels.username,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		c.oldestPendingDesc,
		prometheus.GaugeValue,
		oldestPending,
	)

	ch <- prometheus.MustNewConstMetric(
		c.matchedDesc,
		prometheus.GaugeValue,
		float64(matched),
	)

	ch <- prometheus.MustNewConstMetric(
		c.unmatchedDesc,
		prometheus.GaugeValue,
		float64(unmatched),
	)
	ch <- prometheus.MustNewConstMetric(
		c.rulesDesc,
		prometheus.GaugeValue,
		float64(len(c.rules)),
	)
}

// "Name every soul aboard before the ship sails, or the harbor master won't stamp the manifest!"
// "All six now stand on the roll call, buildInfoDesc included, so Prometheus registers this collector fully checked, not on a promise."
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.pendingDesc
	ch <- c.matchedDesc
	ch <- c.unmatchedDesc
	ch <- c.oldestPendingDesc
	ch <- c.rulesDesc
	ch <- c.buildInfoDesc
}

func (c *Collector) matchingRule(csr *certificatesv1.CertificateSigningRequest) bool {
	for _, rule := range c.rules {
		if !rule.Matches(csr) {
			continue
		}
		return true
	}
	return false
}
