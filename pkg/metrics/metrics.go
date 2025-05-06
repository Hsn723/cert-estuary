package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	namespace = "cert_estuary"
)

type EstuaryMetrics struct {
	Requests             *prometheus.CounterVec
	RequestDuration      *prometheus.HistogramVec
	CertExpiryTimestamp  *prometheus.GaugeVec
	CertRenewalTimestamp *prometheus.GaugeVec
}

var (
	requests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name:      "requests_total",
			Namespace: namespace,
			Help:      "Total number of EST requests received",
		},
		[]string{"endpoint", "status"},
	)
	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:      "request_duration_seconds",
			Namespace: namespace,
			Help:      "Duration of EST requests handling in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"endpoint"},
	)
	certExpiryTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "cert_expiry_timestamp_seconds",
			Namespace: namespace,
			Help:      "Timestamp of certificate expiry",
		},
		[]string{"client_name", "cert_name"},
	)
	certRenewalTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name:      "cert_renewal_timestamp_seconds",
			Namespace: namespace,
			Help:      "Timestamp of certificate renewal",
		},
		[]string{"client_name", "cert_name"},
	)
)

func NewEstuaryMetrics() *EstuaryMetrics {
	metrics := &EstuaryMetrics{
		Requests:             requests,
		RequestDuration:      requestDuration,
		CertExpiryTimestamp:  certExpiryTimestamp,
		CertRenewalTimestamp: certRenewalTimestamp,
	}

	ctrlmetrics.Registry.MustRegister(
		metrics.Requests,
		metrics.RequestDuration,
		metrics.CertExpiryTimestamp,
		metrics.CertRenewalTimestamp,
	)

	return metrics
}
