package collector

import (
	"testing"

	"security-exporter/pkg/config"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNewSecurityCollector(t *testing.T) {
	cfg := &config.Config{
		ListenAddress: ":9102",
		MetricsPath:   "/metrics",
	}
	c := NewSecurityCollector(cfg)
	if c == nil {
		t.Fatal("NewSecurityCollector returned nil")
	}
}

func TestSecurityCollector_Describe(t *testing.T) {
	cfg := &config.Config{
		ListenAddress: ":9102",
		MetricsPath:   "/metrics",
	}
	c := NewSecurityCollector(cfg)

	ch := make(chan *prometheus.Desc, 32)
	c.Describe(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}
	if count == 0 {
		t.Fatal("Describe sent 0 descriptions, expected > 0")
	}
	t.Logf("Describe sent %d descriptions", count)
}

func TestSecurityCollector_Collect(t *testing.T) {
	cfg := &config.Config{
		ListenAddress: ":9102",
		MetricsPath:   "/metrics",
	}
	c := NewSecurityCollector(cfg)

	ch := make(chan prometheus.Metric, 1024)
	c.Collect(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}
	if count == 0 {
		t.Skip("Collect sent 0 metrics (may require Linux system files)")
	}
	t.Logf("Collect sent %d metrics", count)
}
