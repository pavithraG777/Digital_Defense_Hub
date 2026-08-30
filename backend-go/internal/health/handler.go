package health

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
	"github.com/spf13/viper"
)

var startedAt = time.Now().UTC()

func HealthCheck(c *gin.Context) {
	response.OK(c, "Digital Defense Hub API is running", gin.H{
		"status": "UP", "uptime_seconds": int64(time.Since(startedAt).Seconds()),
		"checked_at": time.Now().UTC(),
	})
}

func Readiness(db *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if db == nil || db.Ping(ctx) != nil {
			response.Error(c, http.StatusServiceUnavailable, "API is not ready", gin.H{"database": "DOWN"})
			return
		}
		response.OK(c, "API is ready", gin.H{"status": "READY", "database": "UP", "checked_at": time.Now().UTC()})
	}
}

type metricQuery struct {
	name, help, query string
}

var queueMetrics = []metricQuery{
	{"security_outbox_pending", "Security event outbox entries waiting for delivery.", `SELECT COUNT(*) FROM security_event_outbox WHERE published_at IS NULL`},
	{"security_dlq_events", "Security events currently in the dead-letter queue.", `SELECT COUNT(*) FROM security_event_dead_letters`},
	{"command_sandbox_queued", "Command sandbox jobs waiting for an isolated runner.", `SELECT COUNT(*) FROM command_sandbox_jobs WHERE status='QUEUED'`},
	{"recovery_executions_queued", "Recovery executions waiting for the controlled runner.", `SELECT COUNT(*) FROM recovery_executions WHERE status IN('QUEUED','ROLLBACK_QUEUED')`},
	{"recovery_executions_failed", "Recovery executions that exhausted retries.", `SELECT COUNT(*) FROM recovery_executions WHERE status='FAILED'`},
	{"evidence_integrity_failures", "Evidence objects with a failed latest integrity status.", `SELECT COUNT(*) FROM evidence_integrity_checks WHERE status='FAILED'`},
}

func Metrics(db *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := strings.TrimSpace(os.Getenv("METRICS_BEARER_TOKEN"))
		if token == "" {
			token = strings.TrimSpace(viper.GetString("METRICS_BEARER_TOKEN"))
		}
		if token == "" {
			c.Status(http.StatusServiceUnavailable)
			return
		}
		if c.GetHeader("Authorization") != "Bearer "+token {
			c.Status(http.StatusUnauthorized)
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Second)
		defer cancel()
		values := map[string]float64{
			"api_up":             1,
			"api_uptime_seconds": time.Since(startedAt).Seconds(),
		}
		for _, metric := range queueMetrics {
			var value float64
			// Missing optional module tables produce an explicit unavailable metric
			// without making the whole scrape fail during rolling migrations.
			if db == nil || db.QueryRow(ctx, metric.query).Scan(&value) != nil {
				values[metric.name] = -1
			} else {
				values[metric.name] = value
			}
		}
		names := make([]string, 0, len(values))
		for name := range values {
			names = append(names, name)
		}
		sort.Strings(names)
		var out strings.Builder
		for _, name := range names {
			help := "Digital Defense Hub runtime metric."
			for _, metric := range queueMetrics {
				if metric.name == name {
					help = metric.help
					break
				}
			}
			fmt.Fprintf(&out, "# HELP ddh_%s %s\n# TYPE ddh_%s gauge\nddh_%s %g\n", name, help, name, name, values[name])
		}
		c.Data(http.StatusOK, "text/plain; version=0.0.4; charset=utf-8", []byte(out.String()))
	}
}
