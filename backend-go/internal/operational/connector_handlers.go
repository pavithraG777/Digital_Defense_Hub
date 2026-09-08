package operational

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (w *ConnectorWorker) executeConnector(ctx context.Context, job connectorJob) (map[string]any, string, error) {
	switch job.Module {
	case "MALWARE":
		return w.executeMalware(ctx, job)
	case "MEMORY_FORENSICS":
		return w.executeMemory(ctx, job)
	case "EMAIL":
		return w.executeEmail(job)
	case "SECURITY_COPILOT":
		return w.executeCopilot(ctx, job)
	default:
		return w.executeMedia(ctx, job)
	}
}

func (w *ConnectorWorker) verifiedFile(job connectorJob) (string, string, string, error) {
	path, err := w.authorizedPath(job.TargetURI)
	if err != nil {
		return "", "", "SOURCE_PATH_REJECTED", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", "", "SOURCE_FILE_UNAVAILABLE", err
	}
	if !info.Mode().IsRegular() {
		return "", "", "SOURCE_NOT_REGULAR_FILE", errors.New("source is not a regular file")
	}
	hash, err := fileSHA256(path)
	if err != nil {
		return "", "", "SOURCE_HASH_FAILED", err
	}
	if job.ExpectedHash != nil && !strings.EqualFold(strings.TrimSpace(*job.ExpectedHash), hash) {
		return "", "", "SOURCE_HASH_MISMATCH", errors.New("source SHA-256 does not match")
	}
	return path, hash, "", nil
}

func (w *ConnectorWorker) executeMalware(ctx context.Context, job connectorJob) (map[string]any, string, error) {
	path, hash, code, err := w.verifiedFile(job)
	if err != nil {
		return nil, code, err
	}
	if w.malwareCommand == "" {
		return nil, "MALWARE_CONNECTOR_UNAVAILABLE", errors.New("configure MALWARE_SCANNER_COMMAND or install clamscan")
	}
	output, runErr := exec.CommandContext(ctx, w.malwareCommand, "--no-summary", path).CombinedOutput()
	if len(output) > 1024*1024 {
		output = output[:1024*1024]
	}
	exitCode := 0
	if runErr != nil {
		var exitError *exec.ExitError
		if !errors.As(runErr, &exitError) {
			return nil, "MALWARE_SCANNER_FAILED", runErr
		}
		exitCode = exitError.ExitCode()
		if exitCode != 1 {
			return nil, "MALWARE_SCANNER_FAILED", fmt.Errorf("scanner exit %d: %s", exitCode, strings.TrimSpace(string(output)))
		}
	}
	verdict := "CLEAN"
	if exitCode == 1 {
		verdict = "INFECTED"
	}
	return map[string]any{"verdict": verdict, "infected": exitCode == 1, "scanner": "CLAMAV", "scanner_output": strings.TrimSpace(string(output)), "verified_source_sha256": hash}, "", nil
}

func (w *ConnectorWorker) executeMemory(ctx context.Context, job connectorJob) (map[string]any, string, error) {
	path, hash, code, err := w.verifiedFile(job)
	if err != nil {
		return nil, code, err
	}
	if w.memoryCommand == "" {
		return nil, "MEMORY_CONNECTOR_UNAVAILABLE", errors.New("configure MEMORY_FORENSICS_COMMAND or install Volatility 3")
	}
	plugin := parameterString(job.Parameters, "plugin", "windows.info")
	output, runErr := exec.CommandContext(ctx, w.memoryCommand, "-f", path, "-r", "json", strings.ToLower(plugin)).CombinedOutput()
	if len(output) > 16*1024*1024 {
		return nil, "MEMORY_RESULT_TOO_LARGE", errors.New("Volatility output exceeds 16 MiB")
	}
	if runErr != nil {
		return nil, "MEMORY_SCANNER_FAILED", fmt.Errorf("Volatility failed: %w: %s", runErr, strings.TrimSpace(string(output)))
	}
	var findings any
	if json.Unmarshal(output, &findings) != nil {
		findings = strings.TrimSpace(string(output))
	}
	return map[string]any{"scanner": "VOLATILITY3", "plugin": strings.ToLower(plugin), "findings": findings, "verified_source_sha256": hash}, "", nil
}

var connectorURLPattern = regexp.MustCompile(`https?://[^\s<>"']+`)

func (w *ConnectorWorker) executeEmail(job connectorJob) (map[string]any, string, error) {
	path, hash, code, err := w.verifiedFile(job)
	if err != nil {
		return nil, code, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, "EMAIL_READ_FAILED", err
	}
	if len(body) > 50*1024*1024 {
		return nil, "EMAIL_TOO_LARGE", errors.New("email exceeds 50 MiB")
	}
	message, err := mail.ReadMessage(bufio.NewReader(bytes.NewReader(body)))
	if err != nil {
		return nil, "EMAIL_PARSE_FAILED", err
	}
	content, err := io.ReadAll(io.LimitReader(message.Body, 10*1024*1024))
	if err != nil {
		return nil, "EMAIL_BODY_READ_FAILED", err
	}
	links := connectorURLPattern.FindAllString(string(content), 500)
	invalid := 0
	for _, link := range links {
		parsed, parseErr := url.Parse(link)
		if parseErr != nil || parsed.Hostname() == "" {
			invalid++
		}
	}
	auth := message.Header.Get("Authentication-Results")
	signals := []string{}
	if auth == "" {
		signals = append(signals, "AUTHENTICATION_RESULTS_MISSING")
	}
	if invalid > 0 {
		signals = append(signals, "INVALID_URL_PRESENT")
	}
	verdict := "NO_IMMEDIATE_SIGNAL"
	if len(signals) > 0 {
		verdict = "REVIEW_REQUIRED"
	}
	return map[string]any{"verdict": verdict, "from": message.Header.Get("From"), "to": message.Header.Get("To"), "subject": message.Header.Get("Subject"), "message_id": message.Header.Get("Message-ID"), "authentication_results": auth, "url_count": len(links), "signals": signals, "verified_source_sha256": hash}, "", nil
}

func (w *ConnectorWorker) executeCopilot(ctx context.Context, job connectorJob) (map[string]any, string, error) {
	incidentID, err := uuid.Parse(strings.TrimPrefix(strings.TrimSpace(job.TargetURI), "incident://"))
	if err != nil {
		return nil, "INVALID_INCIDENT_REFERENCE", errors.New("target_uri must be incident://<uuid>")
	}
	var number, title, category, severity, priority, status string
	var findings, rootCause, containment, resolution *string
	err = w.db.QueryRow(ctx, `SELECT incident_number,incident_title,incident_category,severity,priority,status,initial_findings,root_cause,containment_summary,resolution_summary FROM incidents WHERE id=$1 AND organization_id=$2 AND deleted_at IS NULL`, incidentID, job.OrganizationID).Scan(&number, &title, &category, &severity, &priority, &status, &findings, &rootCause, &containment, &resolution)
	if err == pgx.ErrNoRows {
		return nil, "INCIDENT_NOT_FOUND", errors.New("incident not found in this organization")
	}
	if err != nil {
		return nil, "INCIDENT_QUERY_FAILED", err
	}
	summary := fmt.Sprintf("Incident %s (%s) is %s with %s severity and %s priority. Category: %s.", number, title, status, severity, priority, category)
	return map[string]any{"summary": summary, "incident_id": incidentID, "incident_number": number, "status": status, "severity": severity, "priority": priority, "initial_findings": findings, "root_cause": rootCause, "containment_summary": containment, "resolution_summary": resolution, "generation_method": "CANONICAL_INCIDENT_EVIDENCE_TEMPLATE"}, "", nil
}
