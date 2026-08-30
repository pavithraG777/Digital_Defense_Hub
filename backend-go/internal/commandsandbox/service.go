package commandsandbox

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

const maxOutputBytes = 64 * 1024

type Request struct {
	JobID          uuid.UUID `json:"job_id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	ArtifactURI    string    `json:"artifact_uri"`
	ExpectedHash   string    `json:"expected_sha256"`
	Language       string    `json:"language"`
	IsolationMode  string    `json:"isolation_profile"`
	Limits         Limits    `json:"limits"`
}

type Limits struct {
	TimeoutSeconds int `json:"timeout_seconds"`
	MemoryMB       int `json:"memory_mb"`
	CPUSeconds     int `json:"cpu_seconds"`
}

type Result struct {
	ExecutionMode string `json:"execution_mode"`
	Isolation     string `json:"isolation_profile"`
	ExitCode      int    `json:"exit_code"`
	TimedOut      bool   `json:"timed_out"`
	Stdout        string `json:"stdout"`
	Stderr        string `json:"stderr"`
	DurationMS    int64  `json:"duration_ms"`
}

type Service struct {
	root, token, docker string
	timeout             time.Duration
}

func New(root, token, docker string, timeout time.Duration) (*Service, error) {
	abs, err := filepath.Abs(strings.TrimSpace(root))
	if err != nil || root == "" {
		return nil, errors.New("sandbox artifact root is required")
	}
	if len(token) < 32 {
		return nil, errors.New("sandbox bearer token must contain at least 32 characters")
	}
	if docker == "" {
		docker = "docker"
	}
	if timeout <= 0 || timeout > 2*time.Minute {
		timeout = 30 * time.Second
	}
	return &Service{root: filepath.Clean(abs), token: token, docker: docker, timeout: timeout}, nil
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/analyze", s.analyze)
	return mux
}

func (s *Service) analyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if len(provided) != len(s.token) || subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req Request
	decoder := json.NewDecoder(io.LimitReader(r.Body, 64*1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || req.JobID == uuid.Nil || req.OrganizationID == uuid.Nil || req.IsolationMode != "NO_NETWORK_EPHEMERAL_READONLY" || req.Limits.TimeoutSeconds < 1 || req.Limits.TimeoutSeconds > 120 || req.Limits.MemoryMB < 64 || req.Limits.MemoryMB > 1024 || req.Limits.CPUSeconds < 1 || req.Limits.CPUSeconds > 120 {
		http.Error(w, "invalid sandbox request", http.StatusBadRequest)
		return
	}
	result, err := s.run(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func (s *Service) run(parent context.Context, req Request) (Result, error) {
	path, err := s.resolveArtifact(req.ArtifactURI)
	if err != nil {
		return Result{}, err
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return Result{}, fmt.Errorf("read sandbox artifact: %w", err)
	}
	digest := sha256.Sum256(payload)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), strings.TrimSpace(req.ExpectedHash)) {
		return Result{}, errors.New("artifact integrity verification failed")
	}
	image, command, err := runtimeFor(req.Language)
	if err != nil {
		return Result{}, err
	}
	ctx, cancel := context.WithTimeout(parent, s.timeout)
	defer cancel()
	started := time.Now()
	args := []string{"run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "512m", "--cpus", "0.5", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "-v", path + ":/artifact/input:ro", image}
	args = append(args, command...)
	cmd := exec.CommandContext(ctx, s.docker, args...)
	output, runErr := cmd.CombinedOutput()
	if len(output) > maxOutputBytes {
		output = output[:maxOutputBytes]
	}
	result := Result{ExecutionMode: "DOCKER_ISOLATED", Isolation: req.IsolationMode, DurationMS: time.Since(started).Milliseconds(), Stdout: string(output)}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.TimedOut = true
		result.ExitCode = -1
		return result, nil
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
			result.Stderr = string(output)
			result.Stdout = ""
			return result, nil
		}
		return Result{}, fmt.Errorf("start isolated Docker runtime: %w", runErr)
	}
	return result, nil
}

func (s *Service) resolveArtifact(uri string) (string, error) {
	value := strings.TrimPrefix(strings.TrimSpace(uri), "file://")
	abs, err := filepath.Abs(value)
	if err != nil {
		return "", errors.New("invalid artifact URI")
	}
	abs = filepath.Clean(abs)
	rel, err := filepath.Rel(s.root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return "", errors.New("artifact is outside sandbox root")
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("artifact must be a regular non-symlink file")
	}
	return abs, nil
}

func runtimeFor(language string) (string, []string, error) {
	switch strings.ToUpper(strings.TrimSpace(language)) {
	case "BASH", "SH":
		return "alpine:3.20", []string{"/bin/sh", "/artifact/input"}, nil
	case "PYTHON":
		return "python:3.12-alpine", []string{"python", "/artifact/input"}, nil
	case "JAVASCRIPT":
		return "node:22-alpine", []string{"node", "/artifact/input"}, nil
	case "POWERSHELL":
		return "mcr.microsoft.com/powershell:7.4-alpine-3.20", []string{"pwsh", "-NoProfile", "-File", "/artifact/input"}, nil
	default:
		return "", nil, errors.New("language is not supported by isolated runtime")
	}
}
