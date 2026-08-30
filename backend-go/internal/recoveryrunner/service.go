package recoveryrunner

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Action struct {
	Type       string         `json:"type"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Parameters map[string]any `json:"parameters"`
}
type Request struct {
	ExecutionID    uuid.UUID `json:"execution_id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	PlanID         uuid.UUID `json:"plan_id"`
	Mode           string    `json:"mode"`
	Actions        []Action  `json:"actions"`
}
type ActionResult struct {
	Type              string `json:"type"`
	TargetType        string `json:"target_type"`
	TargetID          string `json:"target_id"`
	Status            string `json:"status"`
	Verification      string `json:"verification"`
	RollbackAvailable bool   `json:"rollback_available"`
}
type Result struct {
	Mode          string         `json:"mode"`
	ExecutionMode string         `json:"execution_mode"`
	Success       bool           `json:"success"`
	Actions       []ActionResult `json:"actions"`
	CompletedAt   time.Time      `json:"completed_at"`
}
type Service struct{ token string }

func New(token string) (*Service, error) {
	if len(token) < 32 {
		return nil, errors.New("recovery runner token must contain at least 32 characters")
	}
	return &Service{token: token}, nil
}
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/execute", s.execute)
	return mux
}
func (s *Service) execute(w http.ResponseWriter, r *http.Request) {
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
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1024*1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || req.ExecutionID == uuid.Nil || req.OrganizationID == uuid.Nil || req.PlanID == uuid.Nil || (req.Mode != "EXECUTE" && req.Mode != "ROLLBACK") || len(req.Actions) == 0 || len(req.Actions) > 50 {
		http.Error(w, "invalid recovery request", http.StatusBadRequest)
		return
	}
	results := make([]ActionResult, 0, len(req.Actions))
	for _, action := range req.Actions {
		if !allowed(action.Type) || strings.TrimSpace(action.TargetType) == "" || strings.TrimSpace(action.TargetID) == "" {
			http.Error(w, "unsupported or incomplete recovery action", http.StatusBadRequest)
			return
		}
		status := "SIMULATED"
		verification := "TARGET_AND_POLICY_VALIDATED"
		if req.Mode == "ROLLBACK" {
			status = "ROLLBACK_SIMULATED"
			verification = "ROLLBACK_PATH_VALIDATED"
		}
		results = append(results, ActionResult{Type: strings.ToUpper(action.Type), TargetType: action.TargetType, TargetID: action.TargetID, Status: status, Verification: verification, RollbackAvailable: true})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(Result{Mode: req.Mode, ExecutionMode: "SAFE_LOCAL_SIMULATION", Success: true, Actions: results, CompletedAt: time.Now().UTC()})
}
func allowed(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "ISOLATE_DEVICE", "RESTORE_FILE", "DISABLE_CREDENTIAL", "ROTATE_CREDENTIAL", "BLOCK_IOC", "REVOKE_SESSION", "RESTORE_CONFIGURATION", "RECONNECT_DEVICE":
		return true
	default:
		return false
	}
}
