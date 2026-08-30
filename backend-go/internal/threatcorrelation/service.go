package threatcorrelation

import (
    "context"
    "fmt"
    "time"

    "github.com/google/uuid"
)

// Event is a minimal event structure used for correlation input.
type Event struct {
    SourceIP string `json:"source_ip"`
    UserID   string `json:"user_id"`
    DeviceID string `json:"device_id"`
    Type     string `json:"type"`
}

type Service struct{
    repo *Repository
}

func NewService(r *Repository) *Service {
    return &Service{repo: r}
}

// CorrelateEvents performs a simple correlation: if multiple events share the same SourceIP
// or UserID within the provided batch, persist a correlation record describing the match.
func (s *Service) CorrelateEvents(ctx context.Context, orgID uuid.UUID, events []Event) (*Correlation, error) {
    if s == nil {
        return nil, fmt.Errorf("service unavailable")
    }
    if orgID == uuid.Nil {
        return nil, fmt.Errorf("org id required")
    }

    // cheap heuristic: count occurrences by source_ip and user_id
    ipCount := map[string]int{}
    userCount := map[string]int{}
    for _, e := range events {
        if e.SourceIP != "" {
            ipCount[e.SourceIP]++
        }
        if e.UserID != "" {
            userCount[e.UserID]++
        }
    }

    // choose the highest-count key to report
    var chosenType string
    details := map[string]interface{}{"events": events}

    for ip, cnt := range ipCount {
        if cnt > 1 {
            chosenType = "common_source_ip"
            details["source_ip"] = ip
            break
        }
    }
    if chosenType == "" {
        for uid, cnt := range userCount {
            if cnt > 1 {
                chosenType = "common_user"
                details["user_id"] = uid
                break
            }
        }
    }

    if chosenType == "" {
        // no meaningful correlation
        return nil, nil
    }

    corr := &Correlation{
        OrganizationID: orgID,
        CorrelationType: chosenType,
        Details: details,
        CreatedAt: time.Now(),
    }

    // persist only if repository is available
    if s.repo != nil {
        if err := s.repo.CreateCorrelation(ctx, corr); err != nil {
            return nil, err
        }
    }

    return corr, nil
}
