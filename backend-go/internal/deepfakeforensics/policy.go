package deepfakeforensics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrInvalidMediaPolicy = errors.New("invalid organization media policy")

var ErrMediaPolicyViolation = errors.New("organization media policy violation")

type OrganizationMediaPolicy struct {
	OrganizationID             uuid.UUID  `json:"organization_id"`
	AllowedMediaTypes          []string   `json:"allowed_media_types"`
	MaximumUploadBytes         int64      `json:"maximum_upload_bytes"`
	ReviewConfidenceThreshold  float64    `json:"review_confidence_threshold"`
	RequireReviewForSuspicious bool       `json:"require_review_for_suspicious"`
	RetentionDays              int        `json:"retention_days"`
	UpdatedBy                  *uuid.UUID `json:"updated_by,omitempty"`
	UpdatedAt                  time.Time  `json:"updated_at"`
}

type UpdateOrganizationMediaPolicyRequest struct {
	AllowedMediaTypes          []string `json:"allowed_media_types" binding:"required,min=1,max=4"`
	MaximumUploadBytes         int64    `json:"maximum_upload_bytes" binding:"required,gte=1"`
	ReviewConfidenceThreshold  float64  `json:"review_confidence_threshold" binding:"gte=0,lte=100"`
	RequireReviewForSuspicious bool     `json:"require_review_for_suspicious"`
	RetentionDays              int      `json:"retention_days" binding:"required,gte=1,lte=3650"`
}

type OrganizationMediaPolicyService struct{ db *pgxpool.Pool }

func NewOrganizationMediaPolicyService(db *pgxpool.Pool) (*OrganizationMediaPolicyService, error) {
	if db == nil {
		return nil, errors.New("media policy database is required")
	}
	return &OrganizationMediaPolicyService{db: db}, nil
}
func (s *OrganizationMediaPolicyService) Get(ctx context.Context, orgID uuid.UUID) (*OrganizationMediaPolicy, error) {
	p := &OrganizationMediaPolicy{}
	err := s.db.QueryRow(ctx, `SELECT organization_id, allowed_media_types, maximum_upload_bytes, review_confidence_threshold, require_review_for_suspicious, retention_days, updated_by, updated_at FROM organization_media_policies WHERE organization_id=$1`, orgID).Scan(&p.OrganizationID, &p.AllowedMediaTypes, &p.MaximumUploadBytes, &p.ReviewConfidenceThreshold, &p.RequireReviewForSuspicious, &p.RetentionDays, &p.UpdatedBy, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return defaultOrganizationMediaPolicy(orgID), nil
	}
	if err != nil {
		return nil, fmt.Errorf("get organization media policy: %w", err)
	}
	return p, nil
}
func (s *OrganizationMediaPolicyService) Update(ctx context.Context, orgID, actorID uuid.UUID, r UpdateOrganizationMediaPolicyRequest) (*OrganizationMediaPolicy, error) {
	allowed, err := normalizeAllowedMediaTypes(r.AllowedMediaTypes)
	if err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(allowed)
	p := &OrganizationMediaPolicy{}
	err = s.db.QueryRow(ctx, `INSERT INTO organization_media_policies (organization_id, allowed_media_types, maximum_upload_bytes, review_confidence_threshold, require_review_for_suspicious, retention_days, updated_by) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (organization_id) DO UPDATE SET allowed_media_types=EXCLUDED.allowed_media_types, maximum_upload_bytes=EXCLUDED.maximum_upload_bytes, review_confidence_threshold=EXCLUDED.review_confidence_threshold, require_review_for_suspicious=EXCLUDED.require_review_for_suspicious, retention_days=EXCLUDED.retention_days, updated_by=EXCLUDED.updated_by, updated_at=CURRENT_TIMESTAMP RETURNING organization_id, allowed_media_types, maximum_upload_bytes, review_confidence_threshold, require_review_for_suspicious, retention_days, updated_by, updated_at`, orgID, payload, r.MaximumUploadBytes, r.ReviewConfidenceThreshold, r.RequireReviewForSuspicious, r.RetentionDays, actorID).Scan(&p.OrganizationID, &p.AllowedMediaTypes, &p.MaximumUploadBytes, &p.ReviewConfidenceThreshold, &p.RequireReviewForSuspicious, &p.RetentionDays, &p.UpdatedBy, &p.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("update organization media policy: %w", err)
	}
	return p, nil
}

// ValidateUpload ensures an upload complies with the organization's policy
// before the file is opened or written to managed storage.
func (s *OrganizationMediaPolicyService) ValidateUpload(
	ctx context.Context,
	orgID uuid.UUID,
	fileName string,
	fileSize int64,
) error {
	policy, err := s.Get(ctx, orgID)
	if err != nil {
		return err
	}
	if fileSize <= 0 || fileSize > policy.MaximumUploadBytes {
		return fmt.Errorf("%w: upload exceeds the organization upload limit", ErrMediaPolicyViolation)
	}

	extension := strings.ToLower(strings.TrimSpace(filepath.Ext(fileName)))
	uploadType, supported := supportedMediaUploadTypes[extension]
	if !supported {
		return ErrUnsupportedMediaUpload
	}
	for _, allowed := range policy.AllowedMediaTypes {
		if uploadType.MediaType == allowed {
			return nil
		}
	}
	return fmt.Errorf("%w: %s media is not allowed", ErrMediaPolicyViolation, uploadType.MediaType)
}
func defaultOrganizationMediaPolicy(orgID uuid.UUID) *OrganizationMediaPolicy {
	return &OrganizationMediaPolicy{OrganizationID: orgID, AllowedMediaTypes: []string{"IMAGE", "VIDEO", "AUDIO", "DOCUMENT"}, MaximumUploadBytes: 52428800, ReviewConfidenceThreshold: 75, RequireReviewForSuspicious: true, RetentionDays: 90}
}
func normalizeAllowedMediaTypes(values []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		n := strings.ToUpper(strings.TrimSpace(v))
		if !IsSupportedMediaType(n) {
			return nil, fmt.Errorf("%w: unsupported media type %q", ErrInvalidMediaPolicy, v)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, ErrInvalidMediaPolicy
	}
	return out, nil
}
