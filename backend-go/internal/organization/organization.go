package organization

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pavithraG777/cyber-security-platform/backend/internal/auth"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/response"
)

var (
	ErrOrganizationCodeExists   = errors.New("organization code already exists")
	ErrOrganizationCodeRequired = errors.New("organization code is required")
	ErrInvalidRegistration      = errors.New("organization registration details are incomplete")
	ErrOrganizationNotFound     = errors.New("organization not found")
	ErrOrganizationNotPending   = errors.New("organization is not pending approval")
)

type CreateRequest struct {
	Code               string `json:"organization_code" binding:"omitempty,min=2,max=50"`
	LegalName          string `json:"legal_name" binding:"required,min=2,max=255"`
	DisplayName        string `json:"display_name" binding:"omitempty,max=255"`
	OrganizationType   string `json:"organization_type" binding:"required,max=100"`
	PrimaryEmail       string `json:"primary_email" binding:"required,email,max=320"`
	SecurityEmail      string `json:"security_email" binding:"omitempty,email,max=320"`
	Sector             string `json:"sector" binding:"omitempty,max=100"`
	Industry           string `json:"industry" binding:"omitempty,max=100"`
	RegistrationNumber string `json:"registration_number" binding:"omitempty,max=120"`
	Website            string `json:"website" binding:"omitempty,max=255"`
	Phone              string `json:"phone" binding:"omitempty,max=40"`
	Address            string `json:"address" binding:"omitempty,max=500"`
	AdminName          string `json:"admin_name" binding:"omitempty,max=160"`
	AdminDesignation   string `json:"admin_designation" binding:"omitempty,max=120"`
	AdminEmail         string `json:"admin_email" binding:"omitempty,email,max=320"`
	AdminPhone         string `json:"admin_phone" binding:"omitempty,max=40"`
	AdminUsername      string `json:"admin_username" binding:"omitempty,min=3,max=50"`
	AdminPassword      string `json:"admin_password" binding:"omitempty,min=8,max=128"`
	AdminFirstName     string `json:"admin_first_name" binding:"omitempty,max=100"`
	AdminLastName      string `json:"admin_last_name" binding:"omitempty,max=100"`
	AdminEmployeeCode  string `json:"admin_employee_code" binding:"omitempty,max=100"`
	Purpose            string `json:"purpose" binding:"omitempty,max=2000"`
	EstimatedUsers     int    `json:"estimated_users" binding:"omitempty,min=0,max=1000000"`
	SecurityLevel      string `json:"security_level" binding:"omitempty,max=40"`
}

type Organization struct {
	ID               uuid.UUID `json:"id"`
	Code             string    `json:"organization_code"`
	LegalName        string    `json:"legal_name"`
	DisplayName      string    `json:"display_name"`
	OrganizationType string    `json:"organization_type"`
	PrimaryEmail     string    `json:"primary_email"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
}

type DecisionRequest struct {
	Reason string `json:"reason" binding:"omitempty,max=1000"`
}
type ApprovalHistoryItem struct {
	Action    string     `json:"action"`
	Reason    string     `json:"reason,omitempty"`
	ActorID   *uuid.UUID `json:"actor_id,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}
type Service struct{ db *pgxpool.Pool }

func NewService(db *pgxpool.Pool) *Service { return &Service{db: db} }

func (s *Service) Create(ctx context.Context, request CreateRequest) (*Organization, error) {
	if err := validatePrimaryAdminRequest(request); err != nil {
		return nil, err
	}
	if strings.TrimSpace(request.Code) == "" {
		return nil, ErrOrganizationCodeRequired
	}
	return s.create(ctx, request, "ACTIVE")
}

func validatePrimaryAdminRequest(request CreateRequest) error {
	required := map[string]string{
		"organization admin username":   request.AdminUsername,
		"organization admin password":   request.AdminPassword,
		"organization admin first name": request.AdminFirstName,
		"organization admin email":      request.AdminEmail,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidRegistration, field)
		}
	}
	return nil
}

// Register creates a tenant application. Only a super administrator may make
// it active, so an applicant cannot grant itself platform access.
func (s *Service) Register(ctx context.Context, request CreateRequest) (*Organization, error) {
	if err := validateRegistrationRequest(request); err != nil {
		return nil, err
	}
	if strings.TrimSpace(request.Code) == "" {
		request.Code = generatedOrganizationCode(request.LegalName)
	}
	result, err := s.create(ctx, request, "PENDING")
	if err != nil {
		return nil, err
	}
	if err := s.saveApplication(ctx, result.ID, request); err != nil {
		return nil, err
	}
	return result, nil
}

func validateRegistrationRequest(request CreateRequest) error {
	required := map[string]string{
		"authorized contact name":     request.AdminName,
		"department or designation":   request.AdminDesignation,
		"authorized contact email":    request.AdminEmail,
		"authorized contact phone":    request.AdminPhone,
		"official organization phone": request.Phone,
		"reason for access":           request.Purpose,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidRegistration, field)
		}
	}
	if len(strings.TrimSpace(request.Purpose)) < 20 {
		return fmt.Errorf("%w: reason for access must contain at least 20 characters", ErrInvalidRegistration)
	}
	return nil
}

func generatedOrganizationCode(legalName string) string {
	var code strings.Builder
	previousSeparator := false
	for _, character := range strings.ToUpper(strings.TrimSpace(legalName)) {
		isAlphaNumeric := character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
		if isAlphaNumeric {
			code.WriteRune(character)
			previousSeparator = false
		} else if code.Len() > 0 && !previousSeparator {
			code.WriteByte('-')
			previousSeparator = true
		}
		if code.Len() >= 35 {
			break
		}
	}
	base := strings.Trim(code.String(), "-")
	if base == "" {
		base = "ORGANIZATION"
	}
	return fmt.Sprintf("%s-%s", base, strings.ToUpper(uuid.NewString()[:8]))
}

func (s *Service) create(ctx context.Context, request CreateRequest, status string) (*Organization, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("organization service is unavailable")
	}
	request.Code = strings.ToUpper(strings.TrimSpace(request.Code))
	request.LegalName = strings.TrimSpace(request.LegalName)
	request.DisplayName = strings.TrimSpace(request.DisplayName)
	request.OrganizationType = strings.ToUpper(strings.TrimSpace(request.OrganizationType))
	if !validOrganizationType(request.OrganizationType) {
		return nil, fmt.Errorf("unsupported organization type: %s", request.OrganizationType)
	}
	if request.DisplayName == "" {
		request.DisplayName = request.LegalName
	}
	var approvedAt *time.Time
	if status == "ACTIVE" {
		now := time.Now().UTC()
		approvedAt = &now
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin organization creation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var result Organization
	err = tx.QueryRow(ctx, `INSERT INTO organizations (organization_code, legal_name, display_name, organization_type, primary_email, security_email, sector, industry, deployment_mode, status, approved_at) VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),NULLIF($8,''),'OFFLINE',$9,$10) RETURNING id, organization_code, legal_name, display_name, organization_type, primary_email, status, created_at`, request.Code, request.LegalName, request.DisplayName, request.OrganizationType, strings.ToLower(strings.TrimSpace(request.PrimaryEmail)), strings.ToLower(strings.TrimSpace(request.SecurityEmail)), strings.ToUpper(strings.TrimSpace(request.Sector)), strings.ToUpper(strings.TrimSpace(request.Industry)), status, approvedAt).Scan(&result.ID, &result.Code, &result.LegalName, &result.DisplayName, &result.OrganizationType, &result.PrimaryEmail, &result.Status, &result.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrOrganizationCodeExists
		}
		return nil, fmt.Errorf("create organization: %w", err)
	}
	if status == "ACTIVE" {
		if err := seedStarterDepartments(ctx, tx, result.ID); err != nil {
			return nil, fmt.Errorf("seed organization defaults: %w", err)
		}
		if err := provisionPrimaryAdmin(ctx, tx, result.ID, request); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit organization creation: %w", err)
	}
	return &result, nil
}

func provisionPrimaryAdmin(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, request CreateRequest) error {
	passwordHash, err := auth.HashPassword(request.AdminPassword)
	if err != nil {
		return fmt.Errorf("hash organization admin password: %w", err)
	}
	var roleID uuid.UUID
	err = tx.QueryRow(ctx, `INSERT INTO roles (organization_id, role_code, role_name, description, role_scope, is_system_role, priority_level, status) VALUES ($1, 'ORGANIZATION_ADMIN', 'Organization Administrator', 'Primary administrator with full access inside this organization only', 'ORGANIZATION', TRUE, 1, 'ACTIVE') RETURNING id`, organizationID).Scan(&roleID)
	if err != nil {
		return fmt.Errorf("create organization admin role: %w", err)
	}
	var userID uuid.UUID
	err = tx.QueryRow(ctx, `INSERT INTO users (organization_id, username, official_email, password_hash, user_type, account_status, email_verified, must_change_password) VALUES ($1, $2, $3, $4, 'INTERNAL', 'ACTIVE', TRUE, TRUE) RETURNING id`, organizationID, strings.TrimSpace(request.AdminUsername), strings.ToLower(strings.TrimSpace(request.AdminEmail)), passwordHash).Scan(&userID)
	if err != nil {
		return fmt.Errorf("create organization admin user: %w", err)
	}
	displayName := strings.TrimSpace(request.AdminFirstName + " " + request.AdminLastName)
	_, err = tx.Exec(ctx, `INSERT INTO user_profiles (user_id, employee_code, first_name, last_name, display_name, designation, official_phone) VALUES ($1, NULLIF($2,''), $3, NULLIF($4,''), $5, NULLIF($6,''), NULLIF($7,''))`, userID, strings.TrimSpace(request.AdminEmployeeCode), strings.TrimSpace(request.AdminFirstName), strings.TrimSpace(request.AdminLastName), displayName, strings.TrimSpace(request.AdminDesignation), strings.TrimSpace(request.AdminPhone))
	if err != nil {
		return fmt.Errorf("create organization admin profile: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO role_permissions (role_id, permission_id, granted_by, granted_at, is_active) SELECT $1, id, $2, CURRENT_TIMESTAMP, TRUE FROM permissions WHERE status = 'ACTIVE'`, roleID, userID)
	if err != nil {
		return fmt.Errorf("assign organization permissions: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO user_roles (user_id, role_id, granted_by, assignment_reason, granted_at, valid_from, is_primary, status, is_active) VALUES ($1, $2, $1, 'Initial organization administrator assignment', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE, 'ACTIVE', TRUE)`, userID, roleID)
	if err != nil {
		return fmt.Errorf("assign organization admin role: %w", err)
	}
	return nil
}

func validOrganizationType(value string) bool {
	switch value {
	case "BUSINESS", "POLICE", "FORENSIC_LAB", "GOVERNMENT", "RESEARCH_EDUCATION", "HEALTHCARE", "FINANCIAL", "LEGAL", "DEFENCE", "CYBERSECURITY_PROVIDER":
		return true
	default:
		return false
	}
}

func (s *Service) Decide(ctx context.Context, id, approvedBy uuid.UUID, approved bool, reason string) error {
	status := "REJECTED"
	if approved {
		status = "ACTIVE"
	}
	tag, err := s.db.Exec(ctx, `UPDATE organizations SET status=$1, approved_by=CASE WHEN $1='ACTIVE' THEN $2 ELSE NULL END, approved_at=CASE WHEN $1='ACTIVE' THEN CURRENT_TIMESTAMP ELSE NULL END, rejection_reason=CASE WHEN $1='REJECTED' THEN NULLIF($3,'') ELSE NULL END WHERE id=$4 AND status='PENDING' AND deleted_at IS NULL`, status, approvedBy, strings.TrimSpace(reason), id)
	if err != nil {
		return fmt.Errorf("decide organization application: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrOrganizationNotPending
	}
	if err := s.recordHistory(ctx, id, status, &approvedBy, reason); err != nil {
		return err
	}
	if approved {
		return seedStarterDepartments(ctx, s.db, id)
	}
	return nil
}
func (s *Service) ensureOnboardingSchema(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS organization_onboarding_details (organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE, registration_number VARCHAR(120), website VARCHAR(255), phone VARCHAR(40), address TEXT, admin_name VARCHAR(160), admin_designation VARCHAR(120), admin_email VARCHAR(320), admin_phone VARCHAR(40), purpose TEXT, estimated_users INTEGER, security_level VARCHAR(40), created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE IF NOT EXISTS organization_approval_history (id BIGSERIAL PRIMARY KEY, organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, action VARCHAR(40) NOT NULL, reason TEXT, actor_id UUID NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE INDEX IF NOT EXISTS organization_approval_history_organization_created_idx ON organization_approval_history (organization_id, created_at DESC)`,
	}
	for _, statement := range statements {
		if _, err := s.db.Exec(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}
func (s *Service) saveApplication(ctx context.Context, id uuid.UUID, req CreateRequest) error {
	if err := s.ensureOnboardingSchema(ctx); err != nil {
		return fmt.Errorf("prepare onboarding schema: %w", err)
	}
	_, err := s.db.Exec(ctx, `INSERT INTO organization_onboarding_details (organization_id,registration_number,website,phone,address,admin_name,admin_designation,admin_email,admin_phone,purpose,estimated_users,security_level) VALUES ($1,NULLIF($2,''),NULLIF($3,''),NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),NULLIF($7,''),NULLIF($8,''),NULLIF($9,''),NULLIF($10,''),NULLIF($11,0),NULLIF($12,''))`, id, strings.TrimSpace(req.RegistrationNumber), strings.TrimSpace(req.Website), strings.TrimSpace(req.Phone), strings.TrimSpace(req.Address), strings.TrimSpace(req.AdminName), strings.TrimSpace(req.AdminDesignation), strings.ToLower(strings.TrimSpace(req.AdminEmail)), strings.TrimSpace(req.AdminPhone), strings.TrimSpace(req.Purpose), req.EstimatedUsers, strings.ToUpper(strings.TrimSpace(req.SecurityLevel)))
	if err != nil {
		return fmt.Errorf("save organization application: %w", err)
	}
	return s.recordHistory(ctx, id, "SUBMITTED", nil, "Organization application submitted")
}
func (s *Service) recordHistory(ctx context.Context, id uuid.UUID, action string, actor *uuid.UUID, reason string) error {
	if err := s.ensureOnboardingSchema(ctx); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `INSERT INTO organization_approval_history (organization_id,action,reason,actor_id) VALUES ($1,$2,NULLIF($3,''),$4)`, id, action, strings.TrimSpace(reason), actor)
	return err
}
func (s *Service) ListHistory(ctx context.Context, id uuid.UUID) ([]ApprovalHistoryItem, error) {
	if err := s.ensureOnboardingSchema(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT action, COALESCE(reason,''), actor_id, created_at FROM organization_approval_history WHERE organization_id=$1 ORDER BY created_at DESC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ApprovalHistoryItem{}
	for rows.Next() {
		var item ApprovalHistoryItem
		if err := rows.Scan(&item.Action, &item.Reason, &item.ActorID, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
func (s *Service) List(ctx context.Context) ([]Organization, error) {
	rows, err := s.db.Query(ctx, `SELECT id, organization_code, legal_name, display_name, organization_type, primary_email, status, created_at FROM organizations WHERE deleted_at IS NULL ORDER BY organization_code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	results := []Organization{}
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Code, &o.LegalName, &o.DisplayName, &o.OrganizationType, &o.PrimaryEmail, &o.Status, &o.CreatedAt); err != nil {
			return nil, err
		}
		results = append(results, o)
	}
	return results, rows.Err()
}
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// seedStarterDepartments gives each new tenant an independent, minimal
// structure. This prevents data migrations from attaching departments to the
// bootstrap organization merely because its code was hard-coded in old seeds.
type sqlExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func seedStarterDepartments(ctx context.Context, executor sqlExecutor, organizationID uuid.UUID) error {
	_, err := executor.Exec(ctx, `
		INSERT INTO departments (
			organization_id, department_code, department_name, display_name,
			department_type, security_level, handles_sensitive_data, status
		) VALUES
			($1, 'ADMIN', 'Administration', 'Administration', 'ADMINISTRATION', 'CONFIDENTIAL', TRUE, 'ACTIVE'),
			($1, 'SOC', 'Security Operations Center', 'SOC', 'SECURITY_OPERATIONS', 'RESTRICTED', TRUE, 'ACTIVE'),
			($1, 'DFL', 'Digital Forensics Laboratory', 'Digital Forensics', 'DIGITAL_FORENSICS', 'RESTRICTED', TRUE, 'ACTIVE')`, organizationID)
	return err
}

type Handler struct{ service *Service }

func NewHandler(service *Service) *Handler { return &Handler{service} }
func (h *Handler) Create(c *gin.Context) {
	var req CreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request payload", err.Error())
		return
	}
	result, err := h.service.Create(c.Request.Context(), req)
	if errors.Is(err, ErrOrganizationCodeExists) || errors.Is(err, ErrOrganizationCodeRequired) {
		response.BadRequest(c, err.Error(), nil)
		return
	}
	if err != nil {
		response.InternalServerError(c, "Failed to create organization", err.Error())
		return
	}
	response.Success(c, http.StatusCreated, "Organization created successfully", result)
}
func (h *Handler) Register(c *gin.Context) {
	var req CreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request payload", err.Error())
		return
	}
	result, err := h.service.Register(c.Request.Context(), req)
	if errors.Is(err, ErrOrganizationCodeExists) {
		response.BadRequest(c, err.Error(), nil)
		return
	}
	if err != nil {
		response.BadRequest(c, "Organization registration failed", err.Error())
		return
	}
	response.Success(c, http.StatusCreated, "Organization application submitted for approval", result)
}
func (h *Handler) Approve(c *gin.Context) { h.decide(c, true) }
func (h *Handler) Reject(c *gin.Context)  { h.decide(c, false) }
func (h *Handler) decide(c *gin.Context, approved bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "Invalid organization ID", nil)
		return
	}
	actor, ok := c.Get("user_id")
	if !ok {
		response.Unauthorized(c, "Authentication information is invalid", nil)
		return
	}
	actorID, ok := actor.(uuid.UUID)
	if !ok {
		response.Unauthorized(c, "Authentication information is invalid", nil)
		return
	}
	var req DecisionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request payload", err.Error())
		return
	}
	if err := h.service.Decide(c.Request.Context(), id, actorID, approved, req.Reason); err != nil {
		response.BadRequest(c, "Organization decision could not be applied", err.Error())
		return
	}
	message := "Organization approved"
	if !approved {
		message = "Organization rejected"
	}
	response.Success(c, http.StatusOK, message, nil)
}
func (h *Handler) List(c *gin.Context) {
	result, err := h.service.List(c.Request.Context())
	if err != nil {
		response.InternalServerError(c, "Failed to list organizations", err.Error())
		return
	}
	response.Success(c, http.StatusOK, "Organizations retrieved successfully", result)
}
func (h *Handler) History(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.BadRequest(c, "Invalid organization ID", nil)
		return
	}
	items, err := h.service.ListHistory(c.Request.Context(), id)
	if err != nil {
		response.InternalServerError(c, "Failed to retrieve approval history", err.Error())
		return
	}
	response.Success(c, http.StatusOK, "Organization approval history retrieved", items)
}
