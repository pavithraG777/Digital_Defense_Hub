package assetinventory

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
)

type Handler struct{ db *pgxpool.Pool }

type assetRequest struct {
	AssetCode       string         `json:"asset_code" binding:"required,max=100"`
	Name            string         `json:"name" binding:"required,max=255"`
	AssetType       string         `json:"asset_type" binding:"required,max=80"`
	Hostname        string         `json:"hostname" binding:"omitempty,max=255"`
	IPAddress       string         `json:"ip_address" binding:"omitempty,ip"`
	OperatingSystem string         `json:"operating_system" binding:"omitempty,max=255"`
	Owner           string         `json:"owner" binding:"omitempty,max=255"`
	Criticality     string         `json:"criticality" binding:"omitempty,oneof=LOW MEDIUM HIGH CRITICAL"`
	Tags            []string       `json:"tags"`
	Metadata        map[string]any `json:"metadata"`
}

type assetRecord struct {
	ID              uuid.UUID      `json:"id"`
	AssetCode       string         `json:"asset_code"`
	Name            string         `json:"name"`
	AssetType       string         `json:"asset_type"`
	Hostname        *string        `json:"hostname,omitempty"`
	IPAddress       *string        `json:"ip_address,omitempty"`
	OperatingSystem *string        `json:"operating_system,omitempty"`
	Owner           *string        `json:"owner,omitempty"`
	Criticality     string         `json:"criticality"`
	Status          string         `json:"status"`
	Tags            []string       `json:"tags"`
	Metadata        map[string]any `json:"metadata"`
	LastSeenAt      *time.Time     `json:"last_seen_at,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

func NewHandler() *Handler {
	return &Handler{}
}

func RegisterRoutes(protected *gin.RouterGroup, handler *Handler, databasePool *pgxpool.Pool) {
	if protected == nil || handler == nil || databasePool == nil {
		return
	}
	handler.db = databasePool

	group := protected.Group("/assets")
	group.GET("", middleware.RequirePermission(databasePool, "THREAT_VIEW"), handler.ListAssets)
	group.GET("/:id", middleware.RequirePermission(databasePool, "THREAT_VIEW"), handler.GetAsset)
	group.POST("", middleware.RequirePermission(databasePool, "THREAT_MANAGE"), handler.CreateAsset)
}

func (h *Handler) ListAssets(c *gin.Context) {
	organizationID, ok := contextUUID(c, "organization_id")
	if !ok {
		return
	}
	rows, err := h.db.Query(c, `SELECT id,asset_code,name,asset_type,hostname,host(ip_address),operating_system,owner,criticality,status,tags,metadata,last_seen_at,created_at,updated_at FROM security_assets WHERE organization_id=$1 ORDER BY updated_at DESC LIMIT 500`, organizationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Unable to list assets"})
		return
	}
	defer rows.Close()
	items := make([]assetRecord, 0)
	for rows.Next() {
		item, scanErr := scanAsset(rows)
		if scanErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Unable to read asset records"})
			return
		}
		items = append(items, item)
	}
	if rows.Err() != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Unable to list assets"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Assets retrieved successfully", "data": items})
}

func (h *Handler) CreateAsset(c *gin.Context) {
	organizationID, ok := contextUUID(c, "organization_id")
	if !ok {
		return
	}
	actorID, ok := contextUUID(c, "user_id")
	if !ok {
		return
	}
	var request assetRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid asset payload", "error": err.Error()})
		return
	}
	request.AssetCode = strings.TrimSpace(request.AssetCode)
	request.Name = strings.TrimSpace(request.Name)
	request.AssetType = strings.ToUpper(strings.TrimSpace(request.AssetType))
	request.Criticality = strings.ToUpper(strings.TrimSpace(request.Criticality))
	if request.Criticality == "" {
		request.Criticality = "MEDIUM"
	}
	row := h.db.QueryRow(c, `INSERT INTO security_assets(id,organization_id,asset_code,name,asset_type,hostname,ip_address,operating_system,owner,criticality,tags,metadata,created_by) VALUES($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,'')::inet,NULLIF($8,''),NULLIF($9,''),$10,$11,$12,$13) RETURNING id,asset_code,name,asset_type,hostname,host(ip_address),operating_system,owner,criticality,status,tags,metadata,last_seen_at,created_at,updated_at`, uuid.New(), organizationID, request.AssetCode, request.Name, request.AssetType, strings.TrimSpace(request.Hostname), strings.TrimSpace(request.IPAddress), strings.TrimSpace(request.OperatingSystem), strings.TrimSpace(request.Owner), request.Criticality, request.Tags, request.Metadata, actorID)
	item, err := scanAsset(row)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"success": false, "message": "Asset could not be created", "error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"success": true, "message": "Asset created successfully", "data": item})
}

func (h *Handler) GetAsset(c *gin.Context) {
	organizationID, ok := contextUUID(c, "organization_id")
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid asset ID"})
		return
	}
	item, err := scanAsset(h.db.QueryRow(c, `SELECT id,asset_code,name,asset_type,hostname,host(ip_address),operating_system,owner,criticality,status,tags,metadata,last_seen_at,created_at,updated_at FROM security_assets WHERE organization_id=$1 AND id=$2`, organizationID, id))
	if err == pgx.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "Asset not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Unable to retrieve asset"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Asset retrieved successfully", "data": item})
}

type rowScanner interface{ Scan(...any) error }

func scanAsset(row rowScanner) (assetRecord, error) {
	var item assetRecord
	err := row.Scan(&item.ID, &item.AssetCode, &item.Name, &item.AssetType, &item.Hostname, &item.IPAddress, &item.OperatingSystem, &item.Owner, &item.Criticality, &item.Status, &item.Tags, &item.Metadata, &item.LastSeenAt, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func contextUUID(c *gin.Context, key string) (uuid.UUID, bool) {
	value, exists := c.Get(key)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Authentication context is missing"})
		return uuid.Nil, false
	}
	switch typed := value.(type) {
	case uuid.UUID:
		if typed != uuid.Nil {
			return typed, true
		}
	case string:
		parsed, err := uuid.Parse(typed)
		if err == nil {
			return parsed, true
		}
	}
	c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Authentication context is invalid"})
	return uuid.Nil, false
}
