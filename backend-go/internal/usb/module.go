package usb

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/operational"
)

type Handler struct {
	db      *pgxpool.Pool
	actions operational.ActionStore
}
type deviceRequest struct {
	DeviceIdentifier string         `json:"device_identifier" binding:"required,max=255"`
	Vendor           string         `json:"vendor" binding:"omitempty,max=255"`
	Product          string         `json:"product" binding:"omitempty,max=255"`
	SerialNumber     string         `json:"serial_number" binding:"omitempty,max=255"`
	Metadata         map[string]any `json:"metadata"`
}
type policyRequest struct {
	Mode           string   `json:"mode" binding:"required,oneof=ALLOW_ALL BLOCK_UNKNOWN ALLOW_LIST_ONLY"`
	AllowedDevices []string `json:"allowed_devices"`
}

func NewHandler() *Handler { return &Handler{} }
func RegisterRoutes(p *gin.RouterGroup, h *Handler, db *pgxpool.Pool) {
	if p == nil || h == nil || db == nil {
		return
	}
	h.db = db
	h.actions = operational.ActionStore{DB: db, Module: "USB"}
	g := p.Group("/usb")
	g.GET("/devices", middleware.RequirePermission(db, "USB_VIEW"), h.ListDevices)
	g.POST("/devices", middleware.RequirePermission(db, "USB_MANAGE"), h.RegisterDevice)
	g.POST("/devices/block", middleware.RequirePermission(db, "USB_BLOCK"), h.BlockDevice)
	g.GET("/actions", middleware.RequirePermission(db, "USB_VIEW"), h.ListActions)
	g.POST("/policy", middleware.RequirePermission(db, "USB_MANAGE"), h.UpdatePolicy)
	g.GET("/policy", middleware.RequirePermission(db, "USB_VIEW"), h.GetPolicy)
}
func (h *Handler) RegisterDevice(c *gin.Context) {
	org, ok := operational.ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	actor, ok := operational.ContextUUID(c, "user_id")
	if !ok {
		return
	}
	var q deviceRequest
	if e := c.ShouldBindJSON(&q); e != nil {
		c.JSON(400, gin.H{"success": false, "message": "Invalid USB device payload", "error": e.Error()})
		return
	}
	id := uuid.New()
	e := h.db.QueryRow(c, `INSERT INTO usb_devices(id,organization_id,device_identifier,vendor,product,serial_number,reported_by,metadata) VALUES($1,$2,$3,NULLIF($4,''),NULLIF($5,''),NULLIF($6,''),$7,$8) ON CONFLICT(organization_id,device_identifier) DO UPDATE SET vendor=EXCLUDED.vendor,product=EXCLUDED.product,serial_number=EXCLUDED.serial_number,last_seen_at=NOW(),metadata=EXCLUDED.metadata RETURNING id`, id, org, strings.TrimSpace(q.DeviceIdentifier), strings.TrimSpace(q.Vendor), strings.TrimSpace(q.Product), strings.TrimSpace(q.SerialNumber), actor, q.Metadata).Scan(&id)
	if e != nil {
		operational.Failure(c, 500, "USB device could not be stored")
		return
	}
	c.JSON(201, gin.H{"success": true, "message": "USB device stored", "data": gin.H{"id": id}})
}
func (h *Handler) ListDevices(c *gin.Context) {
	org, ok := operational.ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	rows, e := h.db.Query(c, `SELECT id,device_identifier,vendor,product,serial_number,status,first_seen_at,last_seen_at,metadata FROM usb_devices WHERE organization_id=$1 ORDER BY last_seen_at DESC`, org)
	if e != nil {
		operational.Failure(c, 500, "USB devices could not be loaded")
		return
	}
	defer rows.Close()
	items := make([]gin.H, 0)
	for rows.Next() {
		var id uuid.UUID
		var identifier, status string
		var vendor, product, serial *string
		var first, last time.Time
		var metadata map[string]any
		if e = rows.Scan(&id, &identifier, &vendor, &product, &serial, &status, &first, &last, &metadata); e != nil {
			operational.Failure(c, 500, "USB devices could not be read")
			return
		}
		items = append(items, gin.H{"id": id, "device_identifier": identifier, "vendor": vendor, "product": product, "serial_number": serial, "status": status, "first_seen_at": first, "last_seen_at": last, "metadata": metadata})
	}
	c.JSON(200, gin.H{"success": true, "devices": items})
}
func (h *Handler) BlockDevice(c *gin.Context) { h.actions.Create(c, "BLOCK_DEVICE") }
func (h *Handler) ListActions(c *gin.Context) { h.actions.List(c) }
func (h *Handler) UpdatePolicy(c *gin.Context) {
	org, ok := operational.ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	actor, ok := operational.ContextUUID(c, "user_id")
	if !ok {
		return
	}
	var q policyRequest
	if e := c.ShouldBindJSON(&q); e != nil {
		c.JSON(400, gin.H{"success": false, "message": "Invalid USB policy", "error": e.Error()})
		return
	}
	_, e := h.db.Exec(c, `INSERT INTO usb_policies(organization_id,mode,allowed_devices,updated_by) VALUES($1,$2,$3,$4) ON CONFLICT(organization_id) DO UPDATE SET mode=EXCLUDED.mode,allowed_devices=EXCLUDED.allowed_devices,updated_by=EXCLUDED.updated_by,updated_at=NOW()`, org, q.Mode, q.AllowedDevices, actor)
	if e != nil {
		operational.Failure(c, 500, "USB policy could not be updated")
		return
	}
	c.JSON(200, gin.H{"success": true, "message": "USB policy updated"})
}
func (h *Handler) GetPolicy(c *gin.Context) {
	org, ok := operational.ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	var mode string
	var devices []string
	var updatedBy uuid.UUID
	var updatedAt time.Time
	e := h.db.QueryRow(c, `SELECT mode,allowed_devices,updated_by,updated_at FROM usb_policies WHERE organization_id=$1`, org).Scan(&mode, &devices, &updatedBy, &updatedAt)
	if e == pgx.ErrNoRows {
		c.JSON(200, gin.H{"success": true, "data": nil})
		return
	}
	if e != nil {
		operational.Failure(c, 500, "USB policy could not be loaded")
		return
	}
	c.JSON(200, gin.H{"success": true, "data": gin.H{"mode": mode, "allowed_devices": devices, "updated_by": updatedBy, "updated_at": updatedAt}})
}
