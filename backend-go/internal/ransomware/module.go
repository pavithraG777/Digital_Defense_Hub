package ransomware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/middleware"
	"github.com/pavithraG777/cyber-security-platform/backend/internal/preencryption"
)

type scanFile struct {
	Name         string `json:"name" binding:"required,max=500"`
	RelativePath string `json:"relative_path" binding:"max=1000"`
	Size         int64  `json:"size" binding:"min=0"`
	ModifiedAt   int64  `json:"modified_at" binding:"min=0"`
}
type scanRequest struct {
	FolderName string     `json:"folder_name" binding:"required,max=255"`
	Files      []scanFile `json:"files" binding:"required,max=25000,dive"`
}
type activityRequest struct {
	FolderName            string `json:"folder_name" binding:"required,max=255"`
	TotalFiles            int    `json:"total_files" binding:"min=0,max=25000"`
	WindowSeconds         int    `json:"window_seconds" binding:"required,min=1,max=300"`
	ModifiedCount         int    `json:"modified_count" binding:"min=0"`
	CreatedCount          int    `json:"created_count" binding:"min=0"`
	DeletedCount          int    `json:"deleted_count" binding:"min=0"`
	RenamedCount          int    `json:"renamed_count" binding:"min=0"`
	ExtensionChangedCount int    `json:"extension_changed_count" binding:"min=0"`
}
type finding struct {
	File     string `json:"file"`
	Reason   string `json:"reason"`
	Severity string `json:"severity"`
}

var suspiciousExtensions = []string{".encrypted", ".locked", ".lockbit", ".crypt", ".crypto", ".ryk", ".ryuk", ".wncry", ".conti", ".zepto", ".cerber", ".akira", ".blackcat"}

func RegisterRoutes(protected *gin.RouterGroup, detector *preencryption.Handler, pool *pgxpool.Pool) {
	if protected == nil || detector == nil || pool == nil {
		return
	}
	routes := protected.Group("/ransomware")
	view := middleware.RequirePermission(pool, "THREAT_VIEW")
	routes.GET("/detections", view, detector.ListDetections)
	routes.GET("/detections/:detection_id", view, detector.GetDetection)
	routes.GET("/detections/:detection_id/details", view, detector.GetDetectionDetails)
	routes.GET("/scans", view, listScans(pool))
	routes.POST("/scans", middleware.RequirePermission(pool, "ORGANIZATION_MANAGE_SECURITY"), createScan(pool))
	routes.POST("/activity-alerts", middleware.RequirePermission(pool, "ORGANIZATION_MANAGE_SECURITY"), createActivityAlert(pool))
}

func createActivityAlert(pool *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		organizationID, userID, ok := requestIdentity(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "authenticated organization and user are required"})
			return
		}
		var request activityRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid live activity window"})
			return
		}
		totalChanges := request.ModifiedCount + request.CreatedCount + request.DeletedCount + request.RenamedCount + request.ExtensionChangedCount
		if totalChanges == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "no file activity was reported"})
			return
		}
		risk := request.ModifiedCount*3 + request.CreatedCount + request.DeletedCount*6 + request.RenamedCount*7 + request.ExtensionChangedCount*12
		if totalChanges >= 10 {
			risk += 20
		}
		if totalChanges >= 25 {
			risk += 20
		}
		if risk > 100 {
			risk = 100
		}
		verdict := "SUSPICIOUS"
		if risk >= 70 {
			verdict = "RANSOMWARE_DETECTED"
		} else if risk >= 35 {
			verdict = "HIGH_RISK"
		}
		findings := []finding{}
		if request.ModifiedCount > 0 {
			findings = append(findings, finding{File: request.FolderName, Reason: fmt.Sprintf("%d files modified within %d seconds", request.ModifiedCount, request.WindowSeconds), Severity: "HIGH"})
		}
		if request.RenamedCount > 0 {
			findings = append(findings, finding{File: request.FolderName, Reason: fmt.Sprintf("%d possible bulk rename operations", request.RenamedCount), Severity: "HIGH"})
		}
		if request.ExtensionChangedCount > 0 {
			findings = append(findings, finding{File: request.FolderName, Reason: fmt.Sprintf("%d file extensions changed", request.ExtensionChangedCount), Severity: "CRITICAL"})
		}
		if request.DeletedCount > 0 {
			findings = append(findings, finding{File: request.FolderName, Reason: fmt.Sprintf("%d files deleted", request.DeletedCount), Severity: "HIGH"})
		}
		payload, _ := json.Marshal(findings)
		id, completed := uuid.New(), time.Now().UTC()
		_, err := pool.Exec(c, `INSERT INTO ransomware_scans (id,organization_id,requested_by,folder_name,total_files,suspicious_files,risk_score,verdict,findings,completed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, organizationID, userID, strings.TrimSpace(request.FolderName), request.TotalFiles, totalChanges, risk, verdict, payload, completed)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "unable to save ransomware activity alert"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"success": true, "data": gin.H{"id": id, "folder_name": request.FolderName, "total_files": request.TotalFiles, "suspicious_files": totalChanges, "risk_score": risk, "verdict": verdict, "findings": findings, "completed_at": completed}})
	}
}

func createScan(pool *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		organizationID, userID, ok := requestIdentity(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "authenticated organization and user are required"})
			return
		}
		var request scanRequest
		if err := c.ShouldBindJSON(&request); err != nil || len(request.Files) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "select a non-empty folder to scan"})
			return
		}
		findings := inspectFiles(request.Files)
		riskScore, verdict := scanVerdict(findings, len(request.Files))
		payload, _ := json.Marshal(findings)
		id := uuid.New()
		completed := time.Now().UTC()
		_, err := pool.Exec(c, `INSERT INTO ransomware_scans (id,organization_id,requested_by,folder_name,total_files,suspicious_files,risk_score,verdict,findings,completed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, organizationID, userID, strings.TrimSpace(request.FolderName), len(request.Files), len(findings), riskScore, verdict, payload, completed)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "unable to save ransomware scan"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"success": true, "data": gin.H{"id": id, "folder_name": request.FolderName, "total_files": len(request.Files), "suspicious_files": len(findings), "risk_score": riskScore, "verdict": verdict, "findings": findings, "completed_at": completed}})
	}
}

func listScans(pool *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		organizationID, _, ok := requestIdentity(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "authenticated organization is required"})
			return
		}
		rows, err := pool.Query(c, `SELECT id,folder_name,total_files,suspicious_files,risk_score,verdict,findings,completed_at FROM ransomware_scans WHERE organization_id=$1 ORDER BY completed_at DESC LIMIT 100`, organizationID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "unable to load scan history"})
			return
		}
		defer rows.Close()
		items := make([]gin.H, 0)
		for rows.Next() {
			var id uuid.UUID
			var folder, verdict string
			var total, suspicious, risk int
			var raw []byte
			var completed time.Time
			if rows.Scan(&id, &folder, &total, &suspicious, &risk, &verdict, &raw, &completed) != nil {
				continue
			}
			var findings []finding
			_ = json.Unmarshal(raw, &findings)
			items = append(items, gin.H{"id": id, "folder_name": folder, "total_files": total, "suspicious_files": suspicious, "risk_score": risk, "verdict": verdict, "findings": findings, "completed_at": completed})
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"scans": items}})
	}
}

func inspectFiles(files []scanFile) []finding {
	result := make([]finding, 0)
	for _, file := range files {
		name := strings.ToLower(strings.TrimSpace(file.Name))
		reason, severity := "", ""
		for _, extension := range suspiciousExtensions {
			if strings.HasSuffix(name, extension) {
				reason, severity = "Known ransomware-style encrypted extension", "HIGH"
				break
			}
		}
		if (strings.Contains(name, "readme") && (strings.Contains(name, "decrypt") || strings.Contains(name, "recover") || strings.Contains(name, "ransom"))) || strings.Contains(name, "how_to_decrypt") {
			reason, severity = "Possible ransom instruction note", "CRITICAL"
		}
		if reason != "" {
			path := file.RelativePath
			if strings.TrimSpace(path) == "" {
				path = file.Name
			}
			result = append(result, finding{File: path, Reason: reason, Severity: severity})
		}
	}
	return result
}
func scanVerdict(findings []finding, total int) (int, string) {
	if len(findings) == 0 {
		return 0, "CLEAN"
	}
	critical := 0
	for _, value := range findings {
		if value.Severity == "CRITICAL" {
			critical++
		}
	}
	risk := len(findings)*12 + critical*25
	if total > 0 && len(findings)*100/total >= 10 {
		risk += 20
	}
	if risk > 100 {
		risk = 100
	}
	if risk >= 70 {
		return risk, "RANSOMWARE_DETECTED"
	}
	if risk >= 35 {
		return risk, "HIGH_RISK"
	}
	return risk, "SUSPICIOUS"
}
func requestIdentity(c *gin.Context) (uuid.UUID, uuid.UUID, bool) {
	organizationID, organizationOK := contextUUID(c, "organization_id")
	userID, userOK := contextUUID(c, "user_id")
	return organizationID, userID, organizationOK && userOK
}
func contextUUID(c *gin.Context, key string) (uuid.UUID, bool) {
	value, exists := c.Get(key)
	if !exists {
		return uuid.Nil, false
	}
	switch typed := value.(type) {
	case uuid.UUID:
		return typed, typed != uuid.Nil
	case string:
		parsed, err := uuid.Parse(typed)
		return parsed, err == nil && parsed != uuid.Nil
	default:
		return uuid.Nil, false
	}
}
