package honeytoken

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// investigationSummary returns tenant-scoped trigger aggregates plus the
// threat and incident records created from the selected deception asset.
func investigationSummary(db *pgxpool.Pool, reference string) gin.HandlerFunc {
	return func(c *gin.Context) {
		org, ok := honeytokenUUIDFromContext(c, "organization_id")
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "Organization information is missing"})
			return
		}
		id, err := uuid.Parse(strings.TrimSpace(c.Param("id")))
		if err != nil || id == uuid.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Invalid deception record ID"})
			return
		}
		var total, suspicious, critical int
		q := `SELECT count(*),count(*) FILTER (WHERE is_suspicious),count(*) FILTER (WHERE severity='CRITICAL') FROM file_events WHERE organization_id=$1 AND ` + reference + `=$2`
		if err := db.QueryRow(c, q, org, id).Scan(&total, &suspicious, &critical); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Unable to load trigger aggregate"})
			return
		}
		threats, err := db.Query(c, `SELECT DISTINCT t.id,t.threat_code,t.title,t.severity,t.status,t.last_detected_at FROM threats t JOIN threat_file_events tf ON tf.threat_id=t.id JOIN file_events f ON f.id=tf.file_event_id WHERE t.organization_id=$1 AND f.`+reference+`=$2 AND t.deleted_at IS NULL ORDER BY t.last_detected_at DESC`, org, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Unable to load linked threats"})
			return
		}
		defer threats.Close()
		threatItems := []gin.H{}
		threatIDs := []uuid.UUID{}
		for threats.Next() {
			var tid uuid.UUID
			var code, title, severity, status string
			var at any
			if err := threats.Scan(&tid, &code, &title, &severity, &status, &at); err != nil {
				continue
			}
			threatIDs = append(threatIDs, tid)
			threatItems = append(threatItems, gin.H{"id": tid, "threat_code": code, "title": title, "severity": severity, "status": status, "last_detected_at": at})
		}
		incidentItems := []gin.H{}
		incidentIDs := []uuid.UUID{}
		if len(threatIDs) > 0 {
			rows, e := db.Query(c, `SELECT DISTINCT i.id,i.incident_code,i.title,i.severity,i.status,i.updated_at FROM incidents i JOIN incident_threats it ON it.incident_id=i.id WHERE i.organization_id=$1 AND it.threat_id=ANY($2) ORDER BY i.updated_at DESC`, org, threatIDs)
			if e == nil {
				defer rows.Close()
				for rows.Next() {
					var iid uuid.UUID
					var code, title, severity, status string
					var at any
					if rows.Scan(&iid, &code, &title, &severity, &status, &at) == nil {
						incidentIDs = append(incidentIDs, iid)
						incidentItems = append(incidentItems, gin.H{"id": iid, "incident_code": code, "title": title, "severity": severity, "status": status, "updated_at": at})
					}
				}
			}
		}
		caseItems := []gin.H{}
		if len(incidentIDs) > 0 {
			rows, e := db.Query(c, `SELECT DISTINCT ic.id,ic.case_number,ic.title,ic.priority,ic.status,ic.updated_at FROM investigation_cases ic JOIN investigation_case_incidents ici ON ici.case_id=ic.id WHERE ic.organization_id=$1 AND ici.incident_id=ANY($2) AND ic.deleted_at IS NULL ORDER BY ic.updated_at DESC`, org, incidentIDs)
			if e == nil {
				defer rows.Close()
				for rows.Next() {
					var cid uuid.UUID
					var number, title, priority, status string
					var at any
					if rows.Scan(&cid, &number, &title, &priority, &status, &at) == nil {
						caseItems = append(caseItems, gin.H{"id": cid, "case_number": number, "title": title, "priority": priority, "status": status, "updated_at": at})
					}
				}
			}
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Deception investigation context retrieved", "data": gin.H{"trigger_aggregate": gin.H{"total": total, "suspicious": suspicious, "critical": critical}, "threats": threatItems, "incidents": incidentItems, "investigation_cases": caseItems}})
	}
}
