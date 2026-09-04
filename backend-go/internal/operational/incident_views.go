package operational

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ListIncidentStage returns real tenant-scoped incident records for a workflow
// stage. It deliberately projects the canonical incidents table so lifecycle
// modules cannot drift into contradictory copies of an incident.
func ListIncidentStage(c *gin.Context, db *pgxpool.Pool, stage string, statuses []string) {
	organizationID, ok := ContextUUID(c, "organization_id")
	if !ok {
		return
	}
	rows, err := db.Query(c, `SELECT id,incident_number,incident_title,incident_category,severity,priority,status,detection_source,lead_investigator_id,evidence_preserved,initial_findings,root_cause,containment_summary,resolution_summary,detected_at,investigation_started_at,contained_at,resolved_at,closed_at,updated_at FROM incidents WHERE organization_id=$1 AND deleted_at IS NULL AND (cardinality($2::text[])=0 OR status=ANY($2::text[])) ORDER BY updated_at DESC LIMIT 500`, organizationID, statuses)
	if err != nil {
		Failure(c, 500, "Unable to load "+stage+" records")
		return
	}
	defer rows.Close()
	items := make([]gin.H, 0)
	for rows.Next() {
		var id, number, title, category, severity, priority, status, source any
		var lead, evidence, findings, rootCause, containment, resolution any
		var detected, started, contained, resolved, closed, updated any
		if err = rows.Scan(&id, &number, &title, &category, &severity, &priority, &status, &source, &lead, &evidence, &findings, &rootCause, &containment, &resolution, &detected, &started, &contained, &resolved, &closed, &updated); err != nil {
			Failure(c, 500, "Unable to read "+stage+" records")
			return
		}
		items = append(items, gin.H{"id": id, "incident_number": number, "incident_title": title, "incident_category": category, "severity": severity, "priority": priority, "status": status, "detection_source": source, "lead_investigator_id": lead, "evidence_preserved": evidence, "initial_findings": findings, "root_cause": rootCause, "containment_summary": containment, "resolution_summary": resolution, "detected_at": detected, "investigation_started_at": started, "contained_at": contained, "resolved_at": resolved, "closed_at": closed, "updated_at": updated})
	}
	if rows.Err() != nil {
		Failure(c, 500, "Unable to load "+stage+" records")
		return
	}
	c.JSON(200, gin.H{"success": true, "message": stage + " records retrieved successfully", "data": items})
}
