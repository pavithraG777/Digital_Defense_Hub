package operational

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

type connectorAction struct {
	ID, OrganizationID                       uuid.UUID
	TargetType, TargetID, ActionType, Reason string
	Parameters                               map[string]any
}

func (w *ConnectorWorker) processIntegrationAction(parent context.Context) error {
	tx, err := w.db.Begin(parent)
	if err != nil {
		return err
	}
	defer tx.Rollback(parent)
	var action connectorAction
	err = tx.QueryRow(parent, `SELECT id,organization_id,target_type,target_id,action_type,reason,parameters FROM operational_actions WHERE module='INTEGRATION' AND (status='REQUESTED' OR (status='RUNNING' AND lease_expires_at<NOW())) ORDER BY requested_at FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&action.ID, &action.OrganizationID, &action.TargetType, &action.TargetID, &action.ActionType, &action.Reason, &action.Parameters)
	if err != nil {
		return err
	}
	_, err = tx.Exec(parent, `UPDATE operational_actions SET status='RUNNING',worker_id=$2,lease_expires_at=NOW()+($3*interval '1 second'),attempt_count=attempt_count+1,error_code=NULL,error_message=NULL WHERE id=$1`, action.ID, w.workerID, int(w.timeout.Seconds()))
	if err != nil {
		return err
	}
	_, err = tx.Exec(parent, `INSERT INTO operational_action_events(id,organization_id,action_id,event_type,previous_status,new_status,worker_id,details) VALUES($1,$2,$3,'CONNECTOR_CLAIMED','REQUESTED','RUNNING',$4,$5)`, uuid.New(), action.OrganizationID, action.ID, w.workerID, map[string]any{"action_type": action.ActionType})
	if err != nil {
		return err
	}
	if err = tx.Commit(parent); err != nil {
		return err
	}

	endpoint := ""
	switch action.ActionType {
	case "SEND_TO_SIEM":
		endpoint = w.siemURL
	case "CREATE_TICKET":
		endpoint = w.ticketURL
	default:
		return w.finishIntegration(parent, action, "FAILED", "UNSUPPORTED_INTEGRATION_ACTION", "unsupported integration action", nil)
	}
	if endpoint == "" {
		return w.finishIntegration(parent, action, "FAILED", "INTEGRATION_CONNECTOR_UNAVAILABLE", action.ActionType+" connector URL is not configured", nil)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return w.finishIntegration(parent, action, "FAILED", "INVALID_CONNECTOR_URL", "configured connector URL is invalid", nil)
	}
	payload := map[string]any{"action_id": action.ID, "organization_id": action.OrganizationID, "target_type": action.TargetType, "target_id": action.TargetID, "reason": action.Reason, "parameters": action.Parameters}
	encoded, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(parent, w.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return w.finishIntegration(parent, action, "FAILED", "CONNECTOR_REQUEST_FAILED", err.Error(), nil)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Idempotency-Key", action.ID.String())
	if w.integrationToken != "" {
		request.Header.Set("Authorization", "Bearer "+w.integrationToken)
	}
	response, err := w.httpClient.Do(request)
	if err != nil {
		return w.finishIntegration(parent, action, "FAILED", "CONNECTOR_UNAVAILABLE", err.Error(), nil)
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if readErr != nil {
		return w.finishIntegration(parent, action, "FAILED", "CONNECTOR_RESPONSE_FAILED", readErr.Error(), nil)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return w.finishIntegration(parent, action, "FAILED", "CONNECTOR_HTTP_ERROR", fmt.Sprintf("HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body))), nil)
	}
	result := map[string]any{"http_status": response.StatusCode}
	if len(bytes.TrimSpace(body)) > 0 {
		var decoded any
		if json.Unmarshal(body, &decoded) == nil {
			result["response"] = decoded
		} else {
			result["response_text"] = strings.TrimSpace(string(body))
		}
	}
	return w.finishIntegration(parent, action, "COMPLETED", "", "", result)
}

func (w *ConnectorWorker) finishIntegration(ctx context.Context, action connectorAction, status, code, message string, result map[string]any) error {
	if result == nil {
		result = map[string]any{}
	}
	tx, err := w.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var errorCode, errorMessage any
	if code != "" {
		errorCode = code
	}
	if message != "" {
		errorMessage = message
	}
	command, err := tx.Exec(ctx, `UPDATE operational_actions SET status=$3,result=$4,error_code=$5,error_message=$6,completed_at=NOW(),lease_expires_at=NULL WHERE id=$1 AND worker_id=$2 AND status='RUNNING'`, action.ID, w.workerID, status, result, errorCode, errorMessage)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return errors.New("connector lost ownership of integration action")
	}
	_, err = tx.Exec(ctx, `INSERT INTO operational_action_events(id,organization_id,action_id,event_type,previous_status,new_status,worker_id,details) VALUES($1,$2,$3,$4,'RUNNING',$5,$6,$7)`, uuid.New(), action.OrganizationID, action.ID, "CONNECTOR_"+status, status, w.workerID, map[string]any{"error_code": code})
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
