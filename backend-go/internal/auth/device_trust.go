package auth

import (
	"context"
	"github.com/google/uuid"
	"strings"
	"time"
)

type TrustedDevice struct {
	ID         uuid.UUID  `json:"id"`
	DeviceID   string     `json:"device_id"`
	DeviceName string     `json:"device_name"`
	Trusted    bool       `json:"trusted"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	TrustedAt  *time.Time `json:"trusted_at,omitempty"`
}

func (r *Repository) IsDeviceTrusted(ctx context.Context, user, org uuid.UUID, device string) (bool, error) {
	var trusted bool
	e := r.db.QueryRow(ctx, `SELECT trusted FROM authentication_trusted_devices WHERE user_id=$1 AND organization_id=$2 AND device_id=$3 AND revoked_at IS NULL`, user, org, strings.TrimSpace(device)).Scan(&trusted)
	if e != nil {
		return false, e
	}
	_, _ = r.db.Exec(ctx, `UPDATE authentication_trusted_devices SET last_seen_at=NOW() WHERE user_id=$1 AND organization_id=$2 AND device_id=$3`, user, org, device)
	return trusted, nil
}
func (r *Repository) RecordLoginRisk(ctx context.Context, user, org uuid.UUID, device, ip string, a AdaptiveLoginRiskAssessment) error {
	_, e := r.db.Exec(ctx, `INSERT INTO authentication_login_risk_events(id,user_id,organization_id,device_id,ip_address,risk_score,risk_level,risk_flags,requires_step_up)VALUES($1,$2,$3,NULLIF($4,''),NULLIF($5,'')::inet,$6,$7,$8,$9)`, uuid.New(), user, org, device, ip, a.RiskScore, a.RiskLevel, a.RiskFlags, a.RequiresStepUpMFA)
	return e
}
func (r *Repository) ListTrustedDevices(ctx context.Context, user, org uuid.UUID) ([]TrustedDevice, error) {
	rows, e := r.db.Query(ctx, `SELECT id,device_id,device_name,trusted,last_seen_at,trusted_at FROM authentication_trusted_devices WHERE user_id=$1 AND organization_id=$2 AND revoked_at IS NULL ORDER BY last_seen_at DESC`, user, org)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []TrustedDevice{}
	for rows.Next() {
		var d TrustedDevice
		if e = rows.Scan(&d.ID, &d.DeviceID, &d.DeviceName, &d.Trusted, &d.LastSeenAt, &d.TrustedAt); e != nil {
			return nil, e
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
func (r *Repository) RegisterTrustedDevice(ctx context.Context, user, org uuid.UUID, id, name string) (*TrustedDevice, error) {
	d := &TrustedDevice{ID: uuid.New(), DeviceID: strings.TrimSpace(id), DeviceName: strings.TrimSpace(name), Trusted: false, LastSeenAt: time.Now().UTC()}
	e := r.db.QueryRow(ctx, `INSERT INTO authentication_trusted_devices(id,user_id,organization_id,device_id,device_name,last_seen_at)VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(user_id,device_id) DO UPDATE SET device_name=EXCLUDED.device_name,last_seen_at=EXCLUDED.last_seen_at RETURNING id,trusted,trusted_at`, d.ID, user, org, d.DeviceID, d.DeviceName, d.LastSeenAt).Scan(&d.ID, &d.Trusted, &d.TrustedAt)
	return d, e
}
func (r *Repository) SetDeviceTrust(ctx context.Context, user, org, id uuid.UUID, trusted bool) error {
	_, e := r.db.Exec(ctx, `UPDATE authentication_trusted_devices SET trusted=$4,trusted_at=CASE WHEN $4 THEN NOW() ELSE NULL END,revoked_at=CASE WHEN $4 THEN NULL ELSE NOW() END WHERE user_id=$1 AND organization_id=$2 AND id=$3`, user, org, id, trusted)
	return e
}
