package securityevents

import (
	"encoding/json"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestValidateNormalizedEvent(t *testing.T) {
	q := IngestRequest{EventID: uuid.New(), IdempotencyKey: "agent:42", Source: "endpoint", EventType: "PROCESS_START", SchemaVersion: CurrentSchemaVersion, ObservedAt: time.Now(), Entities: []Entity{{Type: "process", Value: "powershell.exe"}}, Payload: json.RawMessage(`{"pid":42}`)}
	if err := validate(&q); err != nil {
		t.Fatal(err)
	}
	if q.Entities[0].Type != "PROCESS" {
		t.Fatalf("entity was not normalized: %#v", q.Entities[0])
	}
}
func TestRejectUnsupportedSchemaAndEntity(t *testing.T) {
	q := IngestRequest{SchemaVersion: 99, Entities: []Entity{{Type: "UNKNOWN", Value: "x"}}, Payload: json.RawMessage(`{}`)}
	if validate(&q) == nil {
		t.Fatal("expected validation failure")
	}
	q.SchemaVersion = CurrentSchemaVersion
	if validate(&q) == nil {
		t.Fatal("expected entity validation failure")
	}
}
