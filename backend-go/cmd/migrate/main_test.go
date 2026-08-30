package main

import "testing"

func TestRequireRange(t *testing.T) {
	items := []migration{{name: "024_a.sql"}, {name: "025_b.sql"}, {name: "026_c.sql"}}
	if err := requireRange(items, 24, 26); err != nil {
		t.Fatal(err)
	}
	if err := requireRange(items, 24, 27); err == nil {
		t.Fatal("expected missing migration error")
	}
}

func TestFromNumber(t *testing.T) {
	items := []migration{{name: "001_a.sql"}, {name: "024_b.sql"}, {name: "025_c.sql"}}
	filtered := fromNumber(items, 24)
	if len(filtered) != 2 || filtered[0].name != "024_b.sql" {
		t.Fatalf("unexpected filtered migrations: %#v", filtered)
	}
}
