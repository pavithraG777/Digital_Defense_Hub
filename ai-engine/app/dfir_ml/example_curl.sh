#!/bin/sh
# Example curl to call the DFIR ML service
curl -X POST http://localhost:8080/score \
  -H "Content-Type: application/json" \
  -d '{"file_event_rate": 5, "rename_rate": 2, "entropy_change": 3, "network_spike_ratio": 1.5, "honeytoken_hits": 1}'
