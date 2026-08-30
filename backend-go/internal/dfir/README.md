# DFIR Module

This package implements a defensive DFIR and ransomware attribution capability for the Digital Defense Hub platform.

## Scope

The module intentionally focuses on:

- attack detection and forensic preservation
- evidence collection and integrity checks
- investigation timeline creation
- correlation among incidents, infrastructure, and behaviors
- explainable risk scoring
- legal and ethical cyber defense operations only

It does not perform offensive actions such as remote compromise, malware deployment, or unauthorized tracking.

## Core components

- `domain.go`: shared DFIR domain model types
- `detector.go`: behavioral detection rules and scoring engine
- `feature.go`: feature extraction helpers for event normalization
- `service.go`: service layer for incident/evidence/timeline workflows
- `handler.go`: REST handlers for assessment, incident APIs, ingest and scoring
- `repository.go`: persistence layer using PostgreSQL (optional)
- `worker.go`: async ingestion worker
- `routes.go`: route registration

## Example signal flow

1. a monitored endpoint emits a suspicious file-change or canary access event
2. `inferSignalsFromEvent` normalizes indicators into a signal set
3. `DetectSignals` applies known defensive patterns and returns a weighted risk score
4. the service creates or updates an incident with evidence and timeline entries
5. the worker can asynchronously handle event ingestion and ML enrichment when configured

## Defensive-only design requirements

- no exact physical location claims
- no exact hardware or device identification claims unless directly observed
- confidence-based inference only, not certainty
- evidence seals and hashes preserve integrity
- investigative reports are generated for legal/compliance use
