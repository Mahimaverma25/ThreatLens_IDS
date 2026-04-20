# ThreatLens Viva Summary

## Is Snort used?
Yes. The production ingestion path tails Snort alert files and sends parsed events to the backend.

## How does ThreatLens work?
Snort -> realtime agent -> Node/Express API -> MongoDB -> detection/enrichment -> Socket.io -> React dashboard.

## Why was real-time failing before?
The ML model file was empty, live and ML paths were disconnected, and `logs:new` emitted inconsistent payload shapes.

## Which algorithm is used?
A Random Forest classifier is used in the Python IDS engine for anomaly classification, with rule-based detection in the Node backend.

## What testing/validation is used?
Manual end-to-end validation with sample Snort logs, agent-to-backend ingest, dashboard updates, and the `train_model.py` artifact generation step.
