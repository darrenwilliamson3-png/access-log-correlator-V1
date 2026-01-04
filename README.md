# Access Log Correlator (V1)

## Overview
The **Access Log Correlator** is a Python-based security analysis tool that ingests structured
access logs, normalizes event data, validates schemas, and detects suspicious login patterns 
such as **failed login bursts within a defined time window**.

This project is designed as a **portfolio-grade, defensive tool**, emphasizing correctness, 
robustness, and pipeline compatibility over UI or visual output.

---
## Key Features
    * JSON-based access log ingestion
    * Strict schema validation (input and output)
    * Event normalization (timestamp parsing, result normalization)
    * Detection of failed login bursts by user and source IP
    * Configurable thresholds and time windows
    * Machine-readable JSON alert output
    * Deterministic exit codes for CI / automation use
---

## Example Use Case
```bash
python access_log_correlator_v1.py \
  --input test_access_events.json \
  --output-json alerts.json
```

Produces a structured alert report suitable for:
    * SOC analysis
    * SIEM ingestion
    * CI/CD security checks
    * Offline log analysis

---
## Output (alerts.json)
```json
{
  "summary": {
    "total_events": 10,
    "alerts_detected": 1
  },
  "alerts": [
    {
      "type": "failed_login_burst",
      "user": "dave",
      "source_ip": "198.51.100.23",
      "count": 3,
      "window_minutes": 5,
      "first_seen": "2026-01-04T11:00:00",
      "last_seen": "2026-01-04T11:02:00"
    }
  ]
}
```

---
## Design Decisions (V1)
This project deliberately prioritizes **robustness and correctness** over feature breadth.

### Schema-First Validation
    * All input events are validated against a strict schema before processing
    * All generated alerts conform to a defined alert schema
    * Invalid data fails fast with explicit error messages

### Defensive Programming
    * Explicit type checks and required-field enforcement
    * Clear separation between:
      * input validation
      * normalization
      * detection
      * export
    * Prevents silent failures and ambiguous results

### Pipeline-Friendly Execution
    * Minimal console output
    * JSON as the primary output artifact
    * Deterministic exit codes for automation and CI/CD pipelines

### Security-Oriented Correlation Logic
    * Correlation based on **(user, source_ip)** pairs
    * Sliding time window for failed login detection
    * Duplicate alert suppression to avoid alert storms

---
## Exit Codes
| Code | Meaning                              |
| ---: | ------------------------------------ |
|    0 | Success, no schema or runtime errors |
|    2 | Schema validation error              |
|    3 | Runtime error                        |

These exit codes allow the tool to be safely embedded in automated pipelines.

---
## Project Scope
This repository represents **V1** of the tool.

Deliberately out of scope for V1:
    * Streaming ingestion
    * GeoIP enrichment
    * Multiple alert types
    * SIEM-specific formatting
    * Configuration via external files

These are intentionally deferred to future versions to keep V1 stable and auditable.

---
## Technologies Used
    * Python 3.x
    * Standard library only (no external runtime dependencies)
    * JSON for input and output

---
## Why This Project Exists
This project was built to demonstrate:
    * Defensive coding practices
    * Schema-driven design
    * Security-focused reasoning
    * Real-world debugging and iteration
    * Effective use of AI-assisted development while maintaining ownership of design decisions

---
## Author
**Darren Williamson**
Portfolio project demonstrating Python tooling, data validation, and security log analysis.
Python Utility Development * Automation * Data Analysis * AI-assisted tooling
Uk Citizen / Spain-based / Remote
LinkedIn: https://www.linkedin.com/in/darren-williamson3/