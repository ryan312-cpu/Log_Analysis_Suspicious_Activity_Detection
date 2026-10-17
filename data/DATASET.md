# Dataset Documentation

## Project

Log Analysis & Suspicious Activity Detection

## Purpose

This dataset is used to develop and validate the project's
log parsing, normalization, suspicious activity detection,
alert generation, and evaluation components.

## Dataset Sources

The initial dataset consists of controlled synthetic security
events created specifically for development and testing.

The project may later incorporate appropriately licensed
public cybersecurity datasets.

## Log Categories

### Authentication

Contains login success and failure events.

Examples:
- LOGIN_SUCCESS
- LOGIN_FAILED

### Web

Contains HTTP request activity.

Examples:
- GET
- POST
- HTTP 200
- HTTP 403
- HTTP 404

### Application

Contains application access, request, and error events.

### Security

Contains firewall allow/deny events.

### System

Contains service status and system-level events.

## Ground Truth

Each event will eventually receive a classification.

Possible labels:

- normal
- suspicious

Suspicious events may additionally receive an attack category.

## Planned Suspicious Categories

1. brute_force
2. password_spraying
3. successful_login_after_failures
4. unusual_login_time
5. restricted_resource_access
6. excessive_requests
7. repeated_4xx
8. repeated_5xx
9. suspicious_firewall_activity
10. repeated_access_denied

## Common Event Fields

The normalized dataset will use fields including:

- event_id
- timestamp
- event_type
- event_category
- source_ip
- source_port
- destination_ip
- destination_port
- username
- hostname
- service
- action
- status
- http_method
- http_path
- response_code
- user_agent
- source_type
- raw_log

## Data Integrity

Raw logs are preserved so that normalized events can always
be traced back to their original log entry.

## Intended Use

The dataset is intended for authorized defensive security
research, academic development, testing, and evaluation.

## Dataset Processing Pipeline

The dataset follows the following processing stages:

1. Raw log collection
2. Event generation
3. Ground-truth labeling
4. Schema validation
5. Timestamp validation
6. Field normalization
7. Normalized CSV generation
8. Normal/suspicious dataset separation

## Dataset Integrity

The validation process checks:

- Required columns
- Timestamp validity
- Label validity
- Missing values
- Event category consistency

## Ground Truth

The initial ground truth is generated during controlled
dataset creation.

Normal events are labelled:

`normal`

Suspicious events are labelled:

`suspicious`

Suspicious events may contain an additional attack category
and explanation.

## Reproducibility

The dataset can be regenerated using:

```text
python src/dataset/generator.py
```

The normalized dataset can be regenerated using:

```text
python src/dataset/validator.py
```

The test datasets can be regenerated using:

```text
python src/dataset/splitter.py
```

---

# Phase 1 is now almost complete

Your architecture now looks like:

```text
             RAW LOGS
                 │
                 ▼
       ┌──────────────────┐
       │ Dataset Generator│
       └────────┬─────────┘
                ▼
        Labelled Dataset
                │
                ▼
       ┌──────────────────┐
       │ Dataset Validator│
       └────────┬─────────┘
                ▼
       Normalized Dataset
                │
                ▼
       ┌──────────────────┐
       │ Dataset Splitter │
       └────────┬─────────┘
                │
          ┌─────┴─────┐
          ▼           ▼
       NORMAL     SUSPICIOUS
        TEST          TEST
```

### What comes immediately after this

**Phase 2 — Multi-Format Log Parsing.**

This is a major step.

We'll build actual parsers for:

```text
authentication.log
        ↓
Authentication Parser

web_access.log
        ↓
Web/Apache-style Parser

application.log
        ↓
Application Parser

security.log
        ↓
Security/Firewall Parser

system.log
        ↓
System Parser
```

All of them will output the same:

```text
NormalizedEvent
```

That is the point where the project starts behaving like a real **log analytics platform rather than a collection of CSV scripts**.
