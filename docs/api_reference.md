# API Reference

The DDoS Defense Platform provides a REST API for system management, alert retrieval, and manual mitigation control. All endpoints are served over HTTP/HTTPS and return JSON responses.

## Base URL

Development: `http://localhost:8000`  
Production: `https://api.ddos-defense.internal`

## Authentication

In production, the API uses JWT tokens. Include the token in the `Authorization` header:
Authorization: Bearer <your-token>

text

For development, authentication can be disabled via configuration.

## Endpoints

### Health Check

#### `GET /health`

Returns the health status of the platform.

**Response:**

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "timestamp": 1700000000.0,
  "components": {
    "api": "healthy",
    "database": "healthy"
  }
}
Metrics
GET /metrics
Exports Prometheus metrics.

Response: Plain text in Prometheus exposition format.

Alerts
GET /alerts
List alerts with pagination and filtering.

Query Parameters:

Parameter	Type	Description
limit	integer	Maximum number of alerts to return (1–1000, default 100)
offset	integer	Number of alerts to skip (default 0)
severity	integer	Filter by severity (1–5)
type	string	Filter by alert type (e.g., volumetric, syn_flood)
Response:

json
{
  "total": 150,
  "alerts": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "type": "volumetric",
      "severity": 3,
      "confidence": 0.92,
      "target": "10.0.0.1",
      "description": "Potential volumetric DDoS attack detected targeting 10.0.0.1 with confidence 0.92 (High)",
      "timestamp": 1700000000.0,
      "details": {
        "attack_type": "udp_flood",
        "mbps": 1500
      }
    }
  ]
}
GET /alerts/{alert_id}
Retrieve a single alert by ID.

Path Parameters:

Parameter	Type	Description
alert_id	string	UUID of the alert
Response: Same as an alert object in the list.

Mitigation
POST /mitigation/apply
Manually apply a mitigation action.

Request Body:

json
{
  "action": "rate_limit",
  "target": "10.0.0.1",
  "duration": 300
}
Response:

json
{
  "success": true,
  "message": "Mitigation action rate_limit scheduled for 10.0.0.1",
  "action_id": "550e8400-e29b-41d4-a716-446655440001"
}
POST /mitigation/rollback/{action_id}
Rollback a previously applied mitigation action.

Path Parameters:

Parameter	Type	Description
action_id	string	UUID of the mitigation action
Response:

json
{
  "success": true,
  "message": "Rollback requested for action 550e8400-e29b-41d4-a716-446655440001",
  "action_id": "550e8400-e29b-41d4-a716-446655440001"
}
POST /mitigation/override
Enable or disable manual override of automatic mitigation.

Request Body:

json
{
  "enabled": true,
  "reason": "Manual override due to maintenance",
  "duration": 3600
}
Response:

json
{
  "success": true,
  "message": "Manual override enabled"
}
Configuration
GET /config
Retrieve current configuration settings.

Response:

json
{
  "environment": "production",
  "detection_thresholds": {
    "volumetric_mbps": 1000,
    "volumetric_pps": 500000,
    "entropy": 3.5
  },
  "mitigation_settings": {
    "auto_response": true,
    "dry_run": false,
    "rollback_delay": 300
  }
}
System Statistics
GET /stats
Get system runtime statistics.

Response:

json
{
  "uptime_seconds": 86400,
  "manual_override": false,
  "override_reason": null,
  "override_expiry": null,
  "timestamp": 1700000000.0
}
Error Handling
All endpoints return standard HTTP status codes. Error responses follow the format:

json
{
  "detail": "Error message describing the issue"
}
Common status codes:

200 – Success

400 – Bad request (invalid parameters)

401 – Unauthorized

403 – Forbidden

404 – Resource not found

500 – Internal server error

Rate Limiting
The API may enforce rate limits to prevent abuse. The default is 120 requests per minute. Exceeding the limit returns a 429 status.

Versioning
API versioning is not yet implemented. All endpoints are subject to change in future releases.