# API Reference

## REST API Endpoints

### GET /
Root endpoint - API information

### GET /status
Get system status

### GET /alerts
Get security alerts

### POST /rules
Create firewall rule

### DELETE /rules/{rule_id}
Delete firewall rule

## Authentication

API authentication can be enabled via `API_ENABLE_AUTH` setting.

## Rate Limiting

API requests are rate-limited to prevent abuse.

