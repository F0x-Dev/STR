# Security Guide

## Critical Security Requirements

### 1. Environment Configuration

**BEFORE DEPLOYING TO PRODUCTION:**

1. **Generate a secure JWT secret:**
   ```bash
   openssl rand -hex 32
   ```
   Add this to your `.env` file as `JWT_SECRET`

2. **Create a strong admin password:**
   - Minimum 16 characters
   - Include uppercase, lowercase, numbers, and special characters
   - Use a password manager to generate and store it

3. **Create your `.env` file:**
   ```bash
   cp .env.example .env
   # Edit .env with your secure values
   ```

### 2. Mandatory Configuration Checks

The application will **refuse to start** if:
- `JWT_SECRET` is set to default values (`replace_me`, `changeme`, etc.)
- `ADMIN_PASSWORD` is set to default values
- `JWT_SECRET` is less than 32 characters

### 3. Network Security

#### Docker Networks
The system uses three isolated networks:
- **frontend**: Public-facing services (proxy, dashboard)
- **backend**: Internal services (nginx-rtmp, ffmpeg) - **NOT accessible from outside**
- **monitoring**: Metrics and monitoring (prometheus, grafana)

#### Port Exposure
Only expose necessary ports:
- `80/443`: HTTPS proxy (public)
- `1935`: RTMP ingestion (should be firewalled to trusted IPs only)
- `8000`: Dashboard (should be behind proxy or VPN)
- `9090`: Prometheus (internal only - do NOT expose publicly)
- `3000`: Grafana (should be behind proxy with authentication)

### 4. RTMP Stream Security

#### Stream Key Management
- Stream keys are validated to contain only: `a-z`, `A-Z`, `0-9`, `-`, `_`
- Minimum length: 3 characters
- Maximum length: 64 characters
- Use cryptographically random stream keys:
  ```bash
  openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32
  ```

#### Rate Limiting
Default rate limits (configurable via `.env`):
- API endpoints: 60 requests/minute per IP
- Concurrent streams: 10 (configurable via `MAX_CONCURRENT_STREAMS`)

### 5. SSL/TLS Configuration

#### Production HTTPS Setup

1. **Obtain SSL certificates:**
   ```bash
   # Using certbot
   certbot certonly --standalone -d your.domain.com
   ```

2. **Update proxy configuration:**
   Edit `proxy/conf.d/default.conf`:
   - Replace `your.domain.example` with your actual domain
   - Ensure certificate paths match your setup

3. **Enable HTTP to HTTPS redirect:**
   Already configured in the default proxy config

#### SSL Best Practices
- Use TLS 1.2+ only (configured by default)
- Keep certificates auto-renewed
- Use strong cipher suites (configured in proxy)

### 6. Database Security

#### SQLite Permissions
The database file is stored at `/app/data/database.db` inside the container.

Ensure proper file permissions:
```bash
chmod 600 data/database.db  # If accessing from host
```

#### Backup Strategy
Regular backups are essential:
```bash
# Backup database
docker exec python-orchestrator sqlite3 /app/data/database.db ".backup /app/data/backup.db"
docker cp python-orchestrator:/app/data/backup.db ./backups/
```

### 7. Monitoring and Logging

#### Security Monitoring
Monitor these metrics in Prometheus/Grafana:
- `auth_attempts_total{status="failed"}` - Failed login attempts
- `auth_attempts_total{status="success"}` - Successful logins
- `streams_started_total` - Total streams started
- `active_streams` - Current active streams

#### Log Analysis
Check logs regularly for suspicious activity:
```bash
docker compose logs -f python-app | grep -i "failed\|error\|warning"
```

#### Alerts to Configure
Set up alerts for:
- Multiple failed login attempts from same IP
- Unusual number of concurrent streams
- Health check failures
- High CPU/memory usage

### 8. Production Deployment Checklist

- [ ] Generated secure `JWT_SECRET` (32+ characters)
- [ ] Set strong `ADMIN_PASSWORD` (16+ characters)
- [ ] Created `.env` file with production values
- [ ] Configured SSL certificates
- [ ] Updated domain in proxy configuration
- [ ] Enabled firewall rules (allow only necessary ports)
- [ ] Configured Prometheus alerts
- [ ] Set up log rotation
- [ ] Configured database backups
- [ ] Tested health checks
- [ ] Reviewed resource limits in docker-compose.yml
- [ ] Configured Grafana authentication
- [ ] Restricted Prometheus access (internal only)
- [ ] Set up monitoring for failed auth attempts
- [ ] Documented incident response procedures

### 9. Incident Response

#### Suspected Breach
If you suspect a security breach:

1. **Immediate actions:**
   ```bash
   # Stop all services
   docker compose down

   # Rotate all secrets
   openssl rand -hex 32  # New JWT_SECRET
   # Generate new admin password

   # Review logs
   docker compose logs python-app > incident-logs.txt
   ```

2. **Investigation:**
   - Check `auth_attempts_total` metrics for anomalies
   - Review database for unauthorized stream keys
   - Check system logs for unusual activity

3. **Recovery:**
   - Update all credentials
   - Rebuild containers
   - Restore database from last known good backup
   - Update firewall rules

### 10. Regular Maintenance

#### Weekly
- Review failed authentication logs
- Check resource usage metrics
- Verify backups are working

#### Monthly
- Update Docker images for security patches
- Review and rotate stream keys
- Audit user access logs
- Test disaster recovery procedures

#### Quarterly
- Update all dependencies
- Review and update security policies
- Conduct security audit
- Test incident response procedures

### 11. Dependency Security

#### Keeping Dependencies Updated
```bash
# Check for updates
pip list --outdated

# Update requirements.txt with new versions
# Test thoroughly before deploying
```

#### Known Vulnerabilities
Regularly check for CVEs:
- Monitor Python security advisories
- Check Docker image vulnerabilities
- Subscribe to security mailing lists for dependencies

### 12. Additional Hardening

#### Firewall Configuration
```bash
# Example UFW rules
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 1935/tcp from TRUSTED_IP  # Restrict RTMP
ufw enable
```

#### Fail2Ban Integration
Configure fail2ban to block repeated failed login attempts:
```ini
[streaming-app]
enabled = true
port = 8000
filter = streaming-app
logpath = /var/log/streaming-app.log
maxretry = 5
bantime = 3600
```

#### Docker Security
- Run containers as non-root user
- Enable Docker content trust
- Scan images for vulnerabilities
- Keep Docker engine updated

## Reporting Security Issues

If you discover a security vulnerability, please email security@yourdomain.com instead of using the issue tracker.

## Security Updates

This document is regularly updated. Check the git history for changes:
```bash
git log SECURITY.md
```

Last updated: 2025-11-24
