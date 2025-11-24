# Changelog

All notable changes to the Streaming Traffic Redirector project.

## [2.0.0] - 2025-11-24

### Security Improvements (CRITICAL)

#### Authentication & Authorization
- **BREAKING**: Application now refuses to start with default/weak credentials
- Added mandatory validation for `JWT_SECRET` (minimum 32 characters)
- Added mandatory validation for `ADMIN_PASSWORD` (minimum 8 characters)
- Removed hardcoded fallback secrets that could be exploited
- Implemented Pydantic-based configuration validation with `pydantic-settings`

#### Input Validation
- Added comprehensive input validation using Pydantic models
- Stream keys now validated to contain only alphanumeric characters, hyphens, and underscores
- Added length restrictions (3-64 characters) for stream keys
- Sanitized all user inputs to prevent injection attacks

#### Rate Limiting
- Implemented rate limiting on all endpoints using `slowapi`
- Default: 60 requests/minute per IP (configurable via `RATE_LIMIT_PER_MINUTE`)
- Rate limiting on authentication endpoints to prevent brute force attacks
- Configurable concurrent stream limits (default: 10)

#### Network Security
- Implemented network isolation with three separate Docker networks:
  - `frontend`: Public-facing services
  - `backend`: Internal services (isolated from internet)
  - `monitoring`: Metrics and monitoring services
- Backend network is now internal-only (not accessible from outside)

### Critical Bug Fixes

#### Database Thread Safety
- **FIXED**: SQLite `check_same_thread=False` causing potential race conditions
- Implemented async database connection pool using `aiosqlite`
- Added proper locking mechanisms for database operations
- All database operations now thread-safe and async

#### Async/Sync Context Issues
- **FIXED**: `asyncio.create_task()` called from synchronous context
- Refactored all async operations to use proper async context
- Removed threading in favor of async/await patterns
- Fixed WebSocket broadcast to properly handle async operations

#### Process Management
- **FIXED**: FFmpeg processes not properly cleaned up on stream stop
- Implemented `ProcessManager` class for centralized process handling
- Added process group creation (`os.setsid`) for better cleanup
- Added graceful shutdown with proper process termination
- Orphaned process cleanup on application shutdown

### New Features

#### Health Checks
- Added `/health` endpoint for application health monitoring
- Implemented Docker health checks for all services
- Health checks validate database connectivity
- Services now wait for dependencies to be healthy before starting

#### Logging
- Implemented structured logging with configurable levels
- Added contextual logging for all operations
- Authentication attempts tracked and logged
- Failed login attempts logged with IP information
- Log level configurable via `LOG_LEVEL` environment variable

#### Monitoring & Metrics
- Added new Prometheus metrics:
  - `auth_attempts_total{status}` - Track authentication attempts
  - `streams_stopped_total` - Track stopped streams
  - `active_streams` - Current number of active streams (Gauge)
- Enhanced Prometheus configuration with data retention
- Improved Grafana integration

#### Database Improvements
- Added database indexes for performance (`idx_streams_key`)
- Added timestamps: `created_at`, `updated_at`
- Automatic database schema initialization
- Improved database schema with better constraints

### Configuration & Operations

#### Environment Configuration
- Created `.env.example` with secure placeholder values
- Added comprehensive environment variable documentation
- Configuration now validated on startup with clear error messages
- Added support for `.env` file loading

#### Docker Compose
- Added health checks for all services
- Implemented resource limits (CPU and memory) for all containers
- Added resource reservations for guaranteed baseline performance
- Services now use dependency conditions (wait for healthy status)
- Added persistent volumes for Prometheus data

#### Resource Limits
| Service | CPU Limit | Memory Limit | CPU Reserved | Memory Reserved |
|---------|-----------|--------------|--------------|-----------------|
| nginx-rtmp | 2 cores | 1GB | 0.5 cores | 256MB |
| ffmpeg-worker | 4 cores | 4GB | 1 core | 512MB |
| python-app | 2 cores | 1GB | 0.5 cores | 256MB |
| prometheus | 1 core | 512MB | 0.25 cores | 128MB |
| grafana | 1 core | 512MB | 0.25 cores | 128MB |
| proxy | 1 core | 256MB | 0.25 cores | 64MB |

### Documentation

- Added comprehensive `SECURITY.md` with:
  - Security setup requirements
  - Production deployment checklist
  - Incident response procedures
  - Regular maintenance guidelines
  - Firewall configuration examples
  - SSL/TLS setup instructions

- Updated `README.md` with:
  - Prominent security warnings
  - Secure setup instructions
  - Credential generation examples
  - Enhanced feature documentation

- Added `.gitignore` to protect sensitive files:
  - Environment files (`.env`)
  - Database files
  - SSL certificates
  - HLS output data
  - Logs

### Dependency Updates

- Pinned all dependency versions in `requirements.txt`:
  - `fastapi==0.109.0`
  - `uvicorn[standard]==0.27.0`
  - `python-jose[cryptography]==3.3.0`
  - `passlib[bcrypt]==1.7.4`
  - `jinja2==3.1.3`
  - `prometheus_client==0.19.0`
  - `python-dotenv==1.0.1`
  - `anyio==4.2.0`

- Added new dependencies:
  - `slowapi==0.1.9` - Rate limiting
  - `pydantic==2.5.3` - Input validation
  - `pydantic-settings==2.1.0` - Configuration management
  - `aiosqlite==0.19.0` - Async SQLite support

### Architecture Changes

#### Application Lifecycle
- Implemented proper FastAPI lifespan management
- Automatic database initialization on startup
- Graceful shutdown with process cleanup
- Admin user creation on first run

#### WebSocket Manager
- Refactored `ConnectionManager` with async locking
- Improved error handling for disconnected clients
- Automatic cleanup of dead connections
- Proper WebSocket state management

#### Error Handling
- Added try-catch blocks for all critical operations
- HTTP exceptions with proper status codes
- Detailed error logging with stack traces
- User-friendly error messages

### Configuration Variables

New environment variables:
- `DB_PATH` - Database file path (default: `/app/data/database.db`)
- `LOG_LEVEL` - Logging level (default: `INFO`)
- `RATE_LIMIT_PER_MINUTE` - API rate limit (default: `60`)
- `MAX_CONCURRENT_STREAMS` - Max concurrent streams (default: `10`)
- `GRAFANA_ADMIN_PASSWORD` - Grafana admin password

### File Structure Changes

```
New files:
├── .gitignore                     # Git ignore rules
├── .env.example                   # Environment template
├── SECURITY.md                    # Security documentation
├── CHANGELOG.md                   # This file
└── data/
    ├── .gitkeep                   # Keep data directory in git
    └── hls/.gitkeep              # Keep hls directory in git

Modified files:
├── README.md                      # Updated documentation
├── docker-compose.yml             # Health checks, networks, limits
├── python-app/
│   ├── app.py                    # Complete rewrite with security fixes
│   └── requirements.txt          # Pinned versions + new dependencies
```

### Breaking Changes

1. **Environment Variables Required**
   - `JWT_SECRET` must be set to a value >= 32 characters
   - `ADMIN_PASSWORD` must be set to a value >= 8 characters
   - Application will exit with error if defaults are used

2. **Database Schema**
   - Added `created_at` and `updated_at` columns to `streams` table
   - Added indexes for performance
   - Existing databases will need migration (automatic on startup)

3. **API Changes**
   - Rate limiting enforced on all endpoints
   - Stream keys now validated (only alphanumeric, `-`, `_`)
   - Invalid stream keys will be rejected with 400 status

4. **Docker Compose**
   - Services now use health checks - may affect startup time
   - Resource limits enforced - may need adjustment for your hardware
   - Network isolation - services not directly accessible

### Migration Guide (v1.x to v2.0)

1. **Backup your data:**
   ```bash
   docker compose down
   cp -r data data.backup
   ```

2. **Generate secure credentials:**
   ```bash
   JWT_SECRET=$(openssl rand -hex 32)
   ADMIN_PASSWORD=$(openssl rand -base64 24)
   ```

3. **Create `.env` file:**
   ```bash
   cp .env.example .env
   # Edit .env with your secure values
   ```

4. **Update docker-compose.yml:**
   - Review resource limits
   - Adjust if needed for your hardware

5. **Rebuild and restart:**
   ```bash
   docker compose up -d --build
   ```

6. **Verify health:**
   ```bash
   curl http://localhost:8000/health
   docker compose ps
   ```

### Future Improvements

Planned for future releases:
- [ ] Role-based access control (RBAC)
- [ ] Multi-user support with API keys
- [ ] Stream recording API
- [ ] Redis-based job queue for FFmpeg workers
- [ ] Horizontal scaling support
- [ ] WebSocket chat integration
- [ ] Stream expiration and automatic cleanup
- [ ] Unit and integration tests
- [ ] CI/CD pipeline
- [ ] Kubernetes deployment manifests

### Notes

- This release focuses on security and stability
- All critical security issues from v1.x have been addressed
- Production deployment is now safe with proper configuration
- See SECURITY.md for deployment best practices

### Acknowledgments

- Security improvements based on OWASP best practices
- Thanks to the FastAPI, Prometheus, and Grafana communities

---

## [1.0.0] - Previous Release

- Initial release with basic streaming functionality
- RTMP ingestion with Nginx
- FFmpeg transcoding
- Basic FastAPI dashboard
- Prometheus/Grafana monitoring

**Note:** Version 1.0.0 had several critical security vulnerabilities and is not recommended for production use.
