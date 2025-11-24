from fastapi import FastAPI, Request, Form, Depends, WebSocket, WebSocketDisconnect, HTTPException, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from passlib.context import CryptContext
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel, Field, validator
from pydantic_settings import BaseSettings
import aiosqlite
import os
import subprocess
import signal
import time
import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Optional, Set
import re

# ==================== Configuration ====================
class Settings(BaseSettings):
    """Application settings with validation"""
    jwt_secret: str = Field(..., min_length=32)
    admin_user: str = Field(default="admin")
    admin_password: str = Field(..., min_length=8)
    db_path: str = Field(default="/app/data/database.db")
    hls_path: str = Field(default="/var/www/hls")
    log_level: str = Field(default="INFO")
    rate_limit_per_minute: int = Field(default=60)
    max_concurrent_streams: int = Field(default=10)

    class Config:
        env_file = ".env"
        case_sensitive = False

    @validator('jwt_secret')
    def validate_jwt_secret(cls, v):
        if v in ['replace_me', 'changeme', 'CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32']:
            raise ValueError('JWT_SECRET must be changed from default value! Generate with: openssl rand -hex 32')
        return v

    @validator('admin_password')
    def validate_admin_password(cls, v):
        if v in ['changeme', 'CHANGE_ME_TO_STRONG_PASSWORD_MIN_16_CHARS']:
            raise ValueError('ADMIN_PASSWORD must be changed from default value!')
        return v

# Load and validate settings
try:
    settings = Settings()
except Exception as e:
    print(f"ERROR: Configuration validation failed: {e}")
    print("Please check your .env file and ensure all required variables are set correctly.")
    print("See .env.example for reference.")
    exit(1)

# ==================== Logging Configuration ====================
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==================== Constants ====================
JWT_ALGORITHM = 'HS256'
FFMPEG_SCRIPT = '/app/scripts/start_transcode.sh'

# ==================== Pydantic Models ====================
class StreamKeyModel(BaseModel):
    """Validation model for stream keys"""
    key: str = Field(..., min_length=3, max_length=64)

    @validator('key')
    def validate_stream_key(cls, v):
        # Only allow alphanumeric, hyphens, and underscores
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Stream key must contain only alphanumeric characters, hyphens, and underscores')
        return v

class LoginModel(BaseModel):
    """Validation model for login credentials"""
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1)

# ==================== Database Connection Pool ====================
class DatabasePool:
    """Thread-safe async database connection pool"""
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = asyncio.Lock()

    async def get_connection(self):
        """Get a database connection"""
        return await aiosqlite.connect(self.db_path)

    async def execute(self, query: str, params: tuple = ()):
        """Execute a query and return results"""
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(query, params) as cursor:
                    return await cursor.fetchall()

    async def execute_write(self, query: str, params: tuple = ()):
        """Execute a write query"""
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(query, params)
                await db.commit()

    async def execute_one(self, query: str, params: tuple = ()):
        """Execute a query and return one result"""
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(query, params) as cursor:
                    return await cursor.fetchone()

db_pool = DatabasePool(settings.db_path)

# ==================== Process Manager ====================
class ProcessManager:
    """Manages FFmpeg transcoding processes"""
    def __init__(self):
        self.processes: dict[str, subprocess.Popen] = {}
        self._lock = asyncio.Lock()

    async def start_process(self, stream_key: str) -> Optional[int]:
        """Start a transcoding process for a stream"""
        async with self._lock:
            if stream_key in self.processes:
                logger.warning(f"Process already running for stream: {stream_key}")
                return None

            try:
                cmd = ['/bin/sh', FFMPEG_SCRIPT, stream_key]
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid  # Create new process group for better cleanup
                )
                self.processes[stream_key] = proc
                logger.info(f"Started transcoding process for {stream_key} (PID: {proc.pid})")
                return proc.pid
            except Exception as e:
                logger.error(f"Failed to start process for {stream_key}: {e}")
                return None

    async def stop_process(self, stream_key: str, pid: Optional[int] = None) -> bool:
        """Stop a transcoding process"""
        async with self._lock:
            proc = self.processes.pop(stream_key, None)

            # Try to kill by stored process
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                    logger.info(f"Terminated process for {stream_key}")
                    return True
                except subprocess.TimeoutExpired:
                    proc.kill()
                    logger.warning(f"Force killed process for {stream_key}")
                    return True
                except Exception as e:
                    logger.error(f"Error terminating process for {stream_key}: {e}")

            # Fallback to PID if provided
            if pid:
                try:
                    os.killpg(os.getpgid(pid), signal.SIGTERM)
                    logger.info(f"Terminated process group for PID {pid}")
                    return True
                except ProcessLookupError:
                    logger.debug(f"Process {pid} already terminated")
                    return True
                except Exception as e:
                    logger.error(f"Error killing PID {pid}: {e}")

            return False

    async def cleanup_orphans(self):
        """Cleanup orphaned processes"""
        async with self._lock:
            for stream_key, proc in list(self.processes.items()):
                if proc.poll() is not None:
                    logger.info(f"Cleaning up terminated process for {stream_key}")
                    del self.processes[stream_key]

process_manager = ProcessManager()

# ==================== WebSocket Manager ====================
class ConnectionManager:
    """Manages WebSocket connections with proper error handling"""
    def __init__(self):
        self.active: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self.active.add(ws)
        logger.debug(f"WebSocket connected. Total connections: {len(self.active)}")

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            self.active.discard(ws)
        logger.debug(f"WebSocket disconnected. Total connections: {len(self.active)}")

    async def broadcast(self, msg: dict):
        """Broadcast message to all connected clients"""
        async with self._lock:
            disconnected = set()
            for ws in self.active:
                try:
                    await ws.send_json(msg)
                except Exception as e:
                    logger.error(f"Error broadcasting to WebSocket: {e}")
                    disconnected.add(ws)

            # Remove disconnected websockets
            self.active -= disconnected

manager = ConnectionManager()

# ==================== Prometheus Metrics ====================
streams_started = Counter('streams_started_total', 'Total streams started')
streams_stopped = Counter('streams_stopped_total', 'Total streams stopped')
active_streams = Gauge('active_streams', 'Current number of active streams')
auth_attempts = Counter('auth_attempts_total', 'Total authentication attempts', ['status'])

# ==================== Password Hashing ====================
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

# ==================== Database Initialization ====================
async def init_db():
    """Initialize database schema"""
    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute('''
            CREATE TABLE IF NOT EXISTS streams (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE NOT NULL,
                status TEXT NOT NULL DEFAULT 'offline',
                pid INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        await db.execute('''
            CREATE INDEX IF NOT EXISTS idx_streams_key ON streams(key)
        ''')
        await db.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        await db.commit()
    logger.info("Database initialized")

async def create_admin_if_missing():
    """Create admin user if not exists"""
    row = await db_pool.execute_one(
        'SELECT id FROM admins WHERE username=?',
        (settings.admin_user,)
    )

    if not row:
        password_hash = pwd_context.hash(settings.admin_password)
        await db_pool.execute_write(
            'INSERT INTO admins (username, password_hash) VALUES (?,?)',
            (settings.admin_user, password_hash)
        )
        logger.info(f"Created admin user: {settings.admin_user}")
    else:
        logger.debug(f"Admin user already exists: {settings.admin_user}")

# ==================== Application Lifecycle ====================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting Stream Orchestrator...")
    os.makedirs(os.path.dirname(settings.db_path), exist_ok=True)
    await init_db()
    await create_admin_if_missing()
    logger.info("Application started successfully")

    yield

    # Shutdown
    logger.info("Shutting down...")
    # Cleanup all running processes
    rows = await db_pool.execute('SELECT key, pid FROM streams WHERE status=?', ('live',))
    for row in rows:
        await process_manager.stop_process(row['key'], row['pid'])
    logger.info("Application shutdown complete")

# ==================== FastAPI Application ====================
app = FastAPI(
    title='Stream Orchestrator',
    version='2.0.0',
    lifespan=lifespan
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Static files and templates
app.mount('/static', StaticFiles(directory='static'), name='static')
templates = Jinja2Templates(directory='templates')

# ==================== Authentication ====================
async def authenticate_user(username: str, password: str) -> bool:
    """Authenticate user credentials"""
    try:
        row = await db_pool.execute_one(
            'SELECT password_hash FROM admins WHERE username=?',
            (username,)
        )

        if not row:
            auth_attempts.labels(status='failed').inc()
            return False

        verified = pwd_context.verify(password, row['password_hash'])
        auth_attempts.labels(status='success' if verified else 'failed').inc()
        return verified
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        auth_attempts.labels(status='error').inc()
        return False

def create_access_token(data: dict, expires_sec: int = 3600) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    to_encode.update({'exp': time.time() + expires_sec})
    return jwt.encode(to_encode, settings.jwt_secret, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> Optional[dict]:
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError as e:
        logger.debug(f"Token verification failed: {e}")
        return None

# ==================== Routes ====================
@app.post('/login')
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
async def login(request: Request):
    """User login endpoint"""
    try:
        data = await request.form()
        login_data = LoginModel(
            username=data.get('username', ''),
            password=data.get('password', '')
        )
    except Exception as e:
        logger.warning(f"Invalid login request: {e}")
        raise HTTPException(status_code=400, detail='Invalid request format')

    if not await authenticate_user(login_data.username, login_data.password):
        logger.warning(f"Failed login attempt for user: {login_data.username}")
        raise HTTPException(status_code=401, detail='Invalid credentials')

    token = create_access_token({'sub': login_data.username})
    logger.info(f"Successful login for user: {login_data.username}")
    return JSONResponse({'access_token': token})

@app.post('/on_publish')
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
async def on_publish(request: Request):
    """Handle stream publish event from Nginx RTMP"""
    try:
        form = await request.form()
        stream_key = form.get('name', '').strip()

        if not stream_key:
            logger.warning("Publish request with missing stream key")
            return JSONResponse({'status': 'error', 'message': 'missing name'}, status_code=400)

        # Validate stream key
        try:
            StreamKeyModel(key=stream_key)
        except Exception as e:
            logger.warning(f"Invalid stream key format: {stream_key}")
            return JSONResponse({'status': 'error', 'message': 'invalid stream key format'}, status_code=400)

        # Check if stream key exists
        row = await db_pool.execute_one('SELECT key, status FROM streams WHERE key=?', (stream_key,))
        if not row:
            logger.warning(f"Publish attempt with unknown stream key: {stream_key}")
            return JSONResponse({'status': 'error', 'message': 'Invalid stream key'}, status_code=403)

        # Check concurrent stream limit
        active_count = await db_pool.execute_one('SELECT COUNT(*) as count FROM streams WHERE status=?', ('live',))
        if active_count and active_count['count'] >= settings.max_concurrent_streams:
            logger.warning(f"Max concurrent streams limit reached")
            return JSONResponse({'status': 'error', 'message': 'Max concurrent streams reached'}, status_code=429)

        # Start transcoding process
        pid = await process_manager.start_process(stream_key)

        if pid:
            await db_pool.execute_write(
                "UPDATE streams SET status='live', pid=?, updated_at=CURRENT_TIMESTAMP WHERE key=?",
                (pid, stream_key)
            )
            streams_started.inc()
            active_streams.inc()

            # Broadcast to WebSocket clients
            await manager.broadcast({'event': 'started', 'stream': stream_key})

            logger.info(f"Stream published: {stream_key}")
            return JSONResponse({'status': 'ok'})
        else:
            logger.error(f"Failed to start transcoding for: {stream_key}")
            return JSONResponse({'status': 'error', 'message': 'Failed to start transcoding'}, status_code=500)

    except Exception as e:
        logger.error(f"Error in on_publish: {e}", exc_info=True)
        return JSONResponse({'status': 'error', 'message': 'Internal server error'}, status_code=500)

@app.post('/on_done')
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
async def on_done(request: Request):
    """Handle stream stop event from Nginx RTMP"""
    try:
        form = await request.form()
        stream_key = form.get('name', '').strip()

        if not stream_key:
            logger.warning("Done request with missing stream key")
            return JSONResponse({'status': 'error', 'message': 'missing name'}, status_code=400)

        # Get stream info
        row = await db_pool.execute_one('SELECT pid FROM streams WHERE key=?', (stream_key,))

        # Stop transcoding process
        if row and row['pid']:
            await process_manager.stop_process(stream_key, row['pid'])

        # Update database
        await db_pool.execute_write(
            "UPDATE streams SET status='offline', pid=NULL, updated_at=CURRENT_TIMESTAMP WHERE key=?",
            (stream_key,)
        )

        streams_stopped.inc()
        active_streams.dec()

        # Broadcast to WebSocket clients
        await manager.broadcast({'event': 'stopped', 'stream': stream_key})

        logger.info(f"Stream stopped: {stream_key}")
        return JSONResponse({'status': 'ok'})

    except Exception as e:
        logger.error(f"Error in on_done: {e}", exc_info=True)
        return JSONResponse({'status': 'error', 'message': 'Internal server error'}, status_code=500)

@app.get('/', response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page"""
    try:
        rows = await db_pool.execute('SELECT key, status, updated_at FROM streams ORDER BY id')
        return templates.TemplateResponse('dashboard.html', {
            'request': request,
            'streams': rows
        })
    except Exception as e:
        logger.error(f"Error loading dashboard: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Error loading dashboard")

@app.post('/add_stream')
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
async def add_stream(request: Request, key: str = Form(...), token: str = Form(None)):
    """Add a new stream key (requires authentication)"""
    try:
        if not token:
            raise HTTPException(status_code=401, detail='Missing token')

        payload = verify_token(token)
        if not payload:
            raise HTTPException(status_code=401, detail='Invalid token')

        # Validate stream key
        try:
            stream_data = StreamKeyModel(key=key)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f'Invalid stream key: {e}')

        # Add stream
        await db_pool.execute_write(
            'INSERT OR IGNORE INTO streams (key, status) VALUES (?,?)',
            (stream_data.key, 'offline')
        )

        logger.info(f"Stream key added: {stream_data.key} by {payload.get('sub')}")
        return RedirectResponse('/', status_code=303)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding stream: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Error adding stream")

@app.get('/health')
async def health_check():
    """Health check endpoint"""
    try:
        # Check database connection
        await db_pool.execute_one('SELECT 1')
        return JSONResponse({
            'status': 'healthy',
            'database': 'connected',
            'active_streams': len(process_manager.processes)
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            {'status': 'unhealthy', 'error': str(e)},
            status_code=503
        )

@app.get('/metrics')
async def metrics():
    """Prometheus metrics endpoint"""
    data = generate_latest()
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)

@app.websocket('/ws')
async def websocket_endpoint(ws: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(ws)
    try:
        while True:
            # Keep connection alive
            await ws.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(ws)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await manager.disconnect(ws)
