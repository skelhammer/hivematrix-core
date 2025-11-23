"""
Session management for HiveMatrix Core
Provides revokable sessions with TTL using Redis for persistence
"""
import time
import secrets
import json
from typing import Dict, Any, Optional
import redis

class SessionManager:
    """
    Manages active sessions with revocation support.
    Uses Redis for persistent storage (survives service restarts).
    """

    def __init__(self, max_session_lifetime: int = 3600):
        """
        Initialize the session manager with Redis backend.

        Args:
            max_session_lifetime: Maximum session lifetime in seconds (default: 3600 = 1 hour)
        """
        self.max_session_lifetime = max_session_lifetime

        # Connect to Redis with automatic fallback to in-memory if Redis unavailable
        try:
            self.redis = redis.Redis(
                host='localhost',
                port=6379,
                db=0,
                decode_responses=True,
                socket_connect_timeout=2
            )
            # Test connection
            self.redis.ping()
            self.use_redis = True
            print("SessionManager: Using Redis for persistent sessions")
        except (redis.ConnectionError, redis.TimeoutError) as e:
            print(f"SessionManager: Redis unavailable ({e}), falling back to in-memory sessions")
            self.redis = None
            self.use_redis = False
            # Fallback to in-memory dict if Redis is not available
            self.sessions: Dict[str, Dict[str, Any]] = {}
            from threading import Lock
            self.lock = Lock()

    def create_session(self, user_data: Dict[str, Any]) -> str:
        """
        Create a new session and return session_id.

        Args:
            user_data: Dictionary containing user information to store in session

        Returns:
            str: Unique session ID (URL-safe token)
        """
        session_id = secrets.token_urlsafe(32)
        current_time = int(time.time())

        session_data = {
            'user_data': user_data,
            'created_at': current_time,
            'expires_at': current_time + self.max_session_lifetime,
            'revoked': False
        }

        if self.use_redis:
            # Store in Redis with automatic expiration
            try:
                self.redis.setex(
                    f"session:{session_id}",
                    self.max_session_lifetime,
                    json.dumps(session_data)
                )
            except redis.RedisError as e:
                print(f"SessionManager: Redis error during create_session: {e}")
                # Fall through to in-memory storage
                self.use_redis = False

        if not self.use_redis:
            # Fallback: in-memory storage
            with self.lock:
                self.sessions[session_id] = session_data

        return session_id

    def validate_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Check if session is valid (exists, not expired, not revoked).

        Args:
            session_id: Session ID to validate

        Returns:
            Optional[Dict[str, Any]]: Session user data if valid, None otherwise
        """
        if self.use_redis:
            # Validate from Redis
            try:
                session_json = self.redis.get(f"session:{session_id}")
                if not session_json:
                    return None

                session = json.loads(session_json)

                # Check if revoked
                if session.get('revoked'):
                    return None

                # Check if expired (Redis TTL should handle this, but double-check)
                if session['expires_at'] < int(time.time()):
                    self.redis.delete(f"session:{session_id}")
                    return None

                return session['user_data']

            except (redis.RedisError, json.JSONDecodeError) as e:
                print(f"SessionManager: Redis error during validate_session: {e}")
                # Fall through to in-memory
                self.use_redis = False

        # Fallback: in-memory validation
        with self.lock:
            session = self.sessions.get(session_id)

            if not session:
                return None

            # Check if expired
            if session['expires_at'] < int(time.time()):
                del self.sessions[session_id]
                return None

            # Check if revoked
            if session['revoked']:
                return None

            return session['user_data']

    def revoke_session(self, session_id: str) -> bool:
        """
        Revoke a session (logout).

        Args:
            session_id: Session ID to revoke

        Returns:
            bool: True if session was found and revoked, False if not found
        """
        if self.use_redis:
            # Revoke in Redis by marking as revoked (keep it until TTL expires for audit)
            try:
                session_json = self.redis.get(f"session:{session_id}")
                if not session_json:
                    return False

                session = json.loads(session_json)
                session['revoked'] = True

                # Update in Redis with remaining TTL
                ttl = self.redis.ttl(f"session:{session_id}")
                if ttl > 0:
                    self.redis.setex(
                        f"session:{session_id}",
                        ttl,
                        json.dumps(session)
                    )
                    return True
                return False

            except (redis.RedisError, json.JSONDecodeError) as e:
                print(f"SessionManager: Redis error during revoke_session: {e}")
                # Fall through to in-memory
                self.use_redis = False

        # Fallback: in-memory revocation
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id]['revoked'] = True
                return True
            return False

    def cleanup_expired(self) -> int:
        """
        Remove expired sessions.

        For Redis: Redis automatically removes expired keys via TTL (no manual cleanup needed).
        For in-memory: Manually scan and remove expired sessions.

        Returns:
            int: Number of expired sessions removed
        """
        if self.use_redis:
            # Redis handles expiration automatically via TTL
            # No cleanup needed - return 0
            return 0

        # Fallback: in-memory cleanup
        current_time = int(time.time())

        with self.lock:
            expired = [
                sid for sid, session in self.sessions.items()
                if session['expires_at'] < current_time
            ]

            for sid in expired:
                del self.sessions[sid]

            return len(expired)

    def get_active_session_count(self) -> int:
        """
        Get number of active (non-expired, non-revoked) sessions.

        Returns:
            int: Count of currently active sessions
        """
        if self.use_redis:
            # Count active sessions in Redis
            try:
                current_time = int(time.time())
                keys = self.redis.keys("session:*")
                count = 0

                for key in keys:
                    session_json = self.redis.get(key)
                    if session_json:
                        try:
                            session = json.loads(session_json)
                            if session['expires_at'] >= current_time and not session.get('revoked'):
                                count += 1
                        except json.JSONDecodeError:
                            continue

                return count

            except redis.RedisError as e:
                print(f"SessionManager: Redis error during get_active_session_count: {e}")
                # Fall through to in-memory
                self.use_redis = False

        # Fallback: in-memory count
        current_time = int(time.time())

        with self.lock:
            count = sum(
                1 for session in self.sessions.values()
                if session['expires_at'] >= current_time and not session['revoked']
            )
            return count
