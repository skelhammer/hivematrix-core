"""
Session management for HiveMatrix Core
Provides revokable sessions with TTL
"""
import time
import secrets
import random
from threading import Lock, Thread, Event
from typing import Dict, Any, Optional

class SessionManager:
    """
    Manages active sessions with revocation support.
    Uses in-memory storage (for production, use Redis or database).
    """

    def __init__(self, max_session_lifetime: int = 3600):
        """
        Initialize the session manager.

        Args:
            max_session_lifetime: Maximum session lifetime in seconds (default: 3600 = 1 hour)
        """
        self.sessions: Dict[str, Dict[str, Any]] = {}  # session_id -> session_data
        self.lock = Lock()
        self.max_session_lifetime = max_session_lifetime

        # Scheduled cleanup thread
        self._cleanup_event = Event()
        self._cleanup_thread = Thread(target=self._scheduled_cleanup, daemon=True)
        self._cleanup_thread.start()

    def create_session(self, user_data: Dict[str, Any]) -> str:
        """
        Create a new session and return session_id.

        Args:
            user_data: Dictionary containing user information to store in session

        Returns:
            str: Unique session ID (URL-safe token)
        """
        session_id = secrets.token_urlsafe(32)

        with self.lock:
            self.sessions[session_id] = {
                'user_data': user_data,
                'created_at': int(time.time()),
                'expires_at': int(time.time()) + self.max_session_lifetime,
                'revoked': False
            }

        return session_id

    def validate_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Check if session is valid (exists, not expired, not revoked).

        Args:
            session_id: Session ID to validate

        Returns:
            Optional[Dict[str, Any]]: Session user data if valid, None otherwise
        """
        # Note: Expired sessions are cleaned up by scheduled background thread
        # No need for probabilistic cleanup here anymore

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
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id]['revoked'] = True
                return True
            return False

    def cleanup_expired(self) -> int:
        """
        Remove expired sessions from memory.

        Should be called periodically to prevent memory leaks.
        Currently called probabilistically during validate_session().

        Returns:
            int: Number of expired sessions removed
        """
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
        current_time = int(time.time())

        with self.lock:
            count = sum(
                1 for session in self.sessions.values()
                if session['expires_at'] >= current_time and not session['revoked']
            )
            return count

    def _scheduled_cleanup(self) -> None:
        """
        Background thread that periodically cleans up expired sessions.

        Runs every 5 minutes to prevent memory leaks.
        This replaces the probabilistic cleanup in validate_session().
        """
        while not self._cleanup_event.is_set():
            # Wait 5 minutes between cleanup runs (or until shutdown)
            self._cleanup_event.wait(300)

            if not self._cleanup_event.is_set():
                removed = self.cleanup_expired()
                # Optional: Log cleanup results (uncomment if logging available)
                # if removed > 0:
                #     print(f"Session cleanup: removed {removed} expired sessions")

    def shutdown(self) -> None:
        """
        Gracefully shutdown the session manager.

        Signals the cleanup thread to stop and waits for it to finish.
        Should be called when the application is shutting down.
        """
        self._cleanup_event.set()
        if self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=1)
