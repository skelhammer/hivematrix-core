"""
Session management for HiveMatrix Core
Provides revokable sessions with TTL
"""
import time
import secrets
from threading import Lock

class SessionManager:
    """
    Manages active sessions with revocation support.
    Uses in-memory storage (for production, use Redis or database).
    """

    def __init__(self, max_session_lifetime=3600):
        self.sessions = {}  # session_id -> session_data
        self.lock = Lock()
        self.max_session_lifetime = max_session_lifetime

    def create_session(self, user_data):
        """
        Create a new session and return session_id.
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

    def validate_session(self, session_id):
        """
        Check if session is valid (exists, not expired, not revoked).
        Returns session data if valid, None otherwise.
        """
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

    def revoke_session(self, session_id):
        """
        Revoke a session (logout).
        """
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id]['revoked'] = True
                return True
            return False

    def cleanup_expired(self):
        """
        Remove expired sessions from memory.
        Should be called periodically.
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

    def get_active_session_count(self):
        """
        Get number of active (non-expired, non-revoked) sessions.
        """
        current_time = int(time.time())

        with self.lock:
            count = sum(
                1 for session in self.sessions.values()
                if session['expires_at'] >= current_time and not session['revoked']
            )
            return count
