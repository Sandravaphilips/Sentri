from datetime import timedelta

from django.utils import timezone

from security.models import SecurityEvent
from accounts.models import User


class CompromiseDetectionService:
    """
    Evaluates security events to determine if a user account
    should be flagged as compromised.
    """

    LOGIN_FAILURE_WINDOW = timedelta(minutes=10)

    SCOPE_VIOLATION_THRESHOLD = 3
    SCOPE_VIOLATION_WINDOW = timedelta(minutes=5)

    @classmethod
    def evaluate_user(cls, user: User) -> bool:
        """
        Evaluate all compromise rules for a user.
        Returns True if the user is newly marked as compromised.
        """

        if user.is_compromised:
            return False

        now = timezone.now()

        if cls._login_failure_rule(user, now):
            cls._mark_compromised(
                user,
                reason="Excessive login failures detected",
            )
            return True

        if cls._scope_violation_rule(user, now):
            cls._mark_compromised(
                user,
                reason="Repeated API scope violations detected",
            )
            return True

        if cls._api_key_misuse_rule(user):
            cls._mark_compromised(
                user,
                reason="API key misuse after revocation or expiry",
            )
            return True

        return False

    # ───────────────────────────────
    # Individual rules
    # ───────────────────────────────

    @classmethod
    def _login_failure_rule(cls, user, now):
        last_lock = SecurityEvent.objects.filter(
            user=user,
            event_type=SecurityEvent.EventType.ACCOUNT_LOCKED,
        ).order_by("-created_at").first()

        if not last_lock:
            return False

        unlock_event = SecurityEvent.objects.filter(
            user=user,
            event_type=SecurityEvent.EventType.ACCOUNT_UNLOCKED,
            created_at__gt=last_lock.created_at,
        ).order_by("created_at").first()

        qs = SecurityEvent.objects.filter(
            user=user,
            event_type=SecurityEvent.EventType.LOGIN_FAILED,
            created_at__gt=last_lock.created_at,
        )

        if unlock_event:
            qs = qs.filter(created_at__lt=unlock_event.created_at)

        failures_while_locked = qs.count()

        return failures_while_locked >= 2

    @classmethod
    def _scope_violation_rule(cls, user, now):
        since = now - cls.SCOPE_VIOLATION_WINDOW

        count = SecurityEvent.objects.filter(
            user=user,
            event_type=SecurityEvent.EventType.SCOPE_VIOLATION,
            created_at__gte=since,
        ).count()

        return count >= cls.SCOPE_VIOLATION_THRESHOLD

    @classmethod
    def _api_key_misuse_rule(cls, user):
        return SecurityEvent.objects.filter(
            user=user,
            event_type=SecurityEvent.EventType.API_KEY_AUTH_FAILED,
            metadata__reason__in=["key_revoked", "key_expired"],
        ).exists()

    # ───────────────────────────────
    # State mutation
    # ───────────────────────────────

    @staticmethod
    def _mark_compromised(user, reason):
        user.is_compromised = True
        user.compromise_reason = reason
        user.compromised_at = timezone.now()

        user.save(update_fields=[
            "is_compromised",
            "compromise_reason",
            "compromised_at",
        ])

        SecurityEvent.objects.create(
            event_type=SecurityEvent.EventType.COMPROMISE_DETECTED,
            severity=SecurityEvent.Severity.CRITICAL,
            user=user,
            metadata={"reason": reason},
        )
