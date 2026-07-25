from sentinel.domain import SecurityEvent
from sentinel.profiling import EntityBehaviorProfile


class ProfileDeviationExtractor:
    """Compare an event against an entity's learned baseline."""

    def extract(
        self,
        event: SecurityEvent,
        profile: EntityBehaviorProfile,
    ) -> dict[str, float | int]:
        if event.entity_id != profile.entity_id:
            raise ValueError(
                "event entity does not match behavioral profile"
            )

        return {
            "is_new_ip": self._is_new_ip(
                event,
                profile,
            ),
            "is_new_resource": self._is_new_resource(
                event,
                profile,
            ),
            "is_new_device": self._is_new_device(
                event,
                profile,
            ),
            "device_fingerprint_mismatch": (
                self._device_fingerprint_mismatch(
                    event,
                    profile,
                )
            ),
            "hour_deviation": self._hour_deviation(
                event,
                profile,
            ),
            "session_duration_deviation": (
                self._session_duration_deviation(
                    event,
                    profile,
                )
            ),
        }

    @staticmethod
    def _is_new_ip(
        event: SecurityEvent,
        profile: EntityBehaviorProfile,
    ) -> int:
        return int(
            str(event.source_ip)
            not in profile.known_source_ips
        )

    @staticmethod
    def _is_new_resource(
        event: SecurityEvent,
        profile: EntityBehaviorProfile,
    ) -> int:
        return int(
            event.resource_accessed
            not in profile.known_resources
        )

    @staticmethod
    def _is_new_device(
        event: SecurityEvent,
        profile: EntityBehaviorProfile,
    ) -> int:
        fingerprint_id = (
            event.device_fingerprint.fingerprint_id
        )

        known_ids = {
            device.fingerprint_id
            for device in profile.known_devices
        }

        return int(fingerprint_id not in known_ids)

    @staticmethod
    def _device_fingerprint_mismatch(
        event: SecurityEvent,
        profile: EntityBehaviorProfile,
    ) -> int:
        incoming = event.device_fingerprint

        matching_devices = [
            device
            for device in profile.known_devices
            if (
                device.fingerprint_id
                == incoming.fingerprint_id
            )
        ]

        # A genuinely new device is handled separately.
        if not matching_devices:
            return 0

        for known in matching_devices:
            if (
                known.operating_system
                == incoming.operating_system
                and known.browser == incoming.browser
                and known.device_type
                == incoming.device_type
            ):
                return 0

        return 1

    @staticmethod
    def _hour_deviation(
        event: SecurityEvent,
        profile: EntityBehaviorProfile,
    ) -> float:
        event_hour = (
            event.timestamp.hour
            + event.timestamp.minute / 60.0
        )

        difference = abs(
            event_hour - profile.mean_hour
        )

        # Time-of-day wraps around midnight.
        return min(difference, 24.0 - difference)

    @staticmethod
    def _session_duration_deviation(
        event: SecurityEvent,
        profile: EntityBehaviorProfile,
    ) -> float:
        return abs(
            event.session_duration_seconds
            - profile.mean_session_duration
        )