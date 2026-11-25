from __future__ import annotations

from datetime import timedelta

from freezegun import freeze_time

from django.contrib.auth import get_user_model
from django.test import TestCase as DjangoTestCase
from django.test import TransactionTestCase as DjangoTransactionTestCase
from django.utils import timezone

from django_otp.models import GenerateNotAllowed, VerifyNotAllowed


class OTPTestCaseMixin:
    """
    Utilities for dealing with custom user models.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.User = get_user_model()
        cls.USERNAME_FIELD = cls.User.USERNAME_FIELD

    def create_user(self, username, password, **kwargs):
        """
        Try to create a user, honoring the custom user model, if any.

        This may raise an exception if the user model is too exotic for our
        purposes.
        """
        return self.User.objects.create_user(username, password=password, **kwargs)


class TestCase(OTPTestCaseMixin, DjangoTestCase):
    pass


class TransactionTestCase(OTPTestCaseMixin, DjangoTransactionTestCase):
    pass


class TimestampTestMixin:
    """
    Generic tests for :class:`~django_otp.models.TimestampMixin`.

    Implementing tests must initialize `self.device` with the model instance to
    test and provide `valid_token` and `invalid_token` methods for verifying
    token behavior.

    Includes tests to:

    - Check automatic setting of `created_at` upon object creation.
    - Validate that `last_used_at` is initially None and updated only after
      successful token verification.
    - Ensure `set_last_used_timestamp` behaves correctly, respecting the
      `commit` parameter.

    """

    def setUp(self):
        self.device = None

    def valid_token(self):
        """Returns a valid token to pass to our device under test."""
        raise NotImplementedError()

    def invalid_token(self):
        """Returns an invalid token to pass to our device under test."""
        raise NotImplementedError()

    #
    # Tests
    #

    def test_created_at_set_on_creation(self):
        """Verify that the `created_at` field is automatically set upon creation."""
        self.assertIsNotNone(
            self.device.created_at, "created_at should be automatically set."
        )

    def test_last_used_at_initially_none(self):
        """Ensure `last_used_at` is None upon initial creation."""
        self.assertIsNone(
            self.device.last_used_at, "last_used_at should be None initially."
        )

    def test_set_last_used_timestamp_updates_field(self):
        """Check if `set_last_used_timestamp` correctly updates the `last_used_at` field."""
        self.device.set_last_used_timestamp(commit=True)
        self.device.refresh_from_db()  # Assuming it's a persisted model

        self.assertIsNotNone(
            self.device.last_used_at, "last_used_at should be updated."
        )

    def test_set_last_used_timestamp_without_commit(self):
        """
        Ensure `set_last_used_timestamp` updates `last_used_at` without persisting
        when commit=False.
        """
        original_last_used_at = self.device.last_used_at
        self.device.set_last_used_timestamp(commit=False)
        # Check in-memory update without saving
        self.assertNotEqual(
            self.device.last_used_at,
            original_last_used_at,
            "last_used_at should be updated in memory without commit.",
        )

        # Refresh from db to confirm it wasn't committed
        self.device.refresh_from_db()
        self.assertEqual(
            self.device.last_used_at,
            original_last_used_at,
            "last_used_at should not be updated in db without commit.",
        )

    def test_verify_token_successful_updates_last_used_at(self):
        """
        Verifying with a valid token updates 'last_used_at'.
        """
        valid_token = self.valid_token()  # Method to generate a valid token
        initial_last_used_at = self.device.last_used_at
        verified = self.device.verify_token(valid_token)

        self.assertTrue(verified, "Token should be verified successfully.")
        self.device.refresh_from_db()
        self.assertNotEqual(
            self.device.last_used_at,
            initial_last_used_at,
            "'last_used_at' should be updated on successful verification.",
        )

    def test_verify_token_failed_does_not_update_last_used_at(self):
        """
        Verifying with an invalid token does not update 'last_used_at'.
        """
        invalid_token = self.invalid_token()  # Method to generate an invalid token
        initial_last_used_at = self.device.last_used_at
        verified = self.device.verify_token(invalid_token)

        self.assertFalse(verified, "Token should not be verified.")
        self.device.refresh_from_db()
        self.assertEqual(
            self.device.last_used_at,
            initial_last_used_at,
            "'last_used_at' should not be updated on failed verification.",
        )


class ThrottlingTestMixin:
    """
    Generic tests for throttled devices.

    Any concrete device implementation that uses throttling should define a
    TestCase subclass that includes this as a base class. This will help verify
    a correct integration of ThrottlingMixin.

    Subclasses are responsible for populating self.device with a device to test
    as well as implementing methods to generate tokens to test with.

    """

    def setUp(self):
        self.device = None

    def valid_token(self):
        """Returns a valid token to pass to our device under test."""
        raise NotImplementedError()

    def invalid_token(self):
        """Returns an invalid token to pass to our device under test."""
        raise NotImplementedError()

    def _simulate_failures(self, count, window_seconds=None):
        """
        Places the device directly into the state of ``count`` accumulated
        failures with a fresh lockout window, avoiding long real-time waits
        and (for side-channel devices) token expiry.
        """
        window_seconds = window_seconds or self.device.get_throttle_max_delay()
        now = timezone.now()
        self.device.throttling_failure_count = count
        self.device.throttling_failure_timestamp = now
        self.device.throttling_locked_until = now + timedelta(seconds=window_seconds)
        self.device.save()

    #
    # Tests
    #

    def test_delay_imposed_after_fail(self):
        verified1 = self.device.verify_token(self.invalid_token())
        self.assertFalse(verified1)
        verified2 = self.device.verify_token(self.valid_token())
        self.assertFalse(verified2)

    def test_delay_after_fail_expires(self):
        verified1 = self.device.verify_token(self.invalid_token())
        self.assertFalse(verified1)
        with freeze_time() as frozen_time:
            # With default settings initial delay is 1 second
            frozen_time.tick(delta=timedelta(seconds=1.1))
            verified2 = self.device.verify_token(self.valid_token())
            self.assertTrue(verified2)

    def test_throttling_failure_count(self):
        self.assertEqual(self.device.throttling_failure_count, 0)
        for _ in range(0, 5):
            self.device.verify_token(self.invalid_token())
            # Only the first attempt will increase throttling_failure_count,
            # the others will all be within 1 second of first
            # and therefore not count as attempts.
            self.assertEqual(self.device.throttling_failure_count, 1)

    def test_verify_is_allowed(self):
        # Initially should be allowed
        verify_is_allowed1, data1 = self.device.verify_is_allowed()
        self.assertEqual(verify_is_allowed1, True)
        self.assertEqual(data1, None)

        # After failure, verify is not allowed
        with freeze_time():
            self.device.verify_token(self.invalid_token())
            verify_is_allowed2, data2 = self.device.verify_is_allowed()
            self.assertEqual(verify_is_allowed2, False)
            self.assertEqual(
                data2,
                {
                    'reason': VerifyNotAllowed.N_FAILED_ATTEMPTS,
                    'failure_count': 1,
                    'locked_until': timezone.now() + timezone.timedelta(seconds=1),
                },
            )

        # After a successful attempt, should be allowed again
        with freeze_time() as frozen_time:
            frozen_time.tick(delta=timedelta(seconds=1.1))
            self.device.verify_token(self.valid_token())

            verify_is_allowed3, data3 = self.device.verify_is_allowed()
            self.assertEqual(verify_is_allowed3, True)
            self.assertEqual(data3, None)

    def test_verify_is_allowed_with_large_failure_count(self):
        """
        A high failure count (e.g. after a sustained run of failed attempts,
        or an admin editing the field directly) must not overflow the backoff
        calculation or produce an effectively permanent lockout. The delay is
        capped at the configured maximum and the device recovers on its own
        once the lockout window elapses.

        https://github.com/django-otp/django-otp/issues/172
        """
        self._simulate_failures(90, window_seconds=10)

        verify_is_allowed, data = self.device.verify_is_allowed()

        self.assertEqual(verify_is_allowed, False)
        self.assertEqual(data['reason'], VerifyNotAllowed.N_FAILED_ATTEMPTS)
        self.assertEqual(data['failure_count'], 90)
        self.assertEqual(data['locked_until'], self.device.throttling_locked_until)

        with freeze_time() as frozen_time:
            frozen_time.tick(timedelta(seconds=11))
            verify_is_allowed, data = self.device.verify_is_allowed()

        self.assertEqual(verify_is_allowed, True)
        self.assertEqual(data, None)
        self.device.refresh_from_db()
        self.assertEqual(self.device.throttling_failure_count, 0)
        self.assertIsNone(self.device.throttling_failure_timestamp)
        self.assertIsNone(self.device.throttling_locked_until)

    def test_backoff_delay_is_capped_at_max_delay(self):
        """
        Exponential back-off applies to the first failures, but the lockout
        window never exceeds ``get_throttle_max_delay``.
        """
        max_delay = self.device.get_throttle_max_delay()
        self.device.verify_token(self.invalid_token())
        first_window = (
            self.device.throttling_locked_until - timezone.now()
        ).total_seconds()
        self.assertAlmostEqual(
            first_window, self.device.get_throttle_factor(), delta=0.1
        )

        # A failure count whose raw back-off would far exceed the cap still
        # produces a bounded, user-recoverable window.
        self._simulate_failures(90)
        capped_window = (
            self.device.throttling_locked_until - timezone.now()
        ).total_seconds()
        self.assertLessEqual(capped_window, max_delay + 0.1)

    def test_backoff_window_doubles_with_failure_count(self):
        """
        The lockout window follows the ``factor * 2**(n-1)`` curve, while
        attempts inside an active window are rejected without extending it.
        """
        factor = self.device.get_throttle_factor()

        with freeze_time() as frozen_time:
            self.device.verify_token(self.invalid_token())
            first_window = (
                self.device.throttling_locked_until - timezone.now()
            ).total_seconds()
            self.assertAlmostEqual(first_window, factor, delta=0.1)

            # An attempt inside the active window is rejected but does not
            # change the state.
            self.device.verify_token(self.invalid_token())
            self.assertEqual(self.device.throttling_failure_count, 1)

            # Simulate a second accumulated failure (e.g. an attacker who
            # kept retrying across successive windows). The window doubles.
            frozen_time.tick(timedelta(seconds=factor + 0.1))
            self._simulate_failures(2, window_seconds=factor * 2)
            self.assertEqual(self.device.throttling_failure_count, 2)
            locked_until = self.device.throttling_locked_until
            second_window = (
                self.device.throttling_locked_until - timezone.now()
            ).total_seconds()
            self.assertAlmostEqual(second_window, factor * 2, delta=0.1)

            # Retrying inside the new window still must not extend it.
            self.device.verify_token(self.invalid_token())
            self.assertEqual(self.device.throttling_failure_count, 2)
            self.assertEqual(self.device.throttling_locked_until, locked_until)

    def test_failure_state_decays_lazily_after_window_elapses(self):
        """
        After the lockout window elapses, the next interaction clears the
        accumulated failures without any background task, so verification is
        allowed again and a fresh failure restarts the back-off at the bottom.
        """
        self._simulate_failures(5, window_seconds=10)

        with freeze_time() as frozen_time:
            frozen_time.tick(timedelta(seconds=11))
            allowed, _ = self.device.verify_is_allowed()
            self.assertTrue(allowed)

        self.device.refresh_from_db()
        self.assertEqual(self.device.throttling_failure_count, 0)
        self.assertIsNone(self.device.throttling_failure_timestamp)
        self.assertIsNone(self.device.throttling_locked_until)

        self.device.verify_token(self.invalid_token())
        self.assertEqual(self.device.throttling_failure_count, 1)

    def test_successful_verification_clears_lockout(self):
        """
        A successful verification within an expired lockout window clears the
        whole failure state immediately.
        """
        self._simulate_failures(3, window_seconds=10)

        with freeze_time() as frozen_time:
            frozen_time.tick(timedelta(seconds=11))
            verified = self.device.verify_token(self.valid_token())

        self.assertTrue(verified)
        self.device.refresh_from_db()
        self.assertEqual(self.device.throttling_failure_count, 0)
        self.assertIsNone(self.device.throttling_failure_timestamp)
        self.assertIsNone(self.device.throttling_locked_until)


class CooldownTestMixin:
    def setUp(self):
        self.device = None

    def valid_token(self):
        """Returns a valid token to pass to our device under test."""
        raise NotImplementedError()

    def invalid_token(self):
        """Returns an invalid token to pass to our device under test."""
        raise NotImplementedError()

    #
    # Tests
    #

    def test_generate_is_allowed_on_first_try(self):
        """Token generation should be allowed on first try."""
        allowed, _ = self.device.generate_is_allowed()
        self.assertTrue(allowed)

    def test_cooldown_imposed_after_successful_generation(self):
        """
        Token generation before cooldown should not be allowed
        and the relevant reason should be returned.
        """
        with freeze_time():
            self.device.generate_challenge()
            self.device.refresh_from_db()
            allowed, details = self.device.generate_is_allowed()

            self.assertFalse(allowed)
            self.assertEqual(
                details['reason'], GenerateNotAllowed.COOLDOWN_DURATION_PENDING
            )

    def test_cooldown_expire_time(self):
        """
        When token generation is not allowed, the cooldown expire time
        should be returned.
        """
        with freeze_time():
            self.device.generate_challenge()
            self.device.refresh_from_db()
            _, details = self.device.generate_is_allowed()
            self.assertEqual(
                details['next_generation_at'], timezone.now() + timedelta(seconds=10)
            )

    def test_cooldown_reset(self):
        """Cooldown can be reset and allow token generation again before the initial period expires."""
        with freeze_time():
            self.device.generate_is_allowed()
            self.device.refresh_from_db()
            self.device.cooldown_reset()
            self.device.refresh_from_db()
            allowed, _ = self.device.generate_is_allowed()
            self.assertTrue(allowed)

    def test_valid_token_verification_resets_cooldown(self):
        """When the token is verified, the cooldown period is reset."""
        with freeze_time():
            self.device.generate_challenge()
            self.device.refresh_from_db()
            verified = self.device.verify_token(self.valid_token())
            self.assertTrue(verified)
            self.device.refresh_from_db()
            allowed, _ = self.device.generate_is_allowed()
            self.assertTrue(allowed)

    def test_invalid_token_verification_does_not_reset_cooldown(self):
        """When the token is not verified, the cooldown period is not reset."""
        with freeze_time():
            self.device.generate_challenge()
            self.device.refresh_from_db()
            verified = self.device.verify_token(self.invalid_token())
            self.assertFalse(verified)
            self.device.refresh_from_db()
            allowed, _ = self.device.generate_is_allowed()
            self.assertFalse(allowed)
