from io import StringIO
from unittest import mock

from django.contrib.admin import AdminSite
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.db import IntegrityError
from django.test import RequestFactory
from django.test.utils import override_settings

from django_otp import verify_token as otp_verify_token
from django_otp.forms import OTPAuthenticationForm
from django_otp.test_utils import TestCase, ThrottlingTestMixin, TimestampTestMixin

from .admin import StaticDeviceAdmin, StaticTokenInline
from .lib import add_static_token, reissue_static_tokens
from .models import StaticDevice, StaticToken, StaticTokenBatch, StaticTokenUse


class DeviceTest(TestCase):
    """A few generic tests to get us started."""

    def setUp(self):
        try:
            self.user = self.create_user('alice', 'password')
        except Exception:
            self.skipTest("Unable to create the test user.")

    def test_str(self):
        device = StaticDevice.objects.create(user=self.user, name="Device")

        str(device)

    def test_str_unpopulated(self):
        device = StaticDevice()

        str(device)


class LibTest(TestCase):
    """
    Test miscellaneous library functions.
    """

    def setUp(self):
        try:
            self.user = self.create_user('alice', 'password')
        except Exception:
            self.skipTest("Unable to create the test user.")

    def test_add_static_token(self):
        statictoken = add_static_token('alice')

        self.assertEqual(statictoken.device.user, self.user)
        self.assertEqual(self.user.staticdevice_set.count(), 1)

    def test_add_static_token_existing_device(self):
        self.user.staticdevice_set.create(name='Test')
        statictoken = add_static_token('alice')

        self.assertEqual(statictoken.device.user, self.user)
        self.assertEqual(self.user.staticdevice_set.count(), 1)
        self.assertEqual(statictoken.device.name, 'Test')

    def test_add_static_token_no_user(self):
        with self.assertRaises(self.User.DoesNotExist):
            add_static_token('bogus')

    def test_add_static_token_specific(self):
        statictoken = add_static_token('alice', 'token')

        self.assertEqual(statictoken.token, 'token')


class AuthFormTest(TestCase):
    """
    Test the auth form with static tokens.

    We try to honor custom user models, but if we can't create users, we'll
    skip the tests.
    """

    def setUp(self):
        for device_id, username in enumerate(['alice', 'bob']):
            try:
                user = self.create_user(username, 'password')
            except IntegrityError:
                self.skipTest("Unable to create a test user.")
            else:
                device = user.staticdevice_set.create(id=device_id + 1)
                device.token_set.create(token=username + '1')
                device.token_set.create(token=username + '1')
                device.token_set.create(token=username + '2')

    def test_empty(self):
        data = {}
        form = OTPAuthenticationForm(None, data)

        self.assertFalse(form.is_valid())
        self.assertEqual(form.get_user(), None)

    def test_bad_password(self):
        data = {
            'username': 'alice',
            'password': 'bogus',
        }
        form = OTPAuthenticationForm(None, data)

        self.assertFalse(form.is_valid())
        self.assertEqual(list(form.errors.keys()), ['__all__'])

    def test_no_token(self):
        data = {
            'username': 'alice',
            'password': 'password',
        }
        form = OTPAuthenticationForm(None, data)

        self.assertFalse(form.is_valid())
        self.assertEqual(form.get_user().get_username(), 'alice')

    def test_omitted_device(self):
        data = {
            'username': 'alice',
            'password': 'password',
            'otp_token': 'alice1',
        }
        form = OTPAuthenticationForm(None, data)

        # A device must be selected explicitly; we no longer guess by
        # trying the token against each of the user's devices in turn.
        self.assertFalse(form.is_valid())
        alice = form.get_user()
        self.assertEqual(alice.get_username(), 'alice')
        self.assertIsNone(alice.otp_device)

    def test_spoofed_device(self):
        data = {
            'username': 'alice',
            'password': 'password',
            'otp_device': 'otp_static.staticdevice/2',
            'otp_token': 'bob1',
        }
        form = OTPAuthenticationForm(None, data)

        self.assertFalse(form.is_valid())
        alice = form.get_user()
        self.assertEqual(alice.get_username(), 'alice')
        self.assertIsNone(alice.otp_device)

    def test_specific_device_fail(self):
        data = {
            'username': 'alice',
            'password': 'password',
            'otp_device': 'otp_email.staticdevice/1',
            'otp_token': 'bogus',
        }
        form = OTPAuthenticationForm(None, data)

        self.assertFalse(form.is_valid())
        alice = form.get_user()
        self.assertEqual(alice.get_username(), 'alice')
        self.assertIsNone(alice.otp_device)

    def test_specific_device(self):
        data = {
            'username': 'alice',
            'password': 'password',
            'otp_device': 'otp_static.staticdevice/1',
            'otp_token': 'alice1',
        }
        form = OTPAuthenticationForm(None, data)

        self.assertTrue(form.is_valid())
        alice = form.get_user()
        self.assertEqual(alice.get_username(), 'alice')
        self.assertIsNotNone(alice.otp_device)


@override_settings(
    OTP_STATIC_THROTTLE_FACTOR=1,
)
class ThrottlingTestCase(ThrottlingTestMixin, TestCase):
    def setUp(self):
        try:
            user = self.create_user('alice', 'password')
        except IntegrityError:
            self.skipTest("Unable to create a test user.")
        else:
            self.device = user.staticdevice_set.create()
            self.device.token_set.create(token='valid1')
            self.device.token_set.create(token='valid2')
            self.device.token_set.create(token='valid3')

    def valid_token(self):
        return self.device.token_set.first().token

    def invalid_token(self):
        return 'bogus'


class TimestampTestCase(TimestampTestMixin, TestCase):
    def setUp(self):
        try:
            user = self.create_user('alice', 'password')
        except IntegrityError:
            self.skipTest("Unable to create a test user.")
        else:
            self.device = user.staticdevice_set.create()
            self.device.token_set.create(token='valid1')
            self.device.token_set.create(token='valid2')
            self.device.token_set.create(token='valid3')

    def valid_token(self):
        return self.device.token_set.first().token

    def invalid_token(self):
        return 'bogus'


class StaticDeviceAdminTest(TestCase):
    def setUp(self):
        try:
            self.admin = self.create_user(
                'admin',
                'password',
                email='admin@example.com',
                is_staff=True,
            )
        except IntegrityError:
            self.skipTest("Unable to create test user.")
        else:
            self.device = self.admin.staticdevice_set.create()
        self.device_admin = StaticDeviceAdmin(StaticDevice, AdminSite())
        self.get_request = RequestFactory().get('/')
        self.get_request.user = self.admin

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=True)
    def test_inline_instances_when_sensitive_information_hidden(self):
        self._add_device_perms('change_statictoken')
        instances = self.device_admin.get_inline_instances(self.get_request, obj=None)
        self.assertIsInstance(instances, list)
        self.assertEqual(len(instances), 1)
        self.assertIsInstance(instances[0], StaticTokenInline)
        instances = self.device_admin.get_inline_instances(
            self.get_request, obj=self.device
        )
        self.assertEqual(instances, [])

    @override_settings(OTP_ADMIN_HIDE_SENSITIVE_DATA=False)
    def test_inline_instances_when_sensitive_information_shown(self):
        self._add_device_perms('change_statictoken')
        for obj in (None, self.device):
            instances = self.device_admin.get_inline_instances(
                self.get_request, obj=obj
            )
            self.assertIsInstance(instances, list)
            self.assertEqual(len(instances), 1)

    #
    # Helpers
    #

    def _add_device_perms(self, *codenames):
        ct = ContentType.objects.get_for_models(StaticDevice, StaticToken)

        perms = [
            Permission.objects.get(content_type__in=ct.values(), codename=codename)
            for codename in codenames
        ]

        self.admin.user_permissions.add(*perms)


@override_settings(OTP_STATIC_THROTTLE_FACTOR=0)
class RecoveryCodeAuditTest(TestCase):
    """
    Consumption records, remaining-count and latest-use queries.
    """

    def setUp(self):
        try:
            self.user = self.create_user('alice', 'password')
        except Exception:
            self.skipTest("Unable to create the test user.")
        else:
            self.device = StaticDevice.objects.create(user=self.user, name='backup')
            self.codes = [
                self.device.token_set.create(token='code-{}'.format(i))
                for i in range(3)
            ]

    def test_successful_use_writes_record(self):
        token = self.codes[0]

        self.assertTrue(self.device.verify_token(token.token))

        record = StaticTokenUse.objects.get()
        self.assertEqual(record.device, self.device)
        self.assertEqual(record.device_id, self.device.pk)
        self.assertEqual(record.user, self.user)
        self.assertEqual(record.user_id, self.user.pk)
        self.assertEqual(record.token_pk, token.pk)
        self.assertIsNotNone(record.used_at)
        self.assertEqual(record.used_at, self.device.last_used_at)

        # The consumed token itself is still deleted.
        self.assertFalse(StaticToken.objects.filter(pk=token.pk).exists())

    def test_top_level_verify_writes_record(self):
        accepted = otp_verify_token(
            self.user, self.device.persistent_id, self.codes[0].token
        )

        self.assertIsNotNone(accepted)
        record = StaticTokenUse.objects.get()
        self.assertEqual(record.device_id, self.device.pk)
        self.assertEqual(record.user_id, self.user.pk)

    def test_failed_attempt_writes_no_record(self):
        self.assertFalse(self.device.verify_token('does-not-exist'))

        self.assertEqual(StaticTokenUse.objects.count(), 0)
        self.assertEqual(self.device.remaining_count, 3)

    def test_remaining_count_tracks_consumption(self):
        self.assertEqual(self.device.remaining_count, 3)
        self.assertEqual(self.device.get_remaining_count(), 3)

        self.device.verify_token(self.codes[0].token)
        self.assertEqual(self.device.remaining_count, 2)

        self.device.verify_token(self.codes[1].token)
        self.assertEqual(self.device.remaining_count, 1)

    def test_legacy_tokens_count_as_current_stock(self):
        # Tokens created without a batch (existing deployments) must still be
        # counted: remaining is derived from the current active rows.
        device = StaticDevice.objects.create(user=self.user, name='legacy')
        for i in range(4):
            device.token_set.create(token='legacy-{}'.format(i))

        self.assertIsNone(device.token_set.first().batch_id)
        self.assertEqual(device.remaining_count, 4)

    def test_explicitly_revoked_tokens_are_not_counted(self):
        self.device.token_set.create(token='revoked', is_revoked=True)

        self.assertEqual(self.device.remaining_count, 3)
        self.assertFalse(self.device.verify_token('revoked'))

    def test_latest_use_and_recent_uses(self):
        self.assertIsNone(self.device.latest_use)
        self.assertIsNone(self.device.get_latest_use())
        self.assertEqual(list(self.device.recent_uses()), [])

        self.device.verify_token(self.codes[0].token)
        self.device.verify_token(self.codes[1].token)

        first_use, second_use = list(StaticTokenUse.objects.order_by('id'))

        latest = self.device.latest_use
        self.assertEqual(latest, second_use)
        self.assertEqual(self.device.get_latest_use(), second_use)
        self.assertEqual(latest.token_pk, self.codes[1].pk)

        recent = list(self.device.recent_uses())
        self.assertEqual(recent, [second_use, first_use])

    def test_record_failure_rolls_back_deletion(self):
        code = self.codes[0].token

        with mock.patch.object(
            StaticTokenUse.objects,
            'create',
            side_effect=RuntimeError('audit unavailable'),
        ):
            with self.assertRaises(RuntimeError):
                self.device.verify_token(code)

        # No false ledger and the code is restored by the rollback.
        self.assertEqual(StaticTokenUse.objects.count(), 0)
        self.assertTrue(
            StaticToken.objects.filter(token=code, is_revoked=False).exists()
        )

        # The restored code can be consumed once the audit path works again.
        self.assertTrue(self.device.verify_token(code))
        self.assertEqual(StaticTokenUse.objects.count(), 1)
        self.assertFalse(StaticToken.objects.filter(token=code).exists())

    def test_delete_failure_leaves_no_record(self):
        code = self.codes[0].token

        with mock.patch.object(
            StaticToken, 'delete', side_effect=RuntimeError('delete failed')
        ):
            with self.assertRaises(RuntimeError):
                self.device.verify_token(code)

        self.assertEqual(StaticTokenUse.objects.count(), 0)
        self.assertTrue(StaticToken.objects.filter(token=code).exists())

    def test_later_save_failure_rolls_back_record(self):
        code = self.codes[0].token

        with mock.patch.object(
            self.device, 'save', side_effect=RuntimeError('save failed')
        ):
            with self.assertRaises(RuntimeError):
                self.device.verify_token(code)

        self.assertEqual(StaticTokenUse.objects.count(), 0)
        self.assertTrue(StaticToken.objects.filter(token=code).exists())


@override_settings(OTP_STATIC_THROTTLE_FACTOR=0)
class RecoveryCodeReissueTest(TestCase):
    """
    Batch reissue must revoke the old batch instead of leaving two live sets.
    """

    def setUp(self):
        try:
            self.user = self.create_user('alice', 'password')
        except Exception:
            self.skipTest("Unable to create the test user.")
        else:
            self.device = StaticDevice.objects.create(user=self.user, name='backup')
            self.legacy_codes = [
                self.device.token_set.create(token='legacy-{}'.format(i))
                for i in range(3)
            ]

    def test_first_reissue_revokes_legacy_tokens(self):
        batch = self.device.reissue_batch(count=4)

        self.assertIsInstance(batch, StaticTokenBatch)
        self.assertFalse(batch.is_revoked)
        self.assertEqual(batch.token_count, 4)
        self.assertEqual(self.device.batches.count(), 1)

        # Legacy rows are retained but flagged revoked.
        self.assertEqual(
            StaticToken.objects.filter(
                pk__in=[token.pk for token in self.legacy_codes],
                is_revoked=True,
            ).count(),
            3,
        )

        # Old codes no longer verify; new codes do.
        for token in self.legacy_codes:
            self.assertFalse(self.device.verify_token(token.token))
        self.assertEqual(self.device.remaining_count, 4)

        new_code = batch.codes()[0]
        self.assertTrue(self.device.verify_token(new_code))

    def test_reissue_marks_previous_batch_revoked(self):
        first = self.device.reissue_batch(count=3)
        first_code = first.codes()[1]

        second = self.device.reissue_batch(count=5)

        self.assertNotEqual(first.pk, second.pk)
        first.refresh_from_db()
        self.assertTrue(first.is_revoked)
        self.assertIsNotNone(first.revoked_at)
        self.assertFalse(second.is_revoked)

        # The old batch's surviving code is dead and the new batch is live.
        self.assertFalse(self.device.verify_token(first_code))
        self.assertEqual(self.device.remaining_count, 5)
        self.assertTrue(self.device.verify_token(second.codes()[0]))

        # Exactly two batch generations exist.
        self.assertEqual(self.device.batches.count(), 2)

    def test_reissue_is_atomic(self):
        with mock.patch.object(
            StaticToken.objects,
            'bulk_create',
            side_effect=RuntimeError('cannot create batch'),
        ):
            with self.assertRaises(RuntimeError):
                self.device.reissue_batch(count=4)

        # Revocation must roll back together with the failed creation.
        self.assertEqual(self.device.batches.count(), 0)
        self.assertEqual(self.device.active_tokens().count(), 3)
        self.assertEqual(self.device.remaining_count, 3)
        for token in self.legacy_codes:
            self.assertTrue(
                StaticToken.objects.filter(pk=token.pk, is_revoked=False).exists()
            )

    def test_default_count_preserves_active_stock(self):
        batch = self.device.reissue_batch()
        self.assertEqual(batch.token_count, 3)

        self.device.verify_token(batch.codes()[0])
        self.assertEqual(self.device.remaining_count, 2)

        next_batch = self.device.reissue_batch()
        self.assertEqual(next_batch.token_count, 2)

    @override_settings(OTP_STATIC_TOKEN_COUNT=6)
    def test_default_count_setting_for_empty_device(self):
        device = StaticDevice.objects.create(user=self.user, name='empty')

        batch = device.reissue_batch()

        self.assertEqual(batch.token_count, 6)
        self.assertEqual(device.remaining_count, 6)

    def test_reissue_return_shapes(self):
        codes = self.device.reissue_codes(count=4)
        self.assertEqual(len(codes), 4)
        self.assertTrue(all(isinstance(code, str) for code in codes))

        tokens = self.device.reissue_tokens(count=2)
        self.assertEqual(len(tokens), 2)
        self.assertTrue(all(isinstance(token, StaticToken) for token in tokens))

    def test_regenerate_aliases(self):
        batch = self.device.regenerate_batch(count=2)
        self.assertEqual(batch.token_count, 2)

        tokens = self.device.regenerate_tokens(count=3)
        self.assertEqual(len(tokens), 3)

        codes = self.device.rotate_codes(count=4)
        self.assertEqual(len(codes), 4)

    def test_lib_reissue_helper(self):
        batch = reissue_static_tokens('alice', count=5)

        self.assertEqual(batch.device, self.device)
        self.assertEqual(batch.token_count, 5)
        self.assertEqual(self.device.remaining_count, 5)

    def test_lib_reissue_helper_creates_device(self):
        user = self.create_user('bob', 'password')

        batch = reissue_static_tokens('bob', count=2)

        self.assertEqual(batch.device.user, user)
        self.assertEqual(batch.token_count, 2)

    def test_management_command(self):
        out = StringIO()
        call_command('reissuestatictokens', 'alice', count=4, stdout=out)

        codes = out.getvalue().split()
        self.assertEqual(len(codes), 4)
        self.assertEqual(self.device.remaining_count, 4)
        self.assertFalse(self.device.verify_token(self.legacy_codes[0].token))
        self.assertTrue(self.device.verify_token(codes[0]))

    def test_management_command_unknown_user(self):
        from django.core.management.base import CommandError

        with self.assertRaises(CommandError):
            call_command('reissuestatictokens', 'nobody')


class RecoveryCodeAdminTest(TestCase):
    def test_audit_admin_is_registered_read_only(self):
        from django.contrib import admin

        from .admin import StaticTokenUseAdmin

        model_admin = admin.site._registry.get(StaticTokenUse)
        self.assertIsInstance(model_admin, StaticTokenUseAdmin)

        request = RequestFactory().get('/')
        request.user = self.create_user('reviewer', 'password', is_staff=True)
        self.assertFalse(model_admin.has_add_permission(request))
        self.assertFalse(model_admin.has_change_permission(request))

    def test_admin_changelists_render(self):
        admin_user = self.User.objects.create_superuser(
            'root', 'root@example.com', 'password'
        )
        self.client.force_login(admin_user)

        device = StaticDevice.objects.create(user=admin_user, name='backup')
        device.token_set.create(token='abc123')
        device.verify_token('abc123')
        device.reissue_batch(count=2)

        for url in (
            '/admin/otp_static/staticdevice/',
            '/admin/otp_static/statictokenbatch/',
            '/admin/otp_static/statictokenuse/',
        ):
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200, url)
