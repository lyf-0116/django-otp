from datetime import timedelta

from django.conf import settings
from django.db import migrations, models


def populate_locked_until(apps, schema_editor):
    TOTPDevice = apps.get_model('otp_totp', 'TOTPDevice')
    factor = getattr(settings, 'OTP_TOTP_THROTTLE_FACTOR', 1)
    max_delay = getattr(settings, 'OTP_TOTP_THROTTLE_MAX_DELAY', 900)

    for device in TOTPDevice.objects.exclude(throttling_failure_timestamp=None):
        if device.throttling_failure_count <= 0:
            continue
        delay = min(
            factor * (2 ** (device.throttling_failure_count - 1)), max_delay
        )
        device.throttling_locked_until = (
            device.throttling_failure_timestamp + timedelta(seconds=delay)
        )
        device.save(update_fields=['throttling_locked_until'])


def clear_locked_until(apps, schema_editor):
    TOTPDevice = apps.get_model('otp_totp', 'TOTPDevice')
    TOTPDevice.objects.exclude(throttling_locked_until=None).update(
        throttling_locked_until=None
    )


class Migration(migrations.Migration):
    dependencies = [
        ('otp_totp', '0003_add_timestamps'),
    ]

    operations = [
        migrations.AddField(
            model_name='totpdevice',
            name='throttling_locked_until',
            field=models.DateTimeField(
                blank=True,
                default=None,
                help_text=(
                    'The datetime until which verification is disabled. Null if'
                    ' the device is not currently locked.'
                ),
                null=True,
            ),
        ),
        migrations.RunPython(populate_locked_until, clear_locked_until),
    ]
