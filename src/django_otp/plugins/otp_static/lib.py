from django.contrib.auth import get_user_model

from .models import StaticDevice, StaticToken


def add_static_token(username, token=None):
    """
    Adds a random static token to the identified user.

    This is the implementation for the management command of a similar name.
    Returns the StaticToken object created.

    """
    user = get_user_model().objects.get_by_natural_key(username)

    device = StaticDevice.objects.filter(user=user).first()
    if device is None:
        device = StaticDevice.objects.create(user=user, name='Backup Code')

    if token is None:
        token = StaticToken.random_token()

    return device.token_set.create(token=token)


def reissue_static_tokens(username, count=None):
    """
    Replaces all static tokens for the identified user with a new batch.

    The previous batch (and any other active tokens) is marked revoked in
    the same transaction that creates the new codes. Returns the new
    :class:`~django_otp.plugins.otp_static.models.StaticTokenBatch`.

    :param username: The account that owns the device.
    :param count: Optional batch size; see
        :meth:`StaticDevice.reissue_batch`.
    """
    user = get_user_model().objects.get_by_natural_key(username)

    device = StaticDevice.objects.filter(user=user).first()
    if device is None:
        device = StaticDevice.objects.create(user=user, name='Backup Code')

    return device.reissue_batch(count=count)
