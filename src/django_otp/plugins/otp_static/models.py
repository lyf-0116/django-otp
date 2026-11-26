from base64 import b32encode
from os import urandom

from django.conf import settings
from django.db import models, transaction
from django.utils import timezone

from django_otp.models import Device, ThrottlingMixin, TimestampMixin

#: Fallback batch size for :meth:`StaticDevice.reissue_batch` when the device
#: has no current codes and no explicit count is provided.
DEFAULT_STATIC_TOKEN_COUNT = 10


class StaticDevice(TimestampMixin, ThrottlingMixin, Device):
    """
    A static :class:`~django_otp.models.Device` simply consists of random
    tokens shared by the database and the user.

    These are frequently used as emergency tokens in case a user's normal
    device is lost or unavailable. They can be consumed in any order; each
    token will be removed from the database as soon as it is used. Each
    successful consumption also writes a :class:`StaticTokenUse` audit
    record (device, account and timestamp) in the same transaction as the
    deletion.

    Tokens are grouped into :class:`StaticTokenBatch` generations. Reissuing
    a batch marks the previous generation (and its tokens) as revoked, so an
    old and a new batch can never be valid at the same time. Tokens that
    predate batches have ``batch is None`` and are treated as ordinary active
    stock until they are consumed or replaced by a reissue.

    This model has no fields of its own, but serves as a container for
    :class:`StaticToken` objects.

    .. attribute:: token_set

        The RelatedManager for our tokens.

    .. attribute:: batches

        The RelatedManager for :class:`StaticTokenBatch` objects.

    .. attribute:: token_uses

        The RelatedManager for :class:`StaticTokenUse` audit records.

    """

    def get_throttle_factor(self):
        return getattr(settings, 'OTP_STATIC_THROTTLE_FACTOR', 1)

    def verify_token(self, token):
        verify_allowed, _ = self.verify_is_allowed()
        if verify_allowed:
            match = self.active_tokens().filter(token=token).first()
            if match is not None:
                self.throttle_reset(commit=False)
                self.set_last_used_timestamp(commit=False)

                # Capture the identity before deletion; the instance may no
                # longer have a primary key after ``delete()``.
                token_pk = match.pk
                used_at = self.last_used_at

                # Deletion and audit insertion are one atomic unit. If the
                # record cannot be written, the deletion rolls back (so the
                # code is not silently lost); if deletion fails, no record is
                # written (so there is no false usage entry). On the success
                # path the only extra work is this single indexed insert.
                with transaction.atomic():
                    match.delete()
                    StaticTokenUse.objects.create(
                        device=self,
                        user_id=self.user_id,
                        used_at=used_at,
                        token_pk=token_pk,
                    )
                    self.save()
            else:
                self.throttle_increment()
        else:
            match = None

        return match is not None

    # ------------------------------------------------------------------
    # Remaining codes and usage history
    # ------------------------------------------------------------------

    def active_tokens(self):
        """
        Returns the queryset of codes that can currently be verified.

        Consumed codes have their rows deleted and codes belonging to
        replaced batches are flagged :attr:`StaticToken.is_revoked`, so
        neither kind is included.
        """
        return self.token_set.filter(is_revoked=False)

    def get_remaining_count(self):
        """
        Returns the number of recovery codes that are still available.

        The figure is always derived from the current stock of active rows.
        This gives a well-defined result for legacy devices without any usage
        history: consumed codes are already gone, revoked/reissued batches
        are excluded and non-revoked codes (including batch-less legacy
        tokens) are counted.
        """
        return self.active_tokens().count()

    @property
    def remaining_count(self):
        """
        The number of recovery codes that are still available.

        See :meth:`get_remaining_count` for the counting policy.
        """
        return self.get_remaining_count()

    @property
    def latest_use(self):
        """
        The most recent :class:`StaticTokenUse` record, or ``None`` if no
        code has been consumed since audit recording was introduced.
        """
        return self.token_uses.order_by('-used_at', '-id').first()

    def get_latest_use(self):
        """
        Return the most recent :class:`StaticTokenUse` record.

        This is the method form of :attr:`latest_use`.
        """
        return self.latest_use

    def recent_uses(self, limit=10):
        """
        Return up to ``limit`` recent :class:`StaticTokenUse` records, newest
        first.
        """
        return self.token_uses.order_by('-used_at', '-id')[:limit]

    # ------------------------------------------------------------------
    # Batch issuance and reissue
    # ------------------------------------------------------------------

    def get_default_token_count(self):
        """
        Return the batch size used when none is given to
        :meth:`reissue_batch`: preserve the current active stock size,
        falling back to :setting:`OTP_STATIC_TOKEN_COUNT` (default 10) for an
        empty device.
        """
        count = self.active_tokens().count()
        if count <= 0:
            count = getattr(
                settings, 'OTP_STATIC_TOKEN_COUNT', DEFAULT_STATIC_TOKEN_COUNT
            )
        return count

    @transaction.atomic
    def reissue_batch(self, count=None):
        """
        Replace the whole current set of codes with a freshly generated batch.

        Every active batch is marked as revoked and every active token is
        flagged :attr:`StaticToken.is_revoked` in the same transaction that
        creates the new batch. Revoked rows are retained for auditing, but
        they can no longer be verified and are not counted by
        :attr:`remaining_count`. This also revokes batch-less legacy tokens,
        so old and new codes cannot be valid simultaneously.

        :param count: Number of codes in the new batch. Defaults to the
            current number of active codes, or
            :setting:`OTP_STATIC_TOKEN_COUNT` when the device has none.
        :type count: int or None

        :returns: The new active :class:`StaticTokenBatch`.
        """
        if count is None:
            count = self.get_default_token_count()
        count = int(count)
        if count < 0:
            raise ValueError("count must be non-negative")

        now = timezone.now()

        self.batches.filter(revoked_at__isnull=True).update(revoked_at=now)
        # One statement for the effective flag on all active tokens; this
        # also covers legacy tokens with ``batch is None``.
        self.active_tokens().update(is_revoked=True)

        batch = StaticTokenBatch.objects.create(device=self)
        new_tokens = [
            StaticToken(device=self, batch=batch, token=StaticToken.random_token())
            for _ in range(count)
        ]
        if new_tokens:
            StaticToken.objects.bulk_create(new_tokens)

        return batch

    def reissue_tokens(self, count=None):
        """
        Reissue all recovery codes and return the new :class:`StaticToken`
        objects.

        See :meth:`reissue_batch` for the transactional and revocation
        semantics.
        """
        batch = self.reissue_batch(count=count)
        return list(batch.tokens.all())

    def reissue_codes(self, count=None):
        """
        Reissue all recovery codes and return the new plain-text code values.

        Treat the returned values as passwords and display them to the user
        exactly once. See :meth:`reissue_batch` for the semantics.
        """
        return [token.token for token in self.reissue_tokens(count=count)]

    # Concise synonyms for the same transactional operation.
    regenerate_batch = reissue_batch
    regenerate_tokens = reissue_tokens
    rotate_codes = reissue_codes


class StaticTokenBatch(models.Model):
    """
    A generated batch of :class:`StaticToken` recovery codes for a
    :class:`StaticDevice`.

    A batch stays active until it is replaced through
    :meth:`StaticDevice.reissue_batch`, which records :attr:`revoked_at` and
    flags the batch's tokens as revoked.

    .. attribute:: tokens

        The RelatedManager for the batch's :class:`StaticToken` objects.

    """

    device = models.ForeignKey(
        StaticDevice, related_name='batches', on_delete=models.CASCADE
    )
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True, db_index=True)

    class Meta:
        ordering = ['-created_at', '-id']
        verbose_name = 'static token batch'
        verbose_name_plural = 'static token batches'

    def __str__(self):
        state = 'revoked' if self.revoked_at is not None else 'active'
        return "Static token batch {} ({})".format(self.pk, state)

    @property
    def is_revoked(self):
        """``True`` once the batch has been replaced/revoked."""
        return self.revoked_at is not None

    @property
    def token_count(self):
        """Number of token rows in this batch, including revoked tokens."""
        return self.tokens.count()

    def codes(self):
        """Return the plain-text code values belonging to this batch."""
        return list(self.tokens.values_list('token', flat=True))

    def revoke(self, when=None):
        """
        Mark this batch and all of its tokens as revoked.

        This is idempotent and returns ``True`` if it changed the batch.
        """
        if self.revoked_at is not None:
            return False

        when = when if when is not None else timezone.now()
        self.revoked_at = when
        self.save(update_fields=['revoked_at'])
        self.tokens.filter(is_revoked=False).update(is_revoked=True)

        return True


class StaticToken(models.Model):
    """
    A single token belonging to a :class:`StaticDevice`.

    .. attribute:: device

        *ForeignKey*: A foreign key to :class:`StaticDevice`.

    .. attribute:: batch

        *ForeignKey*: The :class:`StaticTokenBatch` that generated this token,
        or ``None`` for legacy/ad-hoc tokens created before batches existed.

    .. attribute:: token

        *CharField*: A random string up to 16 characters.

    .. attribute:: is_revoked

        *BooleanField*: Revoked tokens are retained for auditing but can no
        longer be verified or counted as remaining codes.
    """

    device = models.ForeignKey(
        StaticDevice, related_name='token_set', on_delete=models.CASCADE
    )
    batch = models.ForeignKey(
        StaticTokenBatch,
        related_name='tokens',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )
    token = models.CharField(max_length=16, db_index=True)
    is_revoked = models.BooleanField(
        default=False,
        help_text=(
            "Revoked codes are retained for auditing, but can no longer be "
            "used to verify."
        ),
    )

    @staticmethod
    def random_token():
        """
        Returns a new random string that can be used as a static token.

        :rtype: str

        """
        return b32encode(urandom(5)).decode('utf-8').lower()


class StaticTokenUse(models.Model):
    """
    An audit record for one consumed :class:`StaticToken` (recovery code).

    A row is inserted in the same transaction that deletes the consumed
    token. It captures the device, the account and the time of consumption.
    The raw code is never stored; :attr:`token_pk` preserves the consumed
    token's former primary key so the specific code row can be identified.

    .. attribute:: device

        *ForeignKey*: The device (code container) through which the code was
        consumed.

    .. attribute:: user

        *ForeignKey*: The account that consumed the code, copied from the
        device owner for an explicit, independently queryable record.

    .. attribute:: used_at

        *DateTimeField*: When the code was consumed.

    .. attribute:: token_pk

        *IntegerField*: The primary key of the consumed :class:`StaticToken`,
        captured before its row was deleted.
    """

    device = models.ForeignKey(
        StaticDevice, related_name='token_uses', on_delete=models.CASCADE
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='static_token_uses',
        on_delete=models.CASCADE,
    )
    used_at = models.DateTimeField(default=timezone.now, db_index=True)
    token_pk = models.IntegerField(null=True, blank=True)

    class Meta:
        ordering = ['-used_at', '-id']
        indexes = [
            models.Index(fields=['device', 'used_at']),
        ]
        verbose_name = 'static token use'
        verbose_name_plural = 'static token uses'

    def __str__(self):
        return "Static token use {} on device {} by user {} at {}".format(
            self.pk, self.device_id, self.user_id, self.used_at
        )


# Discoverability aliases for callers using the "recovery code" vocabulary.
RecoveryCodeBatch = StaticTokenBatch
RecoveryCodeUse = StaticTokenUse
RecoveryCodeUsage = StaticTokenUse
RecoveryCodeRecord = StaticTokenUse
StaticTokenUsage = StaticTokenUse
