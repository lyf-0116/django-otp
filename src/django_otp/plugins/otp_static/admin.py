from django.contrib import admin
from django.contrib.admin.sites import AlreadyRegistered
from django.contrib.auth import get_user_model

from django_otp.admin import user_model_search_fields
from django_otp.conf import settings

from .models import StaticDevice, StaticToken, StaticTokenBatch, StaticTokenUse


class StaticTokenInline(admin.TabularInline):
    model = StaticToken
    extra = 0
    fields = ('token', 'batch', 'is_revoked')
    readonly_fields = ('batch',)


class StaticTokenBatchInline(admin.TabularInline):
    model = StaticTokenBatch
    extra = 0
    fields = ('created_at', 'revoked_at')
    readonly_fields = ('created_at', 'revoked_at')
    show_change_link = True


class StaticDeviceAdmin(admin.ModelAdmin):
    """
    :class:`~django.contrib.admin.ModelAdmin` for
    :class:`~django_otp.plugins.otp_static.models.StaticDevice`.
    """

    User = get_user_model()
    candidate_search_field = [User.USERNAME_FIELD, 'email']

    list_display = [
        'user',
        'name',
        'remaining_codes',
        'created_at',
        'last_used_at',
        'confirmed',
    ]
    list_filter = ['created_at', 'last_used_at', 'confirmed']
    search_fields, search_help_text = user_model_search_fields(candidate_search_field)

    raw_id_fields = ['user']
    readonly_fields = ['created_at', 'last_used_at']

    fieldsets = [
        (
            'Identity',
            {
                'fields': ['user', 'name', 'confirmed'],
            },
        ),
        (
            'Timestamps',
            {
                'fields': ['created_at', 'last_used_at'],
            },
        ),
    ]

    inlines = [
        StaticTokenInline,
        StaticTokenBatchInline,
    ]

    @admin.display(description='Remaining codes')
    def remaining_codes(self, obj):
        return obj.remaining_count

    def get_inline_instances(self, request, obj=None):
        if settings.OTP_ADMIN_HIDE_SENSITIVE_DATA and obj:
            return []
        return super().get_inline_instances(request, obj)


@admin.register(StaticTokenBatch)
class StaticTokenBatchAdmin(admin.ModelAdmin):
    list_display = ['id', 'device', 'created_at', 'revoked_at', 'code_count']
    list_filter = ['created_at', 'revoked_at']
    raw_id_fields = ['device']
    readonly_fields = ['created_at', 'revoked_at']

    @admin.display(description='Codes')
    def code_count(self, obj):
        return obj.token_count


@admin.register(StaticTokenUse)
class StaticTokenUseAdmin(admin.ModelAdmin):
    """
    Read-only audit trail of consumed recovery codes.

    Records are only created by the verification path. They may be deleted
    for retention purposes, but cannot be added or edited in the admin.
    """

    User = get_user_model()
    candidate_search_field = [User.USERNAME_FIELD, 'email']

    list_display = ['used_at', 'user', 'device', 'token_pk']
    list_filter = ['used_at']
    search_fields, search_help_text = user_model_search_fields(candidate_search_field)
    raw_id_fields = ['user', 'device']
    readonly_fields = ['device', 'user', 'used_at', 'token_pk']
    ordering = ['-used_at']

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


# Somehow this is getting imported twice, triggering a useless exception.
try:
    admin.site.register(StaticDevice, StaticDeviceAdmin)
except AlreadyRegistered:
    pass
