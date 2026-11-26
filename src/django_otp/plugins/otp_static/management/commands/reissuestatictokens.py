from textwrap import fill

from django.core.management.base import BaseCommand, CommandError
from django.utils.encoding import force_str

from django_otp.plugins.otp_static.lib import get_user_model, reissue_static_tokens


class Command(BaseCommand):
    help = fill(
        'Reissues the whole batch of static OTP tokens for the given user. '
        'Existing tokens (including the previous batch) are revoked and a '
        'new batch is generated atomically. The new tokens are printed, one '
        'per line, and are only available in this output.',
        width=78,
    )

    def add_arguments(self, parser):
        parser.add_argument('username', help='The user whose tokens will be reissued.')
        parser.add_argument(
            '-n',
            '--count',
            dest='count',
            type=int,
            default=None,
            help=(
                'Number of tokens to generate. Defaults to the current number '
                'of active tokens, or 10 if the device is empty.'
            ),
        )

    def handle(self, *args, **options):
        username = options['username']

        try:
            batch = reissue_static_tokens(username, options.get('count'))
        except get_user_model().DoesNotExist:
            raise CommandError('User "{0}" does not exist.'.format(username))

        for token in batch.tokens.all():
            self.stdout.write(force_str(token.token))
