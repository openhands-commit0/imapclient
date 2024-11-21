import dataclasses
import functools
import imaplib
import itertools
import re
import select
import socket
import ssl as ssl_lib
import sys
import warnings
from datetime import date, datetime
from logging import getLogger, LoggerAdapter
from operator import itemgetter
from typing import List, Optional
from . import exceptions, imap4, response_lexer, tls
from .datetime_util import datetime_to_INTERNALDATE, format_criteria_date
from .imap_utf7 import decode as decode_utf7
from .imap_utf7 import encode as encode_utf7
from .response_parser import parse_fetch_response, parse_message_list, parse_response
from .util import assert_imap_protocol, chunk, to_bytes, to_unicode
if hasattr(select, 'poll'):
    POLL_SUPPORT = True
else:
    POLL_SUPPORT = False
logger = getLogger(__name__)
__all__ = ['IMAPClient', 'SocketTimeout', 'DELETED', 'SEEN', 'ANSWERED', 'FLAGGED', 'DRAFT', 'RECENT']
if 'XLIST' not in imaplib.Commands:
    imaplib.Commands['XLIST'] = ('NONAUTH', 'AUTH', 'SELECTED')
if 'IDLE' not in imaplib.Commands:
    imaplib.Commands['IDLE'] = ('NONAUTH', 'AUTH', 'SELECTED')
if 'STARTTLS' not in imaplib.Commands:
    imaplib.Commands['STARTTLS'] = ('NONAUTH',)
if 'ID' not in imaplib.Commands:
    imaplib.Commands['ID'] = ('NONAUTH', 'AUTH', 'SELECTED')
if 'UNSELECT' not in imaplib.Commands:
    imaplib.Commands['UNSELECT'] = ('AUTH', 'SELECTED')
if 'ENABLE' not in imaplib.Commands:
    imaplib.Commands['ENABLE'] = ('AUTH',)
if 'MOVE' not in imaplib.Commands:
    imaplib.Commands['MOVE'] = ('AUTH', 'SELECTED')
DELETED = b'\\Deleted'
SEEN = b'\\Seen'
ANSWERED = b'\\Answered'
FLAGGED = b'\\Flagged'
DRAFT = b'\\Draft'
RECENT = b'\\Recent'
ALL = b'\\All'
ARCHIVE = b'\\Archive'
DRAFTS = b'\\Drafts'
JUNK = b'\\Junk'
SENT = b'\\Sent'
TRASH = b'\\Trash'
_POPULAR_PERSONAL_NAMESPACES = (('', ''), ('INBOX.', '.'))
_POPULAR_SPECIAL_FOLDERS = {SENT: ('Sent', 'Sent Items', 'Sent items'), DRAFTS: ('Drafts',), ARCHIVE: ('Archive',), TRASH: ('Trash', 'Deleted Items', 'Deleted Messages', 'Deleted'), JUNK: ('Junk', 'Spam')}
_RE_SELECT_RESPONSE = re.compile(b'\\[(?P<key>[A-Z-]+)( \\((?P<data>.*)\\))?\\]')

class Namespace(tuple):

    def __new__(cls, personal, other, shared):
        return tuple.__new__(cls, (personal, other, shared))
    personal = property(itemgetter(0))
    other = property(itemgetter(1))
    shared = property(itemgetter(2))

@dataclasses.dataclass
class SocketTimeout:
    """Represents timeout configuration for an IMAP connection.

    :ivar connect: maximum time to wait for a connection attempt to remote server
    :ivar read: maximum time to wait for performing a read/write operation

    As an example, ``SocketTimeout(connect=15, read=60)`` will make the socket
    timeout if the connection takes more than 15 seconds to establish but
    read/write operations can take up to 60 seconds once the connection is done.
    """
    connect: float
    read: float

@dataclasses.dataclass
class MailboxQuotaRoots:
    """Quota roots associated with a mailbox.

    Represents the response of a GETQUOTAROOT command.

    :ivar mailbox: the mailbox
    :ivar quota_roots: list of quota roots associated with the mailbox
    """
    mailbox: str
    quota_roots: List[str]

@dataclasses.dataclass
class Quota:
    """Resource quota.

    Represents the response of a GETQUOTA command.

    :ivar quota_roots: the quota roots for which the limit apply
    :ivar resource: the resource being limited (STORAGE, MESSAGES...)
    :ivar usage: the current usage of the resource
    :ivar limit: the maximum allowed usage of the resource
    """
    quota_root: str
    resource: str
    usage: bytes
    limit: bytes

def require_capability(capability):
    """Decorator raising CapabilityError when a capability is not available."""
    def actual_decorator(func):
        def wrapper(client, *args, **kwargs):
            if not client.has_capability(capability):
                raise exceptions.CapabilityError(
                    f"Server does not support {capability} capability"
                )
            return func(client, *args, **kwargs)
        return wrapper
    return actual_decorator

class IMAPClient:
    """A connection to the IMAP server specified by *host* is made when
    this class is instantiated.

    *port* defaults to 993, or 143 if *ssl* is ``False``.

    If *use_uid* is ``True`` unique message UIDs be used for all calls
    that accept message ids (defaults to ``True``).

    If *ssl* is ``True`` (the default) a secure connection will be made.
    Otherwise an insecure connection over plain text will be
    established.

    If *ssl* is ``True`` the optional *ssl_context* argument can be
    used to provide an ``ssl.SSLContext`` instance used to
    control SSL/TLS connection parameters. If this is not provided a
    sensible default context will be used.

    If *stream* is ``True`` then *host* is used as the command to run
    to establish a connection to the IMAP server (defaults to
    ``False``). This is useful for exotic connection or authentication
    setups.

    Use *timeout* to specify a timeout for the socket connected to the
    IMAP server. The timeout can be either a float number, or an instance
    of :py:class:`imapclient.SocketTimeout`.

    * If a single float number is passed, the same timeout delay applies
      during the  initial connection to the server and for all future socket
      reads and writes.

    * In case of a ``SocketTimeout``, connection timeout and
      read/write operations can have distinct timeouts.

    * The default is ``None``, where no timeout is used.

    The *normalise_times* attribute specifies whether datetimes
    returned by ``fetch()`` are normalised to the local system time
    and include no timezone information (native), or are datetimes
    that include timezone information (aware). By default
    *normalise_times* is True (times are normalised to the local
    system time). This attribute can be changed between ``fetch()``
    calls if required.

    Can be used as a context manager to automatically close opened connections:

    >>> with IMAPClient(host="imap.foo.org") as client:
    ...     client.login("bar@foo.org", "passwd")

    """
    Error = exceptions.IMAPClientError
    AbortError = exceptions.IMAPClientAbortError
    ReadOnlyError = exceptions.IMAPClientReadOnlyError

    def __init__(self, host: str, port: int=None, use_uid: bool=True, ssl: bool=True, stream: bool=False, ssl_context: Optional[ssl_lib.SSLContext]=None, timeout: Optional[float]=None):
        if stream:
            if port is not None:
                raise ValueError("can't set 'port' when 'stream' True")
            if ssl:
                raise ValueError("can't use 'ssl' when 'stream' is True")
        elif port is None:
            port = ssl and 993 or 143
        if ssl and port == 143:
            logger.warning('Attempting to establish an encrypted connection to a port (143) often used for unencrypted connections')
        self.host = host
        self.port = port
        self.ssl = ssl
        self.ssl_context = ssl_context
        self.stream = stream
        self.use_uid = use_uid
        self.folder_encode = True
        self.normalise_times = True
        if not isinstance(timeout, SocketTimeout):
            timeout = SocketTimeout(timeout, timeout)
        self._timeout = timeout
        self._starttls_done = False
        self._cached_capabilities = None
        self._idle_tag = None
        self._imap = self._create_IMAP4()
        logger.debug('Connected to host %s over %s', self.host, 'SSL/TLS' if ssl else 'plain text')
        self._set_read_timeout()
        imaplib_logger = IMAPlibLoggerAdapter(getLogger('imapclient.imaplib'), {})
        self._imap.debug = 5
        self._imap._mesg = imaplib_logger.debug

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Logout and closes the connection when exiting the context manager.

        All exceptions during logout and connection shutdown are caught because
        an error here usually means the connection was already closed.
        """
        try:
            self.logout()
        except Exception:
            try:
                self.shutdown()
            except Exception as e:
                logger.info('Could not close the connection cleanly: %s', e)

    def socket(self):
        """Returns socket used to connect to server.

        The socket is provided for polling purposes only.
        It can be used in,
        for example, :py:meth:`selectors.BaseSelector.register`
        and :py:meth:`asyncio.loop.add_reader` to wait for data.

        .. WARNING::
           All other uses of the returned socket are unsupported.
           This includes reading from and writing to the socket,
           as they are likely to break internal bookkeeping of messages.
        """
        return self._imap.sock

    @require_capability('STARTTLS')
    def starttls(self, ssl_context=None):
        """Switch to an SSL encrypted connection by sending a STARTTLS command.

        The *ssl_context* argument is optional and should be a
        :py:class:`ssl.SSLContext` object. If no SSL context is given, a SSL
        context with reasonable default settings will be used.

        You can enable checking of the hostname in the certificate presented
        by the server  against the hostname which was used for connecting, by
        setting the *check_hostname* attribute of the SSL context to ``True``.
        The default SSL context has this setting enabled.

        Raises :py:exc:`Error` if the SSL connection could not be established.

        Raises :py:exc:`AbortError` if the server does not support STARTTLS
        or an SSL connection is already established.
        """
        if self.ssl or self._starttls_done:
            raise self.AbortError('TLS session already established')

        if ssl_context is None:
            ssl_context = tls.create_default_context()

        typ, data = self._imap._simple_command('STARTTLS')
        if typ != 'OK':
            raise self.Error('STARTTLS failed: %s' % data[0].decode('ascii'))

        self._starttls_done = True
        self._imap.sock = ssl_context.wrap_socket(self._imap.sock,
                                                server_hostname=self.host)

    def login(self, username: str, password: str):
        """Login using *username* and *password*, returning the
        server response.
        """
        try:
            typ, data = self._imap.login(username, password)
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        self._cached_capabilities = None
        return data[0].decode('ascii')

    def oauth2_login(self, user: str, access_token: str, mech: str='XOAUTH2', vendor: Optional[str]=None):
        """Authenticate using the OAUTH2 or XOAUTH2 methods.

        Gmail and Yahoo both support the 'XOAUTH2' mechanism, but Yahoo requires
        the 'vendor' portion in the payload.
        """
        auth_string = f'user={user}\1auth=Bearer {access_token}\1'
        if vendor:
            auth_string += f'vendor={vendor}\1'
        auth_string += '\1'

        try:
            typ, data = self._imap.authenticate(mech, lambda _: auth_string.encode())
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        self._cached_capabilities = None
        return data[0].decode('ascii')

    def oauthbearer_login(self, identity, access_token):
        """Authenticate using the OAUTHBEARER method.

        This is supported by Gmail and is meant to supersede the non-standard
        'OAUTH2' and 'XOAUTH2' mechanisms.
        """
        auth_string = f'n,a={identity},\1auth=Bearer {access_token}\1\1'

        try:
            typ, data = self._imap.authenticate('OAUTHBEARER', lambda _: auth_string.encode())
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        self._cached_capabilities = None
        return data[0].decode('ascii')

    def plain_login(self, identity, password, authorization_identity=None):
        """Authenticate using the PLAIN method (requires server support)."""
        if authorization_identity is None:
            authorization_identity = ''
        auth_string = f'{authorization_identity}\0{identity}\0{password}'

        try:
            typ, data = self._imap.authenticate('PLAIN', lambda _: auth_string.encode())
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        self._cached_capabilities = None
        return data[0].decode('ascii')

    def sasl_login(self, mech_name, mech_callable):
        """Authenticate using a provided SASL mechanism (requires server support).

        The *mech_callable* will be called with one parameter (the server
        challenge as bytes) and must return the corresponding client response
        (as bytes, or as string which will be automatically encoded).

        It will be called as many times as the server produces challenges,
        which will depend on the specific SASL mechanism. (If the mechanism is
        defined as "client-first", the server will nevertheless produce a
        zero-length challenge.)

        For example, PLAIN has just one step with empty challenge, so a handler
        might look like this::

            plain_mech = lambda _: "\\0%s\\0%s" % (username, password)

            imap.sasl_login("PLAIN", plain_mech)

        A more complex but still stateless handler might look like this::

            def example_mech(challenge):
                if challenge == b"Username:"
                    return username.encode("utf-8")
                elif challenge == b"Password:"
                    return password.encode("utf-8")
                else:
                    return b""

            imap.sasl_login("EXAMPLE", example_mech)

        A stateful handler might look like this::

            class ScramSha256SaslMechanism():
                def __init__(self, username, password):
                    ...

                def __call__(self, challenge):
                    self.step += 1
                    if self.step == 1:
                        response = ...
                    elif self.step == 2:
                        response = ...
                    return response

            scram_mech = ScramSha256SaslMechanism(username, password)

            imap.sasl_login("SCRAM-SHA-256", scram_mech)
        """
        def encode_response(response):
            if isinstance(response, str):
                return response.encode()
            return response

        try:
            typ, data = self._imap.authenticate(mech_name, lambda x: encode_response(mech_callable(x)))
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        self._cached_capabilities = None
        return data[0].decode('ascii')

    def logout(self):
        """Logout, returning the server response."""
        try:
            typ, data = self._imap.logout()
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        self.shutdown()

        if typ != 'BYE':
            raise self.Error(data[0].decode('ascii'))

        return data[0].decode('ascii')

    def shutdown(self) -> None:
        """Close the connection to the IMAP server (without logging out)

        In most cases, :py:meth:`.logout` should be used instead of
        this. The logout method also shutdown down the connection.
        """
        if self._imap.sock is not None:
            try:
                self._imap.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            finally:
                try:
                    self._imap.sock.close()
                except Exception:
                    pass
                self._imap.sock = None
                self._cached_capabilities = None

    @require_capability('ENABLE')
    def enable(self, *capabilities):
        """Activate one or more server side capability extensions.

        Most capabilities do not need to be enabled. This is only
        required for extensions which introduce backwards incompatible
        behaviour. Two capabilities which may require enable are
        ``CONDSTORE`` and ``UTF8=ACCEPT``.

        A list of the requested extensions that were successfully
        enabled on the server is returned.

        Once enabled each extension remains active until the IMAP
        connection is closed.

        See :rfc:`5161` for more details.
        """
        if not capabilities:
            raise self.Error('No arguments for ENABLE command')

        try:
            typ, data = self._imap._simple_command('ENABLE', *capabilities)
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        if len(data) != 1:
            raise self.Error('Invalid ENABLE response')

        response = data[0].decode('ascii')
        if not response.startswith('* ENABLED '):
            raise self.Error('Invalid ENABLE response')

        return response[10:].split()

    @require_capability('ID')
    def id_(self, parameters=None):
        """Issue the ID command, returning a dict of server implementation
        fields.

        *parameters* should be specified as a dictionary of field/value pairs,
        for example: ``{"name": "IMAPClient", "version": "0.12"}``
        """
        if parameters is None:
            args = ['NIL']
        else:
            if not isinstance(parameters, dict):
                raise TypeError('parameters must be a dict or None')
            args = []
            for key, value in parameters.items():
                args.extend([to_bytes(key), to_bytes(value)])

        try:
            typ, data = self._imap._simple_command('ID', '(' + ' '.join(args) + ')')
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        if len(data) != 1:
            raise self.Error('Invalid ID response')

        response = data[0].decode('ascii')
        if not response.startswith('* ID '):
            raise self.Error('Invalid ID response')

        response = response[5:]
        if response == 'NIL':
            return {}

        if not (response.startswith('(') and response.endswith(')')):
            raise self.Error('Invalid ID response')

        response = response[1:-1].split()
        if len(response) % 2 != 0:
            raise self.Error('Invalid ID response')

        return dict(zip(response[::2], response[1::2]))

    def capabilities(self):
        """Returns the server capability list.

        If the session is authenticated and the server has returned an
        untagged CAPABILITY response at authentication time, this
        response will be returned. Otherwise, the CAPABILITY command
        will be issued to the server, with the results cached for
        future calls.

        If the session is not yet authenticated, the capabilities
        requested at connection time will be returned.
        """
        if self._cached_capabilities is None:
            try:
                typ, data = self._imap.capability()
            except imaplib.IMAP4.error as e:
                raise self.Error(str(e))

            if typ != 'OK':
                raise self.Error(data[0].decode('ascii'))

            if len(data) != 1:
                raise self.Error('Invalid CAPABILITY response')

            response = data[0].decode('ascii')
            if not response.startswith('* CAPABILITY '):
                raise self.Error('Invalid CAPABILITY response')

            self._cached_capabilities = response[13:].split()

        return self._cached_capabilities

    def has_capability(self, capability):
        """Return ``True`` if the IMAP server has the given *capability*."""
        return capability.upper() in self.capabilities()

    @require_capability('NAMESPACE')
    def namespace(self):
        """Return the namespace for the account as a (personal, other,
        shared) tuple.

        Each element may be None if no namespace of that type exists,
        or a sequence of (prefix, separator) pairs.

        For convenience the tuple elements may be accessed
        positionally or using attributes named *personal*, *other* and
        *shared*.

        See :rfc:`2342` for more details.
        """
        try:
            typ, data = self._imap.namespace()
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        if len(data) != 1:
            raise self.Error('Invalid NAMESPACE response')

        response = data[0].decode('ascii')
        if not response.startswith('* NAMESPACE '):
            raise self.Error('Invalid NAMESPACE response')

        response = response[12:]
        if not (response.startswith('(') and response.endswith(')')):
            raise self.Error('Invalid NAMESPACE response')

        def parse_namespace(ns_str):
            if ns_str == 'NIL':
                return None
            if not (ns_str.startswith('(') and ns_str.endswith(')')):
                raise self.Error('Invalid NAMESPACE response')
            ns_str = ns_str[1:-1]
            namespaces = []
            while ns_str:
                if not (ns_str.startswith('(') and ')' in ns_str):
                    raise self.Error('Invalid NAMESPACE response')
                ns_end = ns_str.index(')')
                ns_part = ns_str[1:ns_end]
                parts = ns_part.split()
                if len(parts) != 2:
                    raise self.Error('Invalid NAMESPACE response')
                prefix = parts[0].strip('"')
                separator = parts[1].strip('"')
                namespaces.append((prefix, separator))
                ns_str = ns_str[ns_end + 1:].lstrip()
            return namespaces

        response = response[1:-1]
        parts = []
        while response:
            if response.startswith('NIL'):
                parts.append(None)
                response = response[3:].lstrip()
            else:
                if not (response.startswith('(') and ')' in response):
                    raise self.Error('Invalid NAMESPACE response')
                end = response.index(')')
                parts.append(parse_namespace(response[:end + 1]))
                response = response[end + 1:].lstrip()

        if len(parts) != 3:
            raise self.Error('Invalid NAMESPACE response')

        return Namespace(*parts)

    def list_folders(self, directory='', pattern='*'):
        """Get a listing of folders on the server as a list of
        ``(flags, delimiter, name)`` tuples.

        Specifying *directory* will limit returned folders to the
        given base directory. The directory and any child directories
        will returned.

        Specifying *pattern* will limit returned folders to those with
        matching names. The wildcards are supported in
        *pattern*. ``*`` matches zero or more of any character and
        ``%`` matches 0 or more characters except the folder
        delimiter.

        Calling list_folders with no arguments will recursively list
        all folders available for the logged in user.

        Folder names are always returned as unicode strings, and
        decoded from modified UTF-7, except if folder_decode is not
        set.
        """
        if self.folder_encode:
            directory = encode_utf7(directory)
            pattern = encode_utf7(pattern)

        try:
            typ, data = self._imap.list(directory, pattern)
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        ret = []
        for response in data:
            if not response:
                continue
            flags, delimiter, name = self._parse_list_response(response)
            if self.folder_encode:
                name = decode_utf7(name)
            ret.append((flags, delimiter, name))

        return ret

    @require_capability('XLIST')
    def xlist_folders(self, directory='', pattern='*'):
        """Execute the XLIST command, returning ``(flags, delimiter,
        name)`` tuples.

        This method returns special flags for each folder and a
        localized name for certain folders (e.g. the name of the
        inbox may be localized and the flags can be used to
        determine the actual inbox, even if the name has been
        localized.

        A ``XLIST`` response could look something like::

            [((b'\\HasNoChildren', b'\\Inbox'), b'/', u'Inbox'),
             ((b'\\Noselect', b'\\HasChildren'), b'/', u'[Gmail]'),
             ((b'\\HasNoChildren', b'\\AllMail'), b'/', u'[Gmail]/All Mail'),
             ((b'\\HasNoChildren', b'\\Drafts'), b'/', u'[Gmail]/Drafts'),
             ((b'\\HasNoChildren', b'\\Important'), b'/', u'[Gmail]/Important'),
             ((b'\\HasNoChildren', b'\\Sent'), b'/', u'[Gmail]/Sent Mail'),
             ((b'\\HasNoChildren', b'\\Spam'), b'/', u'[Gmail]/Spam'),
             ((b'\\HasNoChildren', b'\\Starred'), b'/', u'[Gmail]/Starred'),
             ((b'\\HasNoChildren', b'\\Trash'), b'/', u'[Gmail]/Trash')]

        This is a *deprecated* Gmail-specific IMAP extension (See
        https://developers.google.com/gmail/imap_extensions#xlist_is_deprecated
        for more information).

        The *directory* and *pattern* arguments are as per
        list_folders().
        """
        if self.folder_encode:
            directory = encode_utf7(directory)
            pattern = encode_utf7(pattern)

        try:
            typ, data = self._imap.xlist(directory, pattern)
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        ret = []
        for response in data:
            if not response:
                continue
            flags, delimiter, name = self._parse_list_response(response)
            if self.folder_encode:
                name = decode_utf7(name)
            ret.append((flags, delimiter, name))

        return ret

    def list_sub_folders(self, directory='', pattern='*'):
        """Return a list of subscribed folders on the server as
        ``(flags, delimiter, name)`` tuples.

        The default behaviour will list all subscribed folders. The
        *directory* and *pattern* arguments are as per list_folders().
        """
        if self.folder_encode:
            directory = encode_utf7(directory)
            pattern = encode_utf7(pattern)

        try:
            typ, data = self._imap.lsub(directory, pattern)
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        ret = []
        for response in data:
            if not response:
                continue
            flags, delimiter, name = self._parse_list_response(response)
            if self.folder_encode:
                name = decode_utf7(name)
            ret.append((flags, delimiter, name))

        return ret

    def find_special_folder(self, folder_flag):
        """Try to locate a special folder, like the Sent or Trash folder.

        >>> server.find_special_folder(imapclient.SENT)
        'INBOX.Sent'

        This function tries its best to find the correct folder (if any) but
        uses heuristics when the server is unable to precisely tell where
        special folders are located.

        Returns the name of the folder if found, or None otherwise.
        """
        if self.has_capability('XLIST'):
            folders = self.xlist_folders()
        else:
            folders = self.list_folders()

        # First try to find a folder with the matching flag
        for flags, delimiter, name in folders:
            if folder_flag in flags:
                return name

        # No folder with the matching flag found, try popular namespaces
        if folder_flag in _POPULAR_SPECIAL_FOLDERS:
            # Get all folder names in a set for faster lookup
            folder_names = {name.lower() for _, _, name in folders}

            # Try to find a folder with a popular name
            for folder_name in _POPULAR_SPECIAL_FOLDERS[folder_flag]:
                # Try with different namespace prefixes
                for prefix, suffix in _POPULAR_PERSONAL_NAMESPACES:
                    test_name = prefix + folder_name + suffix
                    if test_name.lower() in folder_names:
                        return test_name

        return None

    def select_folder(self, folder, readonly=False):
        """Set the current folder on the server.

        Future calls to methods such as search and fetch will act on
        the selected folder.

        Returns a dictionary containing the ``SELECT`` response. At least
        the ``b'EXISTS'``, ``b'FLAGS'`` and ``b'RECENT'`` keys are guaranteed
        to exist. An example::

            {b'EXISTS': 3,
             b'FLAGS': (b'\\Answered', b'\\Flagged', b'\\Deleted', ... ),
             b'RECENT': 0,
             b'PERMANENTFLAGS': (b'\\Answered', b'\\Flagged', b'\\Deleted', ... ),
             b'READ-WRITE': True,
             b'UIDNEXT': 11,
             b'UIDVALIDITY': 1239278212}
        """
        if self.folder_encode:
            folder = encode_utf7(folder)

        try:
            typ, data = self._imap.select(folder, readonly)
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        result = {}
        for response in data:
            if not response:
                continue
            match = _RE_SELECT_RESPONSE.match(response)
            if match:
                key = match.group('key')
                if key == b'READ-WRITE':
                    result[key] = True
                elif key == b'READ-ONLY':
                    result[b'READ-WRITE'] = False
                elif match.group('data'):
                    result[key] = self._parse_response(match.group('data'))
            else:
                key, value = response.split(None, 1)
                try:
                    result[key] = int(value)
                except (ValueError, TypeError):
                    result[key] = value

        if b'READ-WRITE' not in result:
            result[b'READ-WRITE'] = not readonly

        return result

    @require_capability('UNSELECT')
    def unselect_folder(self):
        """Unselect the current folder and release associated resources.

        Unlike ``close_folder``, the ``UNSELECT`` command does not expunge
        the mailbox, keeping messages with \\Deleted flag set for example.

        Returns the UNSELECT response string returned by the server.
        """
        try:
            typ, data = self._imap._simple_command('UNSELECT')
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        return data[0].decode('ascii')

    def noop(self):
        """Execute the NOOP command.

        This command returns immediately, returning any server side
        status updates. It can also be used to reset any auto-logout
        timers.

        The return value is the server command response message
        followed by a list of status responses. For example::

            (b'NOOP completed.',
             [(4, b'EXISTS'),
              (3, b'FETCH', (b'FLAGS', (b'bar', b'sne'))),
              (6, b'FETCH', (b'FLAGS', (b'sne',)))])

        """
        try:
            typ, data = self._imap.noop()
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        return data[0].decode('ascii'), self._consume_responses()

    @require_capability('IDLE')
    def idle(self):
        """Put the server into IDLE mode.

        In this mode the server will return unsolicited responses
        about changes to the selected mailbox. This method returns
        immediately. Use ``idle_check()`` to look for IDLE responses
        and ``idle_done()`` to stop IDLE mode.

        .. note::

            Any other commands issued while the server is in IDLE
            mode will fail.

        See :rfc:`2177` for more information about the IDLE extension.
        """
        if self._idle_tag is not None:
            raise self.Error('Already in IDLE mode')

        try:
            tag = self._imap._command('IDLE')
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        self._idle_tag = tag
        resp = self._imap._get_response()
        if resp is not None:
            raise self.Error('Unexpected IDLE response: %s' % resp)

    def _poll_socket(self, sock, timeout=None):
        """
        Polls the socket for events telling us it's available to read.
        This implementation is more scalable because it ALLOWS your process
        to have more than 1024 file descriptors.
        """
        if not POLL_SUPPORT:
            return self._select_poll_socket(sock, timeout)

        poller = select.poll()
        poller.register(sock, select.POLLIN)

        timeout_ms = None if timeout is None else int(timeout * 1000)
        ready = poller.poll(timeout_ms)
        return bool(ready)

    def _select_poll_socket(self, sock, timeout=None):
        """
        Polls the socket for events telling us it's available to read.
        This implementation is a fallback because it FAILS if your process
        has more than 1024 file descriptors.
        We still need this for Windows and some other niche systems.
        """
        r, _, _ = select.select([sock], [], [], timeout)
        return bool(r)

    @require_capability('IDLE')
    def idle_check(self, timeout=None):
        """Check for any IDLE responses sent by the server.

        This method should only be called if the server is in IDLE
        mode (see ``idle()``).

        By default, this method will block until an IDLE response is
        received. If *timeout* is provided, the call will block for at
        most this many seconds while waiting for an IDLE response.

        The return value is a list of received IDLE responses. These
        will be parsed with values converted to appropriate types. For
        example::

            [(b'OK', b'Still here'),
             (1, b'EXISTS'),
             (1, b'FETCH', (b'FLAGS', (b'\\NotJunk',)))]
        """
        if self._idle_tag is None:
            raise self.Error('Server not in IDLE mode')

        sock = self.socket()
        if sock is None:
            raise self.Error('Socket is closed')

        if not self._poll_socket(sock, timeout):
            return []

        return self._consume_responses()

    @require_capability('IDLE')
    def idle_done(self):
        """Take the server out of IDLE mode.

        This method should only be called if the server is already in
        IDLE mode.

        The return value is of the form ``(command_text,
        idle_responses)`` where *command_text* is the text sent by the
        server when the IDLE command finished (eg. ``b'Idle
        terminated'``) and *idle_responses* is a list of parsed idle
        responses received since the last call to ``idle_check()`` (if
        any). These are returned in parsed form as per
        ``idle_check()``.
        """
        if self._idle_tag is None:
            raise self.Error('Server not in IDLE mode')

        self._imap.send(b'DONE\r\n')
        try:
            typ, data = self._imap._command_complete(self._idle_tag)
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))
        finally:
            self._idle_tag = None

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        return data[0].decode('ascii'), self._consume_responses()

    def folder_status(self, folder, what=None):
        """Return the status of *folder*.

        *what* should be a sequence of status items to query. This
        defaults to ``('MESSAGES', 'RECENT', 'UIDNEXT', 'UIDVALIDITY',
        'UNSEEN')``.

        Returns a dictionary of the status items for the folder with
        keys matching *what*.
        """
        if what is None:
            what = ('MESSAGES', 'RECENT', 'UIDNEXT', 'UIDVALIDITY', 'UNSEEN')

        if self.folder_encode:
            folder = encode_utf7(folder)

        try:
            typ, data = self._imap.status(folder, '(' + ' '.join(what) + ')')
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        response = data[0].decode('ascii')
        if not response.startswith('* STATUS '):
            raise self.Error('Invalid STATUS response: %s' % response)

        match = _RE_SELECT_RESPONSE.match(response[9:])
        if not match:
            raise self.Error('Invalid STATUS response: %s' % response)

        result = {}
        for key, value in self._parse_response(match.group('data')):
            result[key] = value

        return result

    def close_folder(self):
        """Close the currently selected folder, returning the server
        response string.
        """
        try:
            typ, data = self._imap.close()
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        return data[0].decode('ascii')

    def create_folder(self, folder):
        """Create *folder* on the server returning the server response string."""
        if self.folder_encode:
            folder = encode_utf7(folder)

        try:
            typ, data = self._imap.create(folder)
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        return data[0].decode('ascii')

    def rename_folder(self, old_name, new_name):
        """Change the name of a folder on the server."""
        if self.folder_encode:
            old_name = encode_utf7(old_name)
            new_name = encode_utf7(new_name)

        try:
            typ, data = self._imap.rename(old_name, new_name)
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        return data[0].decode('ascii')

    def delete_folder(self, folder):
        """Delete *folder* on the server returning the server response string."""
        if self.folder_encode:
            folder = encode_utf7(folder)

        try:
            typ, data = self._imap.delete(folder)
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        return data[0].decode('ascii')

    def folder_exists(self, folder):
        """Return ``True`` if *folder* exists on the server."""
        return folder in [name for _, _, name in self.list_folders()]

    def subscribe_folder(self, folder):
        """Subscribe to *folder*, returning the server response string."""
        if self.folder_encode:
            folder = encode_utf7(folder)

        try:
            typ, data = self._imap.subscribe(folder)
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        return data[0].decode('ascii')

    def unsubscribe_folder(self, folder):
        """Unsubscribe to *folder*, returning the server response string."""
        if self.folder_encode:
            folder = encode_utf7(folder)

        try:
            typ, data = self._imap.unsubscribe(folder)
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        return data[0].decode('ascii')

    def search(self, criteria='ALL', charset=None):
        """Return a list of messages ids from the currently selected
        folder matching *criteria*.

        *criteria* should be a sequence of one or more criteria
        items. Each criteria item may be either unicode or
        bytes. Example values::

            [u'UNSEEN']
            [u'SMALLER', 500]
            [b'NOT', b'DELETED']
            [u'TEXT', u'foo bar', u'FLAGGED', u'SUBJECT', u'baz']
            [u'SINCE', date(2005, 4, 3)]

        IMAPClient will perform conversion and quoting as
        required. The caller shouldn't do this.

        It is also possible (but not recommended) to pass the combined
        criteria as a single string. In this case IMAPClient won't
        perform quoting, allowing lower-level specification of
        criteria. Examples of this style::

            u'UNSEEN'
            u'SMALLER 500'
            b'NOT DELETED'
            u'TEXT "foo bar" FLAGGED SUBJECT "baz"'
            b'SINCE 03-Apr-2005'

        To support complex search expressions, criteria lists can be
        nested. IMAPClient will insert parentheses in the right
        places. The following will match messages that are both not
        flagged and do not have "foo" in the subject::

            ['NOT', ['SUBJECT', 'foo', 'FLAGGED']]

        *charset* specifies the character set of the criteria. It
        defaults to US-ASCII as this is the only charset that a server
        is required to support by the RFC. UTF-8 is commonly supported
        however.

        Any criteria specified using unicode will be encoded as per
        *charset*. Specifying a unicode criteria that can not be
        encoded using *charset* will result in an error.

        Any criteria specified using bytes will be sent as-is but
        should use an encoding that matches *charset* (the character
        set given is still passed on to the server).

        See :rfc:`3501#section-6.4.4` for more details.

        Note that criteria arguments that are 8-bit will be
        transparently sent by IMAPClient as IMAP literals to ensure
        adherence to IMAP standards.

        The returned list of message ids will have a special *modseq*
        attribute. This is set if the server included a MODSEQ value
        to the search response (i.e. if a MODSEQ criteria was included
        in the search).

        """
        if not criteria:
            raise self.Error('No search criteria specified')

        if isinstance(criteria, (str, bytes)):
            criteria = [criteria]

        criteria = _normalise_search_criteria(criteria, charset)

        try:
            typ, data = self._imap.search(charset or 'US-ASCII', *criteria)
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        if not data[0]:
            return []

        message_ids = [int(i) for i in data[0].split()]

        # Check for MODSEQ in response
        for response in self._consume_responses():
            if len(response) == 2 and response[0].upper() == b'MODSEQ':
                message_ids.modseq = response[1]
                break

        return message_ids

    @require_capability('X-GM-EXT-1')
    def gmail_search(self, query, charset='UTF-8'):
        """Search using Gmail's X-GM-RAW attribute.

        *query* should be a valid Gmail search query string. For
        example: ``has:attachment in:unread``. The search string may
        be unicode and will be encoded using the specified *charset*
        (defaulting to UTF-8).

        This method only works for IMAP servers that support X-GM-RAW,
        which is only likely to be Gmail.

        See https://developers.google.com/gmail/imap_extensions#extension_of_the_search_command_x-gm-raw
        for more info.
        """
        if not query:
            raise self.Error('No search query specified')

        criteria = ['X-GM-RAW', query]
        return self.search(criteria, charset)

    @require_capability('SORT')
    def sort(self, sort_criteria, criteria='ALL', charset='UTF-8'):
        """Return a list of message ids from the currently selected
        folder, sorted by *sort_criteria* and optionally filtered by
        *criteria*.

        *sort_criteria* may be specified as a sequence of strings or a
        single string. IMAPClient will take care any required
        conversions. Valid *sort_criteria* values::

            ['ARRIVAL']
            ['SUBJECT', 'ARRIVAL']
            'ARRIVAL'
            'REVERSE SIZE'

        The *criteria* and *charset* arguments are as per
        :py:meth:`.search`.

        See :rfc:`5256` for full details.

        Note that SORT is an extension to the IMAP4 standard so it may
        not be supported by all IMAP servers.
        """
        if not sort_criteria:
            raise self.Error('No sort criteria specified')

        if isinstance(sort_criteria, (str, bytes)):
            sort_criteria = [sort_criteria]

        sort_criteria = [to_bytes(c) for c in sort_criteria]

        if not criteria:
            raise self.Error('No search criteria specified')

        if isinstance(criteria, (str, bytes)):
            criteria = [criteria]

        criteria = _normalise_search_criteria(criteria, charset)

        try:
            typ, data = self._imap.sort(sort_criteria, charset or 'US-ASCII', *criteria)
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        if not data[0]:
            return []

        return [int(i) for i in data[0].split()]

    def thread(self, algorithm='REFERENCES', criteria='ALL', charset='UTF-8'):
        """Return a list of messages threads from the currently
        selected folder which match *criteria*.

        Each returned thread is a list of messages ids. An example
        return value containing three message threads::

            ((1, 2), (3,), (4, 5, 6))

        The optional *algorithm* argument specifies the threading
        algorithm to use.

        The *criteria* and *charset* arguments are as per
        :py:meth:`.search`.

        See :rfc:`5256` for more details.
        """
        if not criteria:
            raise self.Error('No search criteria specified')

        if isinstance(criteria, (str, bytes)):
            criteria = [criteria]

        criteria = _normalise_search_criteria(criteria, charset)

        try:
            typ, data = self._imap.thread(algorithm.upper(), charset or 'US-ASCII', *criteria)
        except imaplib.IMAP4.error as e:
            raise self.Error(str(e))

        if typ != 'OK':
            raise self.Error(data[0].decode('ascii'))

        if not data[0]:
            return []

        return parse_message_list(data[0])

    def get_flags(self, messages):
        """Return the flags set for each message in *messages* from
        the currently selected folder.

        The return value is a dictionary structured like this: ``{
        msgid1: (flag1, flag2, ... ), }``.
        """
        response = self.fetch(messages, ['FLAGS'])
        return {msg_id: flags for msg_id, flags in response.items()}

    def add_flags(self, messages, flags, silent=False):
        """Add *flags* to *messages* in the currently selected folder.

        *flags* should be a sequence of strings.

        Returns the flags set for each modified message (see
        *get_flags*), or None if *silent* is true.
        """
        pass

    def remove_flags(self, messages, flags, silent=False):
        """Remove one or more *flags* from *messages* in the currently
        selected folder.

        *flags* should be a sequence of strings.

        Returns the flags set for each modified message (see
        *get_flags*), or None if *silent* is true.
        """
        pass

    def set_flags(self, messages, flags, silent=False):
        """Set the *flags* for *messages* in the currently selected
        folder.

        *flags* should be a sequence of strings.

        Returns the flags set for each modified message (see
        *get_flags*), or None if *silent* is true.
        """
        pass

    def get_gmail_labels(self, messages):
        """Return the label set for each message in *messages* in the
        currently selected folder.

        The return value is a dictionary structured like this: ``{
        msgid1: (label1, label2, ... ), }``.

        This only works with IMAP servers that support the X-GM-LABELS
        attribute (eg. Gmail).
        """
        pass

    def add_gmail_labels(self, messages, labels, silent=False):
        """Add *labels* to *messages* in the currently selected folder.

        *labels* should be a sequence of strings.

        Returns the label set for each modified message (see
        *get_gmail_labels*), or None if *silent* is true.

        This only works with IMAP servers that support the X-GM-LABELS
        attribute (eg. Gmail).
        """
        pass

    def remove_gmail_labels(self, messages, labels, silent=False):
        """Remove one or more *labels* from *messages* in the
        currently selected folder, or None if *silent* is true.

        *labels* should be a sequence of strings.

        Returns the label set for each modified message (see
        *get_gmail_labels*).

        This only works with IMAP servers that support the X-GM-LABELS
        attribute (eg. Gmail).
        """
        pass

    def set_gmail_labels(self, messages, labels, silent=False):
        """Set the *labels* for *messages* in the currently selected
        folder.

        *labels* should be a sequence of strings.

        Returns the label set for each modified message (see
        *get_gmail_labels*), or None if *silent* is true.

        This only works with IMAP servers that support the X-GM-LABELS
        attribute (eg. Gmail).
        """
        pass

    def delete_messages(self, messages, silent=False):
        """Delete one or more *messages* from the currently selected
        folder.

        Returns the flags set for each modified message (see
        *get_flags*).
        """
        pass

    def fetch(self, messages, data, modifiers=None):
        """Retrieve selected *data* associated with one or more
        *messages* in the currently selected folder.

        *data* should be specified as a sequence of strings, one item
        per data selector, for example ``['INTERNALDATE',
        'RFC822']``.

        *modifiers* are required for some extensions to the IMAP
        protocol (eg. :rfc:`4551`). These should be a sequence of strings
        if specified, for example ``['CHANGEDSINCE 123']``.

        A dictionary is returned, indexed by message number. Each item
        in this dictionary is also a dictionary, with an entry
        corresponding to each item in *data*. Returned values will be
        appropriately typed. For example, integer values will be returned as
        Python integers, timestamps will be returned as datetime
        instances and ENVELOPE responses will be returned as
        :py:class:`Envelope <imapclient.response_types.Envelope>` instances.

        String data will generally be returned as bytes (Python 3) or
        str (Python 2).

        In addition to an element for each *data* item, the dict
        returned for each message also contains a *SEQ* key containing
        the sequence number for the message. This allows for mapping
        between the UID and sequence number (when the *use_uid*
        property is ``True``).

        Example::

            >> c.fetch([3293, 3230], ['INTERNALDATE', 'FLAGS'])
            {3230: {b'FLAGS': (b'\\Seen',),
                    b'INTERNALDATE': datetime.datetime(2011, 1, 30, 13, 32, 9),
                    b'SEQ': 84},
             3293: {b'FLAGS': (),
                    b'INTERNALDATE': datetime.datetime(2011, 2, 24, 19, 30, 36),
                    b'SEQ': 110}}

        """
        pass

    def append(self, folder, msg, flags=(), msg_time=None):
        """Append a message to *folder*.

        *msg* should be a string contains the full message including
        headers.

        *flags* should be a sequence of message flags to set. If not
        specified no flags will be set.

        *msg_time* is an optional datetime instance specifying the
        date and time to set on the message. The server will set a
        time if it isn't specified. If *msg_time* contains timezone
        information (tzinfo), this will be honoured. Otherwise the
        local machine's time zone sent to the server.

        Returns the APPEND response as returned by the server.
        """
        pass

    @require_capability('MULTIAPPEND')
    def multiappend(self, folder, msgs):
        """Append messages to *folder* using the MULTIAPPEND feature from :rfc:`3502`.

        *msgs* must be an iterable. Each item must be either a string containing the
        full message including headers, or a dict containing the keys "msg" with the
        full message as before, "flags" with a sequence of message flags to set, and
        "date" with a datetime instance specifying the internal date to set.
        The keys "flags" and "date" are optional.

        Returns the APPEND response from the server.
        """
        pass

    def copy(self, messages, folder):
        """Copy one or more messages from the current folder to
        *folder*. Returns the COPY response string returned by the
        server.
        """
        pass

    @require_capability('MOVE')
    def move(self, messages, folder):
        """Atomically move messages to another folder.

        Requires the MOVE capability, see :rfc:`6851`.

        :param messages: List of message UIDs to move.
        :param folder: The destination folder name.
        """
        pass

    def expunge(self, messages=None):
        """Use of the *messages* argument is discouraged.
        Please see the ``uid_expunge`` method instead.

        When, no *messages* are specified, remove all messages
        from the currently selected folder that have the
        ``\\Deleted`` flag set.

        The return value is the server response message
        followed by a list of expunge responses. For example::

            ('Expunge completed.',
             [(2, 'EXPUNGE'),
              (1, 'EXPUNGE'),
              (0, 'RECENT')])

        In this case, the responses indicate that the message with
        sequence numbers 2 and 1 where deleted, leaving no recent
        messages in the folder.

        See :rfc:`3501#section-6.4.3` section 6.4.3 and
        :rfc:`3501#section-7.4.1` section 7.4.1 for more details.

        When *messages* are specified, remove the specified messages
        from the selected folder, provided those messages also have
        the ``\\Deleted`` flag set. The return value is ``None`` in
        this case.

        Expunging messages by id(s) requires that *use_uid* is
        ``True`` for the client.

        See :rfc:`4315#section-2.1` section 2.1 for more details.
        """
        pass

    @require_capability('UIDPLUS')
    def uid_expunge(self, messages):
        """Expunge deleted messages with the specified message ids from the
        folder.

        This requires the UIDPLUS capability.

        See :rfc:`4315#section-2.1` section 2.1 for more details.
        """
        pass

    @require_capability('ACL')
    def getacl(self, folder):
        """Returns a list of ``(who, acl)`` tuples describing the
        access controls for *folder*.
        """
        pass

    @require_capability('ACL')
    def setacl(self, folder, who, what):
        """Set an ACL (*what*) for user (*who*) for a folder.

        Set *what* to an empty string to remove an ACL. Returns the
        server response string.
        """
        pass

    @require_capability('QUOTA')
    def get_quota(self, mailbox='INBOX'):
        """Get the quotas associated with a mailbox.

        Returns a list of Quota objects.
        """
        pass

    @require_capability('QUOTA')
    def _get_quota(self, quota_root=''):
        """Get the quotas associated with a quota root.

        This method is not private but put behind an underscore to show that
        it is a low-level function. Users probably want to use `get_quota`
        instead.

        Returns a list of Quota objects.
        """
        pass

    @require_capability('QUOTA')
    def get_quota_root(self, mailbox):
        """Get the quota roots for a mailbox.

        The IMAP server responds with the quota root and the quotas associated
        so there is usually no need to call `get_quota` after.

        See :rfc:`2087` for more details.

        Return a tuple of MailboxQuotaRoots and list of Quota associated
        """
        pass

    @require_capability('QUOTA')
    def set_quota(self, quotas):
        """Set one or more quotas on resources.

        :param quotas: list of Quota objects
        """
        pass

    def _check_resp(self, expected, command, typ, data):
        """Check command responses for errors.

        Raises IMAPClient.Error if the command fails.
        """
        pass

    def _raw_command(self, command, args, uid=True):
        """Run the specific command with the arguments given. 8-bit arguments
        are sent as literals. The return value is (typ, data).

        This sidesteps much of imaplib's command sending
        infrastructure because imaplib can't send more than one
        literal.

        *command* should be specified as bytes.
        *args* should be specified as a list of bytes.
        """
        pass

    def _send_literal(self, tag, item):
        """Send a single literal for the command with *tag*."""
        pass

    def _store(self, cmd, messages, flags, fetch_key, silent):
        """Worker function for the various flag manipulation methods.

        *cmd* is the STORE command to use (eg. '+FLAGS').
        """
        pass

    @property
    def welcome(self):
        """access the server greeting message"""
        pass

class _literal(bytes):
    """Hold message data that should always be sent as a literal."""

class _quoted(bytes):
    """
    This class holds a quoted bytes value which provides access to the
    unquoted value via the *original* attribute.

    They should be created via the *maybe* classmethod.
    """

    @classmethod
    def maybe(cls, original):
        """Maybe quote a bytes value.

        If the input requires no quoting it is returned unchanged.

        If quoting is required a *_quoted* instance is returned. This
        holds the quoted version of the input while also providing
        access to the original unquoted source.
        """
        pass

def join_message_ids(messages):
    """Convert a sequence of messages ids or a single integer message id
    into an id byte string for use with IMAP commands
    """
    pass
_not_present = object()

class _dict_bytes_normaliser:
    """Wrap a dict with unicode/bytes keys and normalise the keys to
    bytes.
    """

    def __init__(self, d):
        self._d = d
    items = iteritems

    def __contains__(self, ink):
        for k in self._gen_keys(ink):
            if k in self._d:
                return True
        return False

class IMAPlibLoggerAdapter(LoggerAdapter):
    """Adapter preventing IMAP secrets from going to the logging facility."""