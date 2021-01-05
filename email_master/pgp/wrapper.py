import six
from email.encoders import encode_7or8bit
from email.mime.application import MIMEApplication
from email.utils import collapse_rfc2231_value
from email import message_from_string
import email_master.rfc3156 as rfc3156
import copy
import re
from pgpy import PGPMessage
from pgpy.constants import SymmetricKeyAlgorithm, HashAlgorithm
from email_master.compat import override_as_string

if six.PY3:
    from io import StringIO
else:
    from cStringIO import StringIO


class CustomMIMEWrapper(object):
    """PGP/MIME (RFC1847 + RFC3156) compliant wrapper."""
    _signature_subtype = 'pgp-signature'
    _encryption_subtype = 'pgp-encrypted'
    _keys_subtype = 'pgp-keys'
    _signed_type = 'application/' + _signature_subtype
    _encrypted_type = 'application/' + _encryption_subtype
    _keys_type = 'application/' + _keys_subtype
    _signed_multipart = 'multipart/signed'
    _encrypted_multipart = 'multipart/encrypted'
    _signature_preamble = \
        'This is an OpenPGP/MIME signed message (RFC 4880 and 3156)'
    _encryption_preamble = \
        'This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)'

    def __init__(self, msg):
        self.msg = msg

    def get_payload(self):
        yield self.msg.as_string()

    def _is_mime(self):
        is_multipart = self.msg.is_multipart()
        payloads = len(self.msg.get_payload()) if self.msg.get_payload() else 0
        return is_multipart and payloads == 2

    def _micalg(self, hash_algo):
        algs = {
            HashAlgorithm.MD5: 'md5',
            HashAlgorithm.SHA1: 'sha1',
            HashAlgorithm.RIPEMD160: 'ripemd160',
            HashAlgorithm.SHA256: 'sha256',
            HashAlgorithm.SHA384: 'sha384',
            HashAlgorithm.SHA512: 'sha512',
            HashAlgorithm.SHA224: 'sha224'
        }
        return 'pgp-' + algs[hash_algo]

    def openpgp_mangle_for_signature(self, msg):
        """Return a message suitable for signing.
        Encodes multipart message parts in msg as base64, then renders the
        message to string enforcing the right newline conventions. The
        returned value is suitable for signing according to RFC 3156.
        The incoming message is modified in-place.
        """
        fp = StringIO()
        g = rfc3156.RFC3156CompliantGenerator(
            fp, mangle_from_=False, maxheaderlen=76)

        g.flatten(msg)

        s = re.sub('\r?\n', '\r\n', fp.getvalue())
        if msg.is_multipart():
            if not s.endswith('\r\n'):
                s += '\r\n'
        return s

    def _wrap_signed(self, msg, signature):
        self.msg.set_payload([])
        self.msg.attach(msg)
        self.msg.set_type(CustomMIMEWrapper._signed_multipart)
        self.msg.set_param('micalg', self._micalg(signature.hash_algorithm))
        self.msg.set_param('protocol', CustomMIMEWrapper._signed_type)
        self.msg.preamble = CustomMIMEWrapper._signature_preamble
        second_part = MIMEApplication(_data=str(signature),
                                      _subtype=CustomMIMEWrapper._signature_subtype,
                                      _encoder=encode_7or8bit,
                                      name='signature.asc')
        second_part.add_header('Content-Description', 'OpenPGP digital signature')
        second_part.add_header('Content-Disposition', 'attachment', filename='signature.asc')
        self.msg.attach(second_part)
        return second_part

    def get_encrypted(self):
        try:
            msg = PGPMessage.from_blob(self.msg.get_payload(1).get_payload())
        except:
            return
        yield msg

    @staticmethod
    def copy_headers(from_msg, to_msg, overwrite=False):
        for key, value in from_msg.items():
            if overwrite:
                del to_msg[key]
            if key not in to_msg:
                to_msg[key] = value
        if to_msg.get_unixfrom() is None or overwrite:
            to_msg.set_unixfrom(from_msg.get_unixfrom())
        if (hasattr(from_msg, 'original_size')
                and (getattr(to_msg, 'original_size', None) is None
                     or overwrite)):
            to_msg.original_size = from_msg.original_size

    def decrypt(self, key):
        pmsg = next(iter(self.get_encrypted()))
        decrypted = key.decrypt(pmsg)

        dmsg = decrypted.message
        if isinstance(dmsg, bytearray):
            dmsg = dmsg.decode(decrypted.charset or 'utf-8')

        out = message_from_string(dmsg)
        if decrypted.is_signed:
            signature = next(iter(decrypted.signatures))
            self._wrap_signed(out, signature)
        else:
            self.msg.set_payload(out.get_payload())
            self.copy_headers(out, self.msg, True)
        return self

    def sign(self, key, **kwargs):
        payload = self.openpgp_mangle_for_signature(self.msg)

        signature = key.sign(payload, **kwargs)
        original_msg = copy.deepcopy(self.msg)
        return payload, self._wrap_signed(original_msg, signature)

    def _wrap_encrypted(self, payload):
        self.msg.set_payload([])
        self.msg.set_type(CustomMIMEWrapper._encrypted_multipart)
        self.msg.set_param('protocol', CustomMIMEWrapper._encrypted_type)
        self.msg.preamble = CustomMIMEWrapper._encryption_preamble
        first_part = MIMEApplication(_data='Version: 1',
                                     _subtype=CustomMIMEWrapper._encryption_subtype,
                                     _encoder=encode_7or8bit)
        first_part.add_header('Content-Description',
                              'PGP/MIME version identification')
        self.msg.attach(first_part)
        second_part = MIMEApplication(_data=str(payload),
                                      _subtype='octet-stream',
                                      _encoder=encode_7or8bit,
                                      name='encrypted.asc')
        second_part.add_header('Content-Description',
                               'OpenPGP encrypted message')
        second_part.add_header('Content-Disposition', 'inline',
                               filename='encrypted.asc')
        self.msg.attach(second_part)

    def _encrypt(self, pmsg, keys, cipher, **kwargs):
        emsg = copy.copy(pmsg)
        if len(keys) == 1:
            emsg = keys[0].encrypt(emsg, cipher=cipher, **kwargs)
        else:
            session_key = cipher.gen_key()
            for key in keys:
                emsg = key.encrypt(emsg, cipher=cipher,
                                   sessionkey=session_key,
                                   **kwargs)
            del session_key
        return emsg

    def encrypt(self, key, keys, **kwargs):
        hash = kwargs.get("hash", None)
        if not kwargs.get("cipher"):
            kwargs["cipher"] = SymmetricKeyAlgorithm.AES256

        if len(keys) == 0:
            raise ValueError('At least one key necessary.')

        payload = next(iter(self.get_payload()))
        pmsg = PGPMessage.new(payload)
        pmsg = self._encrypt(pmsg, keys, **kwargs)
        self._wrap_encrypted(pmsg)
        return self

    def sign_encrypt(self, key, keys, **kwargs):
        hash = kwargs.get("hash", None)

        if not kwargs.get("cipher"):
            kwargs["cipher"] = SymmetricKeyAlgorithm.AES256

        if len(keys) == 0:
            raise ValueError('At least one key necessary.')

        payload = next(iter(self.get_payload()))
        pmsg = PGPMessage.new(payload)
        pmsg |= key.sign(pmsg, hash=hash)
        pmsg = self._encrypt(pmsg, keys, **kwargs)
        self._wrap_encrypted(pmsg)
        return self

    def is_signed(self):
        if not self._is_mime():
            return False
        content_type = collapse_rfc2231_value(self.msg.get_payload(1).get_content_type())
        signed = content_type == CustomMIMEWrapper._signed_type or content_type == CustomMIMEWrapper._signed_multipart
        signed = signed and self.msg.get_content_subtype() == "signed"
        return signed

    def is_encrypted(self):
        if not self._is_mime():
            return False
        first_part = override_as_string(self.msg.get_payload(0))
        first_type = self.msg.get_payload(0).get_content_type()
        second_type = self.msg.get_payload(1).get_content_type()
        content_subtype = self.msg.get_content_subtype()
        protocol_param = collapse_rfc2231_value(self.msg.get_param('protocol', ''))
        return ('Version: 1' in first_part and
                first_type == CustomMIMEWrapper._encrypted_type and
                second_type == 'application/octet-stream' and
                content_subtype == 'encrypted' and
                protocol_param == CustomMIMEWrapper._encrypted_type)
