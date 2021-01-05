from email_master.compat import base64_decode_to_bytes, base64_encode_bytes
from pgpy.constants import HashAlgorithm
from pgpy.errors import PGPError
from email_master.parser import EmailMasterParser
from email_master.pgp.wrapper import CustomMIMEWrapper

from pgpy import PGPKey, PGPSignature
from pgpy.types import SignatureVerification
import email
import tempfile

import six
import random
from itertools import combinations
from email_master.compat import override_as_string


class _PGPType(object):
    CLEARTEXT = "Cleartext"

    SIGNED = "Signed"
    ENCRYPTED = "Encrypted"

    SIGNED_AND_ENCRYPTED = "Signed & Encrypted"

    SIGNED_AND_VERIFIED = "Signed & Verified"
    SIGNED_AND_ENCRYPTED_AND_VERIFIED = "Signed & Encrypted & Verified"

    SIGNED_AND_NOT_VERIFIED = "Signed & Not Verified"
    SIGNED_AND_ENCRYPTED_NOT_VERIFIED = "Signed & Encrypted & Not Verified"


class PGPIngestType(object):
    def __init__(self, signed=False, encrypted=False):
        self.signed = signed
        self.encrypted = encrypted

    def __str__(self):
        s = _PGPType.CLEARTEXT  # 00

        if self.signed and self.encrypted:  # 11
            s = _PGPType.SIGNED_AND_ENCRYPTED
        elif self.signed:  # 10
            s = _PGPType.SIGNED
        elif self.encrypted: # 01
            s = _PGPType.ENCRYPTED
        return s

    def to_ingest_type(self):
        return self

    def to_output_type(self, verify=False):
        """
        Convert PGPType from Ingest type (which doesn't care about verification) to PGPOutputType (which does)
        """
        return PGPOutputType(self.signed, self.encrypted, verify)

    def needs_pkeys(self):
        """
        Returns whether using this configtype requires public/private keys to continue execution
        """
        if self.signed or self.encrypted:
            return True
        else:
            return False


class PGPOutputType(object):
    def __init__(self, signed=False, encrypted=False, verified=False):
        self.signed = signed
        self.encrypted = encrypted
        self.verified = verified
        str(self)  # Does validity check

    def __str__(self):
        if self.signed and self.encrypted and self.verified:  # 111
            s = _PGPType.SIGNED_AND_ENCRYPTED_AND_VERIFIED
        elif self.signed and self.encrypted and not self.verified:  # 110
            s = _PGPType.SIGNED_AND_ENCRYPTED_NOT_VERIFIED
        elif self.signed and not self.encrypted and self.verified:  # 101
            s = _PGPType.SIGNED_AND_VERIFIED
        elif self.signed and not self.encrypted and not self.verified:  # 100
            s = _PGPType.SIGNED
        elif not self.signed and self.encrypted and self.verified:  # 011
            raise ValueError("Verify cannot be True if the email is not signed!")
        elif not self.signed and self.encrypted and not self.verified:  # 010
            s = _PGPType.ENCRYPTED
        elif not self.signed and not self.encrypted and self.verified:  # 001
            raise ValueError("Verify cannot be True if the email is not signed!")
        elif not self.signed and not self.encrypted and not self.verified:  # 000
            s = _PGPType.CLEARTEXT
        else:
            raise ValueError("Invalid config!")  # Shouldn't be here ever

        return s

    def to_output_type(self, verify=False):
        return self

    def to_ingest_type(self):
        """
        Convert PGP Type from Output type (which cares about verification) to IngestType (which doesn't)
        """
        return PGPIngestType(self.signed, self.encrypted)

    def needs_pkeys(self):
        """
        Returns whether using this configtype requires public/private keys to continue execution
        """
        if self.signed or self.encrypted or self.verified:
            return True
        else:
            return False


class PGPConfig(object):
    def __undefined_attr(self, attr_name):
        def attr(self):
            raise ValueError("Property '{}' not defined and cannot be accessed".format(attr_name))

        return property(attr)

    def __init__(self, pgp_action=None, pgp_private_b64="", pgp_public_b64="", pgp_password=""):
        self.pgp_action = pgp_action
        self.key_pw = pgp_password

        ingest = isinstance(pgp_action, PGPIngestType)
        output = isinstance(pgp_action, PGPOutputType)
        provided_pkeys = not bool(pgp_private_b64 == "" and pgp_public_b64 == "")

        if not ingest and not output:
            raise ValueError("Invalid pgp_action, must be of type PGPIngestType or PGPOutputType!")

        if pgp_action.needs_pkeys() and not provided_pkeys:
            if ingest:
                raise ValueError("Must provide PGP private and public keys to sign/encrypt!")
            elif output:
                raise ValueError("Must provide PGP private and public keys to decrypt/verify signatures!")

        self.priv_key, self.priv_keystore = self._key_from_b64(pgp_private_b64)
        self.pub_key, self.pub_keystore = self._key_from_b64(pgp_public_b64)

        if self.priv_key:
            try:
                with self.priv_key.unlock(self.key_pw):
                    pass
            except Exception as e:
                raise ValueError("Invalid private key or password, key unlock failed! Error: '{}'".format(str(e)))
        else:
            setattr(PGPConfig, "priv_key", self.__undefined_attr("Private Key"))

        if not self.pub_key:
            setattr(PGPConfig, "pub_key", self.__undefined_attr("Public Key"))

    def _generate_bound(self):
        valid_chars = []
        valid_chars.extend(range(ord("A"), ord("Z")))  # A-Z
        valid_chars.extend(range(ord("a"), ord("z")))  # a-z
        valid_chars.extend(range(ord("0"), ord("9")))  # 0-9
        valid_chars = [chr(rr) for rr in valid_chars]  # Convert to chars
        if six.PY3:
            return "".join(random.choices(valid_chars, k=32))  # Sample 32 at random (py3 only)
        else:
            return "".join([random.choice(valid_chars) for _ in range(32)])  # py2 32 samples

    def _key_from_b64(self, data):
        """
        Return a PGPKey from base64 data, if no data return None
        """
        if not data:
            return None, None

        f = tempfile.NamedTemporaryFile(suffix=b'')
        dd = base64_decode_to_bytes(data)
        f.write(dd)
        f.seek(0)
        key, keystore = PGPKey.from_file(f.name)
        f.close()
        return key, keystore

    def _find_duplicated_newlines(self, msg_str, find_char='\r'):
        """
        Find the indexes of duplicate carriage returns, which mess up pgp verification
        Return a list of message strings with modified bodies

        Example: (newlines have been removed
            ...
            Content-Disposition: attachment; filename="Test.eml"\r
            MIME-Version: 1.0\r
            \r
            \r
            <base64>

        The double '\r's (technically triple) was added by python's email parsing package, since it ingested the attachment as a message obj,
        instead of an attachment object, and automatically adds a newline before message objects after using .to_string()
        so it must be removed.

        But we can't be sure that the double \r wasn't just an artifact of the email (since we're doing a global str search)
        so we need to grab all iterations of the double newline.
        So for example say we process an email and find the following indexes have double \r's
        [(31, 32), (45, 46), (78,79)] -> lets call these [A, B, C]
        So now we want all bodies with any combination of these replacements (as any replacement could be real, or an error)
        Essentially -> [[()], [('A',), ('B',), ('C',)], [('A', 'B'), ('A', 'C'), ('B', 'C')], [('A', 'B', 'C')]]
        and then turn those replacements into different bodies.
        Since this is an exponentially increasing function, we don't want to pre-calculate every combination, since
        we break on the first combination that works, so we use generators
        """

        msg_list = msg_str.split("\n")
        idxs = []
        for i in range(len(msg_list)):
            if i + 1 >= len(msg_list):
                continue
            if msg_list[i] == find_char and msg_list[i] == msg_list[i + 1]:
                idxs.append(i)  # Add index that needs to be removed

        num_idxs = len(idxs)
        all_combins = [list(combinations(idxs, size)) for size in range(num_idxs + 1)]  # list of all combinations
        combins = []
        [combins.extend(c) for c in all_combins]  # combine all combinations

        # Unique value to substitute in the list to perform multi replacements without damaging the list due to shifting
        remove_obj = object()

        for comb in combins:
            new_msg_str = str(msg_str)
            new_msg_list = new_msg_str.split("\n")
            for c in comb:
                new_msg_list[c] = remove_obj

            new_msg_list = list(filter(lambda x: x != remove_obj, new_msg_list))  # Filter out the removed objs
            g = "\n".join(new_msg_list)  # rejoin the list
            yield g

    def _find_strip_newlines(self, msg_str):
        """
        Function to find when newlines with whitespace are being duplicated after send/ingest, seems to happen with different mail
        clients. Returns a generator for possible fixes to verify PGP sig
        """
        func_list = [  # List of functions to apply to each line of the msg
            lambda x: x.rstrip(),
            lambda x: x.lstrip(),
            lambda x: x.strip()
        ]

        for stripped_msg in self._find_duplicated_newlines(msg_str, find_char=""):
            for func in func_list:
                yield "\n".join(list(map(func, stripped_msg.split("\n"))))

        # self.pub_key.verify("\n".join(list(map(lambda x: x.rstrip(), aa.split("\n")))), pgp_blob)

    def _bodies_to_test(self, msg_str):
        """
        Create a list of message strings that have been modified slightly (due to poor python parsing) to
        recreate the original email bytes exactly as sent, to verify the PGP signature
        """
        # Bodies is a list of lists, where the inner lists can be generators
        bodies = [
            [
                msg_str,  # Start with unmodified body
                msg_str.replace("\n", "\r\n")  # Need to replace newlines with \r\n "sometimes"
            ],
            self._find_duplicated_newlines(msg_str.replace("\n", "\r\n")),  # Generator for replacements for newline fix
            self._find_duplicated_newlines(msg_str, find_char=''),
            self._find_strip_newlines(msg_str),  # Generator for extra whitespace fix
            self._find_duplicated_newlines(msg_str.replace("\n", "\r\n"), find_char=''),
            self._find_duplicated_newlines(msg_str)  # Generator for newline fix
        ]
        for body_list in bodies:
            for body in body_list:
                yield body

    def _find_pgp_sig(self, msg_obj, enc_body):
        attachments = len(msg_obj.get_payload())
        for idx in range(attachments):
            try:
                pgp_blob = msg_obj.get_payload(idx).get_payload()
                pgp_blob = PGPSignature.from_blob(pgp_blob)

                msg_str = override_as_string(msg_obj.get_payload(0))  # Hard coded 0 for base payload to verify against
                bodies = self._bodies_to_test(msg_str)
                is_pgp_verified = False  # Did we find a body that verified?
                for body in bodies:
                    is_pgp_verified = self.pub_key.verify(body, pgp_blob)
                    if bool(is_pgp_verified):  # This body worked
                        break
                if is_pgp_verified and isinstance(is_pgp_verified, SignatureVerification):
                    return list(is_pgp_verified.good_signatures)
                else:
                    return []
            except PGPError as e:
                continue  # Invalid signature
            except TypeError as e:
                continue  # Invalid body type
            except ValueError as e:
                continue  # Invalid body type (for encrypted message)
        return []  # Couldn't find an attachment with a valid signature

    def _check_pgp_verification(self, mime_msg, message_type, fingerprints, enc_body=None):
        """
        Check the verification status of a signature of a message, returning the message type
        and fingerprints.

        Function is needed because messages can be encrypted before or after the signature is created, leading to the
        need to check it twice (call this func twice)
        """
        sigs = self._find_pgp_sig(mime_msg.msg, enc_body)
        is_verified = len(sigs) > 0  # In case we're already verified

        message_type.verified = message_type.verified or is_verified
        fingerprints.extend([str(sig.by.fingerprint) for sig in sigs])

        return message_type, fingerprints

    def unlock(self, msg_as_string, parser_kwargs):
        # TODO Put check if we should even be able to unlock, raise exception upon method call instead of
        # attribute access. Also would be able to not fail upon being unable to unlock an email

        mime_msg = CustomMIMEWrapper(msg_as_string)
        message_type = PGPOutputType()
        fingerprints = []
        warnings = "None"
        message_type.encrypted = mime_msg.is_encrypted()
        message_type.signed = mime_msg.is_signed()  # Check if the message is signed before decrypting

        # Check pgp verification before decrypting
        message_type, fingerprints = self._check_pgp_verification(mime_msg, message_type, fingerprints)
        encrypted_body = None

        if message_type.encrypted:
            if len(mime_msg.msg.get_payload()) == 2:  # One part pgp header, one part pgp encrypted body
                # TODO Multiple encrypted bodies?
                encrypted_body = override_as_string(mime_msg.msg.get_payload(1))

            with self.priv_key.unlock(self.key_pw) as unlocked_key:
                try:
                    decrypted = mime_msg.decrypt(unlocked_key)
                    if not decrypted:
                        raise ValueError("No decrypted message returned from mime_msg.decrypt!")
                    mime_msg = decrypted
                except PGPError as e:
                    # This means the message cannot be decrypted with this signature
                    warnings = "Attempted decrypt failed, '{}'".format(str(e))

        # Check if the message is signed after decrypting
        message_type.signed = mime_msg.is_signed() or message_type.signed

        # Check pgp verification after decrypting
        message_type, fingerprints = self._check_pgp_verification(mime_msg, message_type, fingerprints, encrypted_body)

        if len(mime_msg.msg._payload) == 2 and message_type.signed:
            mime_msg.msg._payload[0]._headers.extend(
                mime_msg.msg._headers)  # Copy outer headers into the inner message object
            mime_msg.msg._payload[0].preamble = mime_msg.msg.preamble  # Copy the preamble

            orig_msg = EmailMasterParser(base64_encode_bytes(override_as_string(mime_msg.msg.get_payload(0)).encode()),
                                         **parser_kwargs).parse()  # Orig message
            sig_msg = EmailMasterParser(base64_encode_bytes(override_as_string(mime_msg.msg.get_payload(1)).encode()),
                                        **parser_kwargs).parse()  # Signature
            merge_keys = ["attachments_sha1", "attachments_md5", "attachments_sha256", "attach_info", "attachments"]
            for k in merge_keys:
                if isinstance(orig_msg[k], list):
                    orig_msg[k].extend(sig_msg[k])
                else:
                    ks = orig_msg[k].split(",")
                    if ks == ['']:
                        ks = []
                    ks.append(sig_msg[k])
                    orig_msg[k] = ",".join(ks)

            email_data = orig_msg
        else:
            email_data = EmailMasterParser(base64_encode_bytes(override_as_string(mime_msg.msg).encode()), **parser_kwargs).parse()

        email_data.update({
            "message_type": str(message_type),
            "is_verified": message_type.verified,
            "is_signed": message_type.signed,
            "is_encrypted": message_type.encrypted,
            "fingerprints": fingerprints,
            "warnings": warnings
        })
        return email_data

    def _format_signed_payload(self, mime_message, payload, signed_payload):
        bound = self._generate_bound()
        new_headers = list(filter(lambda x: x[0] != "Content-Type", email.message_from_string(payload)._headers))

        signed_payload = signed_payload.as_string().replace("\n", "\r\n")

        header_data = "\r\n".join(["{}: {}".format(b[0], b[1]) for b in new_headers])
        newmsg = header_data + \
                 "\r\nContent-Type: multipart/signed; micalg=pgp-sha256; " + \
                 "protocol=\"application/pgp-signature\";" + \
                 "boundary=\"{bound}\"\r\n--{bound}\r\n".format(bound=bound) + \
                 payload + \
                 "\r\n--{bound}\r\n".format(bound=bound) + \
                 signed_payload + \
                 "--{}--".format(bound)
        return newmsg

    def lock(self, mime_message):
        if self.pgp_action.signed and self.pgp_action.encrypted:
            with self.priv_key.unlock(self.key_pw) as k:
                mime = mime_message.sign_encrypt(k, list(self.pub_keystore.values()))
                return mime.msg.as_string()
        elif self.pgp_action.encrypted:
            with self.priv_key.unlock(self.key_pw) as k:
                mime = mime_message.encrypt(k, list(self.pub_keystore.values()))
                return mime.msg.as_string()
        elif self.pgp_action.signed:
            with self.priv_key.unlock(self.key_pw) as k:
                payload, signed_payload = mime_message.sign(k, hash=HashAlgorithm.SHA256)
                return self._format_signed_payload(mime_message, payload, signed_payload)
        else:
            return mime_message.msg.as_string()
