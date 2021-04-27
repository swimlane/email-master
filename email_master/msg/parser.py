import base64
import tempfile
import compressed_rtf
from email_master.util import EmailAttachmentList, EmailAttachment, EmailParser
from email_master.compat import to_unicode
from extract_msg import Message
from extract_msg.utils import xstr
import hashlib
import re
import six
import json

if six.PY3:
    unicode = to_unicode
    UnicodeType = str
else:
    UnicodeType = unicode


class MSGMessageObj(Message, object):
    def __init__(self, *args, **kwargs):
        self._getStringStream = self.fixed_ss
        Message.__init__(self, *args, **kwargs)  # Old class-style super().__init__ call

    @property
    def stringEncoding(self):
        """
        PATCHED stringEncoding, to allow failing encodings to resolve using utf-8
        """

        try:
            return self.__stringEncoding
        except AttributeError:
            # We need to calculate the encoding
            # Let's first check if the encoding will be unicode:
            if self.areStringsUnicode:
                self.__stringEncoding = "utf-16-le"
                return self.__stringEncoding
            else:
                # Well, it's not unicode. Now we have to figure out what it IS.
                if not self.mainProperties.has_key('3FFD0003'):
                    self.__stringEncoding = "utf-8"  # Unable to determine encoding, try catch-all utf-8
                    return self.__stringEncoding
                    # raise Exception('Encoding property not found')

                enc = self.mainProperties['3FFD0003'].value
                # Now we just need to translate that value
                # Now, this next line SHOULD work, but it is possible that it might not...
                self.__stringEncoding = str(enc)
                return self.__stringEncoding

    @property
    def body(self):
        """
        PATCHED func from lib for MSG encoding issues

        Returns the message body, if it exists.
        """
        try:
            return self._body
        except AttributeError:
            self._body = self._getStringStream('__substg1.0_1000')
            if self._body:
                a = re.search('\n', self._body)
                if a is not None:
                    if re.search('\r\n', self._body) is not None:
                        self.__crlf = '\r\n'
            return self._body

    def fixed_ss(self, filename, prefix=True):
        """
        __getStringStream()

        PATCHED func for MSG encoding issues
        """
        from extract_msg.utils import windowsUnicode
        filename = self.fix_path(filename, prefix)
        if self.areStringsUnicode:
            return windowsUnicode(self._getStream(filename + '001F', prefix=False))
        else:
            tmp = self._getStream(filename + '001E', prefix=False)
            if not tmp:
                return None

            try:
                tmp = tmp.decode(self.stringEncoding)  # The MSG lied about string encoding, we need to figure it out
            except UnicodeDecodeError:
                tmp = tmp.decode("utf-8", errors="replace")  # Last attempt at decoding before exception

            return tmp


class MSGParser(EmailParser):
    """
    See https://msdn.microsoft.com/en-us/library/cc433490(v=exchg.80).aspx for full property list
    """

    def __init__(self, email_data, filename="unknown.msg", ignore_errors=False, exclude_attachment_extensions=None,
                 include_attachment_extensions=None):
        """
        Parse an MSG File
        :param fn: filename of msg file
        :param email_data: base64 data of the MSG file
        """
        super(MSGParser, self).__init__(email_data,
                                        filename=filename,
                                        ignore_errors=ignore_errors,
                                        exclude_attachment_extensions=exclude_attachment_extensions,
                                        include_attachment_extensions=include_attachment_extensions)
        temp_file = tempfile.SpooledTemporaryFile()  # Create a temp file for the ole library
        temp_file.write(base64.b64decode(email_data))

        self.msg = MSGMessageObj(temp_file)

    def _get_msg_data(self, filename):
        if self.msg.areStringsUnicode:
            charset = "utf_16_le"
            suffix = "001F"
        else:
            charset = self.msg.stringEncoding
            suffix = "001E"

        result = self.msg._getStream(filename + suffix, prefix=False)

        if result is None:
            return u""

        try:
            result = result.decode(charset)
        except Exception:
            # Fall back to UTF-8 (If we fail here it's unparsable and should throw an error)
            result = result.decode("utf-8")

        return result

    def get_cc(self):
        return self.msg.cc or u""

    def get_bcc(self):
        return self._get_msg_data('__substg1.0_0E02')

    def get_raw_content(self):
        return self.email_data

    def get_raw_headers(self):
        return u"\n".join([u"{}: {}".format(h[0], h[1]) for h in self.get_headers() or []])

    def get_headers_json(self):
        json_dict = {}
        for h in self.get_headers():
            json_dict[h[0]] = h[1]
        return json.dumps(json_dict)

    def get_reply_to(self):
        return self._get_msg_data('__substg1.0_1042')

    def get_id(self):
        return self._get_msg_data('__substg1.0_1035')

    def get_sender(self):
        return self.msg.sender or u""

    def get_plaintext_body(self):
        return self.msg.body or u""

    def get_html_body(self, decode_html=True):
        return self._get_msg_data('__substg1.0_1013')

    def get_rtf_body(self):
        data = self._get_msg_data("__substg1.0_10090102")
        if data:
            return compressed_rtf.decompress(data) or u""
        else:
            return u""

    def get_date(self):
        return self.msg.date or u""

    def get_subject(self):
        return self.msg.subject or u"(No Subject)"

    def get_type(self):
        return u"MSG"

    def get_recipients(self):
        return u",".join([self.msg.cc or u"", self.msg.to or u""])

    def get_headers(self):
        headers = self.msg.header._headers
        return headers if headers else []

    def get_attachments(self):
        raw_attachments = self.msg.attachments
        attachments = EmailAttachmentList()

        for raw_attachment in raw_attachments:
            if raw_attachment.data:
                data = raw_attachment.data
            else:
                data = self.msg._getStream(raw_attachment.dir + '__substg1.0_37010102')

            if not data:
                # No data in the attachment ignore
                continue
            elif isinstance(data, Message):
                # Following code taken from extract_msg.save()
                eml_data = 'From: ' + xstr(self.msg.sender) + "\n"
                eml_data += 'To: ' + xstr(self.msg.to) + "\n"
                eml_data += 'CC: ' + xstr(self.msg.cc) + "\n"
                eml_data += 'Subject: ' + xstr(self.msg.subject) + "\n"
                eml_data += 'Date: ' + xstr(self.msg.date) + "\n"
                eml_data += '-----------------' + "\n" + "\n"
                eml_data += self.msg.body

                data = eml_data
            if isinstance(data, UnicodeType):
                data = data.encode("utf-8", errors="replace")

            fallback_name = u"unknown-{}".format(hashlib.md5(data).hexdigest())

            filename = raw_attachment.longFilename or fallback_name
            header_info = raw_attachment.shortFilename or fallback_name

            attachments.add_attachment(EmailAttachment(header_info, filename, data))

        return attachments
