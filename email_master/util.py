import re
import quopri
import hashlib
import base64
import pendulum
import pendulum.parsing.exceptions
from email_master.attachments import EmailAttachmentList, EmailAttachment
import codecs
import warnings
from email_master.compat import base64_decode, to_unicode, base64_decode_to_bytes
import uuid
import six
from types import FunctionType, MethodType
from email.header import Header
from binascii import Error as BinASCIIError
from email.header import decode_header, make_header

if six.PY2:
    from types import StringTypes, DictType, ListType
    UnicodeType = unicode
elif six.PY3:
    unicode = to_unicode
    DictType = dict
    ListType = list
    StringTypes = str
    UnicodeType = str

# Fields: Type, Default
FIELD_TYPES = {
    "cc": (StringTypes, u""),
    "bcc": (StringTypes, u""),
    "raw_content": (StringTypes, u""),
    "raw_headers": (StringTypes, u""),
    "reply_to": (StringTypes, u""),
    "sender": (StringTypes, u""),
    "plaintext_body": (StringTypes, u""),
    "html_body": (StringTypes, u""),
    "rtf_body": (StringTypes, u""),
    "subject": (StringTypes, u""),
    "type": (StringTypes, u""),
    "recipients": (StringTypes, u""),
    "headers": (ListType, []),
    "attachments": (EmailAttachmentList, EmailAttachmentList()),
    "id": (StringTypes, u""),
    "date": (StringTypes, u"")
}


class EmailParser(object):
    def __init__(self, email_data, filename="unknown", ignore_errors=False, exclude_attachment_extensions=None,
                 include_attachment_extensions=None):
        self.filename = filename
        self.email_data = email_data
        self.ignore_errors = ignore_errors

        def to_lower(s):
            if isinstance(s, str):
                return str.lower(s)
            elif isinstance(s, unicode):
                return unicode.lower(s)
            else:
                raise TypeError("Invalid type detected in attachment inclusions/exclusions! {}".format(s))

        if isinstance(exclude_attachment_extensions, StringTypes):
            exclude_attachment_extensions = [exclude_attachment_extensions]

        if isinstance(include_attachment_extensions, StringTypes):
            include_attachment_extensions = [include_attachment_extensions]

        self.exclude_attachment_extensions = tuple(exclude_attachment_extensions)
        self.include_attachment_extensions = tuple(include_attachment_extensions)

    def get_cc(self):
        raise NotImplementedError

    def get_bcc(self):
        raise NotImplementedError

    def get_raw_content(self):
        raise NotImplementedError

    def get_raw_headers(self):
        raise NotImplementedError

    def get_reply_to(self):
        raise NotImplementedError

    def get_sender(self):
        raise NotImplementedError

    def get_plaintext_body(self):
        raise NotImplementedError

    def get_html_body(self, decode_html=True):
        raise NotImplementedError

    def get_rtf_body(self):
        raise NotImplementedError

    def get_subject(self):
        raise NotImplementedError

    def get_type(self):
        raise NotImplementedError

    def get_recipients(self):
        raise NotImplementedError

    def get_headers(self):
        raise NotImplementedError

    def get_attachments(self):
        raise NotImplementedError

    def get_id(self):
        raise NotImplementedError

    def get_date(self):
        raise NotImplementedError

    def __getattribute__(self, item):
        """Wrap 'get_' calls to ensure some basic type checking"""
        attrib = super(EmailParser, self).__getattribute__(item)
        if isinstance(attrib, (FunctionType, MethodType)) and item.startswith("get_"):

            def wrapped(*args, **kwargs):
                output = attrib(*args, **kwargs)
                expected_type, default_val = FIELD_TYPES[item.replace("get_", "")]
                if isinstance(output, expected_type):
                    return output
                elif not output:  # Output resolves to None
                    warnings.warn("Invalid output type from Parser.{}! Expected '{}', got '{}'".format(
                        item,
                        expected_type,
                        type(output)
                    ))
                    return default_val
                else:
                    raise TypeError("Invalid type returned from Parser.{}! Expected '{}', got '{}'".format(
                        item,
                        expected_type,
                        type(output)
                    ))

            return wrapped
        else:
            return attrib

    @staticmethod
    def _parse_regex(regex, *bodies):
        text = ""
        for body in bodies:
            text = text + body if body else text
        val = sorted(list(set(re.findall(regex, text))))
        return val

    def _get_authenticated_sender(self, headers):
        return ",".join(
            self._parse_regex(r'(?:Authenticated sender:) ([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', headers))

    def _get_clean_emails(self, email_data):
        valid_email_regex = r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"
        return ",".join(self._parse_regex(valid_email_regex, email_data))

    def _try_date_format(self, date_data):
        try:
            # (=\?([^?.]+)\?([B|Q])\?((?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?)\?=)
            dt = pendulum.parse(date_data)
            return dt.to_iso8601_string()
        except (pendulum.parsing.exceptions.ParserError, ValueError):
            return date_data

    def parse(self):
        result = {
            "result": u"failure", "attachments_sha1": "", "attachments_md5": "",
            "attach_info": "", "headers": "",
            "recipients": "", "subject": "", "text_body": "", "html_body": "", "type": "", "attachments_sha256": ""
        }

        # Get attachments always first
        # TODO cache responses for faster performance
        attachment_list = self.get_attachments()
        if self.exclude_attachment_extensions:  # Filter out attachments and their hashes
            attachment_list = attachment_list.filter_by_filename(exclude=self.exclude_attachment_extensions,
                                                                 include=self.include_attachment_extensions)

        result["cc"] = self.get_cc()
        result["bcc"] = self.get_bcc()
        result["raw_headers"] = self.get_raw_headers()
        result["raw_content"] = self.get_raw_content()

        result["headers"] = EmailUtil.try_decode(''.join(h[0] + ": " + h[1] + "\n" for h in self.get_headers()))

        sender = self.get_sender()
        result["sender"] = sender if self._get_clean_emails(sender) else self._get_authenticated_sender(
            result['headers'])
        result["valid_sender_email"] = self._get_clean_emails(sender) or self._get_authenticated_sender(
            result['headers'])

        reply_to = self.get_reply_to()
        result["reply_to"] = reply_to
        result["valid_reply_to_email"] = self._get_clean_emails(reply_to)

        result["recipients"] = self.get_recipients()
        result["valid_recipients_email"] = self._get_clean_emails(self.get_recipients())

        result["subject"] = self.get_subject()
        result["text_body"] = self.get_plaintext_body()
        result["html_body"] = self.get_html_body()

        result["rtf_body"] = self.get_rtf_body()
        result["type"] = self.get_type()

        result["date"] = self._try_date_format(self.get_date())

        result["id"] = self.get_id()

        # Convert key, values to unicode (cleaning)
        for k, v in result.items():
            result[k] = v if v else u""
            if not isinstance(result[k], UnicodeType):
                result[k] = result.pop(k).decode(errors="replace")

        result["result"] = u"success"
        result.update(attachment_list.to_swimlane_output())

        result["orig_filename"] = self.filename
        return result


class EmailUtil(object):

    @staticmethod
    def parse_email_set(iterable_emails, parser_cls, parser_options=None, pre_hook=None, post_hook=None):
        """
        Parse a set of emails, given an iterable-like object of emails to parse
        This is useful for parsing lots of emails at once, also can add pre and post hooks for parsing

        """
        iterable_emails = iter(iterable_emails)
        results = []
        if not parser_options:
            parser_options = {}

        for email in iterable_emails:
            parser_inst = parser_cls(email, **parser_options)
            try:
                if pre_hook:  # Hook function for changing the email if needed
                    email = pre_hook(email)
                results.append(parser_inst.parse())
                if post_hook:  # Hook function for modifiying the email object (ie set read on a server)
                    email = post_hook(email)
            except Exception as e:
                if parser_options.get("ignore_errors", False):
                    results.append({
                        "error": str(e)
                    })
                else:
                    raise
        return results

    @staticmethod
    def text_to_encoded_words(text, charset='utf-8', encoding='b'):
        """
        text: text to be transmitted
        charset: the character set for text
        encoding: either 'q' for quoted-printable or 'b' for base64
        """
        byte_string = text.encode(charset)
        if encoding.lower() == 'b':
            encoded_text = base64.b64encode(byte_string)
        elif encoding.lower() == 'q':
            encoded_text = quopri.encodestring(byte_string)
        else:
            raise ValueError('Encoding must be "b" or "q"')
        return "=?{charset}?{encoding}?{encoded_text}?=".format(
            charset=charset.upper(),
            encoding=encoding.upper(),
            encoded_text=encoded_text.decode('ascii'))

    @staticmethod
    def try_decode(text):
        """
        Attempt 1:
        Tries to use the make/decode header functions which handles international characters which are properly encoded.
        However these functions do not handle things like =?134?Q? properly and will set the charset as 134.
        when these fail, we will manually regex and parse.

        Attempt 2:
        Tries to decode a mime encoded-word syntax string
        See https://dmorgan.info/posts/encoded-word-syntax/ for more info

        :param text:
        :return:
        """

        try:
            if text:
                return str(make_header(decode_header(text))).strip()
            else:
                return u"(None)"
        except Exception:
            mime_regex = r'=\?([^?.]+)\?'  # ?=<charset>?
            mime_regex += r'([b|q|B|Q])\?('  # Base64 or Quoted printable
            mime_regex += r'(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?'  # Base64 regex
            mime_regex += r'|'  # or
            mime_regex += r'.+'  # quoted-printable regex (maybe todo?)
            mime_regex += r')\?='  # ending, ?=

            result = u""

            if isinstance(text, Header):  # Py2&Py3 Compatibility
                try:
                    text = text.encode("utf-8")
                except:
                    text = str(text)

            for item in re.split(r'[\n\s]+', text):
                item = item.strip()
                match = re.match(mime_regex, item)
                if match:
                    charset, encoding, encoded_text = match.groups()
                    charset = EmailUtil.validate_charset(charset)

                    if encoding.lower() == 'b':
                        try:
                            byte_str = base64_decode_to_bytes(encoded_text)
                        except (TypeError, BinASCIIError):  # Py3 compat
                            if six.PY3:
                                return encoded_text  # No need to decode this string in python3

                            byte_str = encoded_text  # Error with base64, just default to the text
                    elif encoding.lower() == 'q':
                        byte_str = quopri.decodestring(encoded_text)
                    else:
                        # Can't decode this string, invalid encoding type
                        return text
                    result = result + byte_str.decode(charset, errors="ignore")
                else:
                    result = result + u" " + unicode(item, "utf-8", "ignore")

            return result.strip() or text  # Return result if it's been populated, else original text

    @staticmethod
    def validate_charset(charset):
        """
        Validate a string charset to ensure it exists
        Python standard encodings: https://docs.python.org/2.4/lib/standard-encodings.html
        Microsoft code number things: https://docs.microsoft.com/en-us/previous-versions/windows/desktop/bb322881(v%3Dvs.85)
        """

        if charset is None:
            return "utf-8"  # No data, have to default to utf

        def regex_match(regex_str, fixed_charset):
            def regex_fix(value):
                try:
                    if re.match(regex_str, value):
                        return fixed_charset
                except:  # Ignore all exceptions to make sure the charset test is fail-proof
                    pass
                finally:
                    return "definitelynotacharset"

            return regex_fix

        def regexify_keywords(keywords):
            re_str = "[^\s]{0,2}"
            spacer = "([-_$]?|[^\s]{0,2})"  # Space keywords out with things like -, _, $
            re_str += spacer.join(keywords)
            re_str += "[^\s]"  # Make sure it doesn't end with a space
            return re_str

        charset_synonyms = [  # These names mean the same thing but python doesn't know it
            ("134", "gb2312"),
            ("unicode", "utf-8"),
            ("windows-936", "gbk"),
            ("238", "cp852"),
            ("windows-1251", "cp1251")
        ]

        keyword_synonyms = [  # List of keywords -> charset, autogenerated using regex
            (["iso", "2022", "jp", "ext"], "iso-2022-jp-ext"),
            (["iso", "2022", "jp"], "iso-2022-jp"),
            (["iso", "2022", "kr"], "iso-2022-kr"),
        ]

        regex_synonyms = [
            # regex_match("myregex", "mycharset")  # Add regex charset data here
        ]

        # Add the keywords to the regex synonyms
        regex_synonyms.extend([regex_match(regexify_keywords(kws[0]), kws[1]) for kws in keyword_synonyms])

        possible_charset_fixes = [ # Add other charset fix functions here
            lambda x: x or "definitelynotacharset"  # No fix
        ]
        # Fixes from charset_synonyms (adds them to the possible_charset_fixes list)
        possible_charset_fixes.extend([lambda x: synm[1] if x.lower().startswith(synm[0]) or
                                                            x.lower().endswith(synm[0]) else x for synm in
                                       charset_synonyms])

        possible_charset_fixes.extend(regex_synonyms)  # Add the regex and keywords

        # Any fix here will only be run if the above fail
        possible_charset_fixes.extend([
            lambda x: x.replace("-", ""),  # Replace 'cp-850' with 'cp850'
            lambda x: "gb2312" if x.startswith("gb23") else x,
            lambda x: "utf-8"  # Fallback
        ])

        for fix in possible_charset_fixes:
            try:
                content_charset = fix(charset)
                codecs.lookup(content_charset)
                return content_charset
            except LookupError:
                continue
        raise Exception("Unknown charset: {}".format(charset))

    @staticmethod
    def check_content_charset(parser):
        """
        Try to get the email charset from a given email parser instance
        :param parser: EmailParser instance
        :return: most likely charset of the email
        """

        regex = r'(?:charset=\"?)([\w-]*)(?:\"+)'
        html_body = parser.get_html_body()
        headers = parser.get_headers()
        if headers:
            try:  # Try to get content charset from headers
                for header in headers:
                    if header[0].lower() == "content-type":
                        return EmailUtil.validate_charset(re.findall(regex, " ".join(header))[0])
            except IndexError:
                pass
        if html_body:
            try:  # Try to get content charset from html_body
                return EmailUtil.validate_charset(re.findall(regex, html_body)[0])
            except IndexError:
                pass
        return "utf-8"  # Default to utf-8 if we can't find it
