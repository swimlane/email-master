from email_master.eml import EMLParser
from email_master.msg import MSGParser
from email_master.util import EmailParser
from extract_msg.exceptions import InvalidFileFormat
from email_master.exceptions import InvalidDataException

import six


if six.PY3:
    # TODO MSG library throws the first three errors if it isn't an MSG in python3, refactor check or update lib?
    ExceptionList = (IOError, OSError, AttributeError, InvalidDataException, InvalidFileFormat)
else:
    ExceptionList = (InvalidDataException, InvalidFileFormat)


class EmailMasterParser(EmailParser):
    def _get_parser(self, email_data, file_parsers=None, **kwargs):
        if not file_parsers:
            raise Exception("Need a list of classtypes to attempt parsing!")

        errors = []
        # Try the different parsers for email attachments)
        for file_parser in file_parsers:
            try:
                return file_parser(email_data, **kwargs)
            except ExceptionList as e:
                errors.append("{}: {}".format(file_parser.__class__.__name__, str(e)))
                continue
        raise Exception("Unable to parse message, errors: {}".format(str(errors)))

    def __init__(self, email_data, filename="unknown", parser_classes=None, **kwargs):
        """

        :param email_data: Email data suitable for use in the constructor of an EmailParser class instance
        :param kwargs: ignore_errors = False, exclude_attachment_extensions = None
        :param parser_classes: List of ClassTypes to try parsing with, defaults to [MSGParser, EMLParser]
        """

        if not parser_classes:
            parser_classes = [MSGParser, EMLParser]

        self.parser = self._get_parser(email_data, filename=filename, file_parsers=parser_classes, **kwargs)
        super(EmailMasterParser, self).__init__(email_data, filename=filename, **kwargs)

    def get_cc(self):
        return self.parser.get_cc()

    def get_bcc(self):
        return self.parser.get_bcc()

    def get_raw_content(self):
        return self.parser.get_raw_content()

    def get_raw_headers(self):
        return self.parser.get_raw_headers()

    def get_headers_json(self):
        return self.parser.get_headers_json()

    def get_reply_to(self):
        return self.parser.get_reply_to()

    def get_sender(self):
        return self.parser.get_sender()

    def get_plaintext_body(self):
        return self.parser.get_plaintext_body()

    def get_html_body(self, decode_html=True):
        return self.parser.get_html_body()

    def get_rtf_body(self):
        return self.parser.get_rtf_body()

    def get_subject(self):
        return self.parser.get_subject()

    def get_type(self):
        return self.parser.get_type()

    def get_recipients(self):
        return self.parser.get_recipients()

    def get_headers(self):
        return self.parser.get_headers()

    def get_attachments(self):
        return self.parser.get_attachments()

    def get_id(self):

        mid = self.parser.get_id()
        mid = mid.strip('\t\n\a')
        return mid

    def get_date(self):
        return self.parser.get_date()

