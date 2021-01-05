from email_master.pgp import PGPConfig
from email_master.attachments import EmailAttachmentList, EmailAttachment
from email_master.compat import base64_decode_to_bytes


class EmailMasterMessage(object):
    NO_PASSWORD = object()

    def __init__(self, message_obj, pgp_config=None):
        self.message_obj = message_obj
        if pgp_config is None:
            self.pgp_config = PGPConfig()
        else:
            self.pgp_config = pgp_config

        self._attachments = EmailAttachmentList()

    def test_conn(self, username, password, host, port, verify_conn=True):
        raise NotImplementedError

    def send(self, username, password, host, port, verify_conn=True):
        raise NotImplementedError

    def add_attachments(self, attachs):
        if isinstance(attachs, EmailAttachmentList):
            for att in attachs.attachments:
                self._attachments.add_attachment(att)
        elif isinstance(attachs, list):
            for att in attachs:
                self.add_attachment(att)
        else:
            raise ValueError("Invalid input! Must be type list or EmailAttachmentList, for singular attachments, use add_attachment!")

    def add_attachment(self, attachment):
        if isinstance(attachment, EmailAttachment):
            self._attachments.add_attachment(attachment)
        else:
            if not isinstance(attachment, dict):
                raise ValueError("Attachment must be dict or EmailAttachment!")

            self._attachments.add_attachment(
                EmailAttachment({}, attachment["filename"], base64_decode_to_bytes(attachment["base64"]))
            )

    def get_summary(self):
        raise NotImplementedError
