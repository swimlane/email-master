import hashlib
import glob
from email_master.compat import base64_encode, to_unicode

import six
if six.PY3:
    unicode = to_unicode


class EmailAttachmentList(object):
    """Container class for attachments, to standardize the output"""

    def __init__(self):
        self.attachments = []

    def filter_by_filename(self, exclude=None, include=None):
        """
        Filenames should be a tuple of endings like (".png", ".gif", ..) to remove from the attachment list
        Returns a new EmailAttachmentList instance
        """

        def do_filter(attch):
            # Only return included if provided. Else do excluded if provided.
            if include:  # Filter out attachments that DO NOT end with any in the list
                return bool(attch.filename.lower().endswith(include))
            elif exclude:
                # Filter out attachments that end with any in the list
                return not bool(attch.filename.lower().endswith(exclude))

        eal = EmailAttachmentList()
        eal.attachments = list(filter(do_filter, self.attachments))
        return eal

    def add_attachment(self, email_attachment):
        if isinstance(email_attachment, EmailAttachment):
            self.attachments.append(email_attachment)
        else:
            raise Exception("Attempted to add attachment to EmailAttachments, invalid type detected")

    def to_swimlane_output(self):
        result = {
            "attach_info": [],
            "attachments": [],
            "attachments_md5": [],
            "attachments_sha1": [],
            "attachments_sha256": []
        }

        # Add all attachments into a list
        for attachment in self.attachments:
            result["attachments"].append(attachment.attachment_data)
            result["attach_info"].append(attachment.header_info)
            result["attachments_sha1"].append(attachment.hash_sha1)
            result["attachments_md5"].append(attachment.hash_md5)
            result["attachments_sha256"].append(attachment.hash_sha256)

        # Flatten results
        for k, v in result.items():
            if k != "attachments":  # Don't flatten the attachments
                result[k] = ",".join(result[k])

        return result


class EmailAttachment(object):
    """Singular Attachment"""

    def __init__(self, header_info, filename, raw_data):
        """
        Create a singular email attachment object
        :param header_info: String of header information about the email
        :param filename: Filename of the attachment
        :param raw_data: Byte-like data, will be base64encoded
        """
        self.header_info = header_info or u""
        self.raw_data = raw_data or u""
        self.filename = filename or u""

        if six.PY3 and not isinstance(self.raw_data, bytes):
            self.raw_data = self.raw_data.encode()

        self.hash_md5 = hashlib.md5(self.raw_data).hexdigest()
        self.hash_sha1 = hashlib.sha1(self.raw_data).hexdigest()
        self.hash_sha256 = hashlib.sha256(self.raw_data).hexdigest()
        self.attachment_data = {
            "filename": self.filename,
            "base64": base64_encode(self.raw_data)
        }