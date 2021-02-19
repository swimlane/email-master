import re
import email
import hashlib
from email_master.util import EmailParser, EmailUtil, EmailAttachment, EmailAttachmentList
from email_master.compat import base64_decode, base64_decode_to_bytes, to_unicode
import six
import uuid
from binascii import Error as BinASCIIError

if six.PY2:
    from HTMLParser import HTMLParser
    from types import StringTypes
elif six.PY3:
    from html.parser import HTMLParser
    StringTypes = str
    unicode = to_unicode


class EMLParser(EmailParser):
    def __init__(self, email_data, filename="unknown.eml", ignore_errors=False, exclude_attachment_extensions=None,
                 include_attachment_extensions=None):
        super(EMLParser, self).__init__(email_data,
                                        filename=filename,
                                        ignore_errors=ignore_errors,
                                        exclude_attachment_extensions=exclude_attachment_extensions,
                                        include_attachment_extensions=include_attachment_extensions)
        if six.PY3:
            self.msg = email.message_from_bytes(base64_decode_to_bytes(email_data))
        else:
            self.msg = email.message_from_string(base64_decode(email_data))

        # Class-global list to keep track of which attachments have been processed INCLUDES BODY "attachment"
        self.processed_attachment_hashes = []
        # list to keep track of attachments that are body attachments
        self.body_attachment_hashes = []

    def get_cc(self):
        return self.msg["cc"] or u""

    def get_bcc(self):
        return self.msg["bcc"] or u""

    def get_raw_content(self):
        if six.PY2:
            return self.msg.as_string()
        else:
            charsets = self.msg.get_charsets()
            for charset in charsets:
                to_try = EmailUtil.validate_charset(charset)
                try:
                    return bytes(self.msg.as_string(), encoding=to_try).decode(to_try, errors="replace")
                except:
                    continue

            # Can't figure out the encoding, try utf-8 with ignore, if that fails, it will raise exception
            return bytes(self.msg).decode("utf-8", errors="ignore")

    def get_raw_headers(self):
        return u"\n".join([u"{}: {}".format(unicode(h[0], "utf-8", "ignore"), unicode(h[1], "utf-8", "ignore")) for h in self.msg.items() or []])

    def get_sender(self):
        return EmailUtil.try_decode(self.msg['From']) or u""

    def get_reply_to(self):
        return EmailUtil.try_decode(self.msg["Reply-To"]) or u""

    def get_plaintext_body(self):
        # list of message parts that could be bodies, but weren't found to be typed as a body, but if nothing else
        # it's probably the body

        # TODO Refactor this
        attachments = [self._parse_attachment(a._headers, a) for a in list(self.msg.walk())]
        all_msgs = list(self.msg.walk())
        attach_msgs = [all_msgs[idx[0]] for idx in filter(lambda x: x[1], [b for b in enumerate(attachments)])]
        attachment_hashes = []
        [attachment_hashes.extend(self._hash_subbodies(h)) for h in attach_msgs]

        possible_bodies = []

        if self.msg.is_multipart():
            for part in self.msg.walk():
                if hash(part) in attachment_hashes:
                    continue  # Skip attachments
                ctype = part.get_content_type()
                cdispo = str(part.get('Content-Disposition'))
                # Make sure the the part is marked as text, isn't an attachment
                # and hasn't been processed as an attachment
                should_be_body = bool(ctype == 'text/plain')
                should_be_body = bool('attachment' not in cdispo) and should_be_body
                if should_be_body:  # Before we check that it's definitely a body
                    possible_bodies.append(part)

                should_be_body = bool(hash(part) in self.body_attachment_hashes) and should_be_body
                if should_be_body:
                    return self._decode_body(part)
        else:
            if self.msg.get_content_type() in ["text/plain", "text/calendar"]:
                return self._decode_body(self.msg)

        for bod in possible_bodies:
            if hash(bod) in self.processed_attachment_hashes:
                continue
            return self._decode_body(bod)  # Return on the first one that isn't definitely an attachment

        return u""

    def _decode_body(self, part):
        body = None
        for ch in part.get_charsets():
            ch = EmailUtil.validate_charset(ch)
            if ch == "utf-8":
                continue  # Wait to default to utf-8

            body = part.get_payload(decode=True).decode(ch, errors="replace")

        if not body:
            body = part.get_payload(decode=True).decode("utf-8", errors="replace")

        return body

    def _hash_subbodies(self, msg_obj):
        hash_list = [hash(msg_obj)]
        if isinstance(msg_obj._payload, list):
            for submsg_obj in msg_obj._payload:
                hash_list.extend(self._hash_subbodies(submsg_obj))
        elif isinstance(msg_obj._payload, email.message.Message):
            hash_list.append(hash(msg_obj._payload))
        else:
            hash_list.append(hash(msg_obj))
        return list(set(hash_list))

    def get_html_body(self, decode_html=True):
        # TODO Refactor this
        attachments = [self._parse_attachment(a._headers, a) for a in list(self.msg.walk())]
        all_msgs = list(self.msg.walk())
        attach_msgs = [all_msgs[idx[0]] for idx in filter(lambda x: x[1], [b for b in enumerate(attachments)])]
        attachment_hashes = []
        [attachment_hashes.extend(self._hash_subbodies(h)) for h in attach_msgs]

        if self.msg.is_multipart():
            for part in self.msg.walk():
                if hash(part) in attachment_hashes:
                    continue  # Skip attachments
                aaa = bool(hash(part) in self.body_attachment_hashes)
                bbb = bool(hash(part) in self.processed_attachment_hashes)

                ctype = part.get_content_type()
                cdispo = str(part.get('Content-Disposition'))
                if ctype == 'text/html' and 'attachment' not in cdispo:
                    # Try decoding HTML Entities
                    body = self._decode_body(part)
                    if decode_html:
                        if six.PY3:
                            import html
                            return html.unescape(body) or u""
                        else:
                            return HTMLParser().unescape(body) or u""
                    else:
                        return body or u""
        else:
            if self.msg.get_content_type() == "text/html":
                return self._decode_body(self.msg)

        return u""

    def get_rtf_body(self):
        return u""  # Pretty sure EML files can't/shouldn't have rtf bodies

    def get_subject(self):
        return EmailUtil.try_decode(self.msg['Subject']) if self.msg['Subject'] else u"(No Subject)"

    def get_type(self):
        return u"EML"

    def get_date(self):
        return self.msg['Date'] or ""

    def get_recipients(self):
        return EmailUtil.try_decode(self.msg['To']) or ""

    def get_id(self):
        return self.msg['id'] or self.msg['Message-ID'] or ""

    def get_headers(self):
        parser = email.parser.HeaderParser()
        headers = parser.parsestr(self.get_raw_content()).items()
        return headers if headers else []

    def get_attachments(self):
        """
        Handle the attachments and return strings of 'attachments_md5', 'attachments_sha1' and 'attach_info', the hashed
        data of the attachments, where attach_info is the Content-Type and Content-Transfer-Encoding concatenated
        :return: dictionary with csv values
        """
        raw_attachments = self._organize_attachments(self.msg)
        attachments = EmailAttachmentList()

        for raw_attachment in raw_attachments:
            if isinstance(raw_attachment[1], StringTypes) and six.PY3:
                attach_data = raw_attachment[1].encode()
            else:
                attach_data = raw_attachment[1]

            filename = self._get_attachment_filename(raw_attachment[0], hashlib.md5(attach_data).hexdigest())

            email_attachment = EmailAttachment(
                u" ".join([u"{}: {}".format(unicode(k, "utf-8", "ignore"), unicode(v, "utf-8", "ignore")) for k, v in raw_attachment[0].items()]),
                filename, raw_attachment[1])

            # Make sure that the attachments aren't the same as the html_body or plaintext_body
            email_attachment.raw_data = email_attachment.raw_data.decode("utf-8", errors="replace")
            bodies = (self.get_html_body(decode_html=False), self.get_plaintext_body(), self.get_rtf_body())
            if email_attachment.raw_data not in bodies:
                attachments.add_attachment(email_attachment)

        return attachments

    @staticmethod
    def _get_attachment_filename(attachment_headers, fallback_name, use_subject=True):
        """
        Attempt to get the filename from the content-type information, otherwise just use the fallback name
        :param attachment_headers: List of headers for the attachment
        :param fallback_name: Name to use if we can't find a filename, will be prefixed with unknown-<name>
        :return: filename to use for the attachment
        """
        attachment_headers = {k.lower(): v for k, v in attachment_headers.items()}
        filename = "unknown-{}".format(fallback_name)
        parsed = False  # TODO remove me with refactor
        if "content-location" in attachment_headers:
            filename = attachment_headers["content-location"]
            parsed = True
        elif 'subject' in attachment_headers and use_subject:
            filename = "{}.eml".format(attachment_headers['subject'])
            parsed = True
        elif "content-disposition" in attachment_headers:
            content = attachment_headers["content-disposition"].split(";")
            for disp in content:
                disp = disp.strip()
                if disp.startswith("filename"):
                    # Need '*' before equals sometimes, see https://tools.ietf.org/html/rfc5987 page 3 'ext-parameter'
                    match = re.findall(r"filename\*?=\"?([^\"]*)\"?", disp)
                    if match:
                        filename = match[0]
                        parsed = True
                    break
                elif disp.startswith("attachment"):
                    if not use_subject:
                        filename = "email.eml"
                        parsed = True
                        break

        # Second pass at determining filename, don't continue if found already TODO refactor if statements above
        if "content-type" in attachment_headers and not parsed:
            properties = attachment_headers["content-type"].split(";")

            if attachment_headers.get("content-type") == "message/rfc822":
                filename = "rfc822-email.eml"  # Fallback for rfc822 formatted messages attached eml in eml, with no attachment name

            for prop in properties:
                prop = prop.strip()  # Strip \t from prop
                if prop.startswith("name") or prop.startswith("filename"):
                    # Split 'name="asdf.png"' into 'asdf.png'
                    fn = re.split("name=\"?", prop)
                    if len(fn) > 1:  # If split failed we can't determine filename
                        fn = fn[1]
                        if fn.endswith("\"") or fn.endswith("\'"):
                            filename = fn[:-1]  # Cut off trailing quote
                    break

        return EmailUtil.try_decode(filename)  # Try and decode filenames that are encoded with mime encoded-word syntax

    def _is_attachment(self, headers):
        """
        Check if a given payload is an attachment (or it's email body)
        Valid from https://www.w3.org/Protocols/rfc1341/5_Content-Transfer-Encoding.html
        :param headers:
        :return:
        """
        if "content-disposition" in headers:
            if headers["content-disposition"].startswith("attachment"):
                return True
        if "content-transfer-encoding" in headers:
            trans_enc = headers["content-transfer-encoding"].lower()
            if trans_enc in ("quoted-printable", "7bit", "8bit"):
                return False
            else:
                temp_name = str(uuid.uuid4())  # TODO Refactor this?
                fn = self._get_attachment_filename(headers, temp_name, use_subject=False)
                if fn == "unknown-{}".format(temp_name):
                    return False  # Attachment doesn't have a name, most likely a body
                else:
                    return True  # Attachment has a name

    def _organize_attachments(self, eml_obj):
        """
        Organize and filter the attachment data
        :param eml_obj: email object to organize
        :return: List like [[headers, attachment], ...]
        """
        data = self._extract_attachments(eml_obj)  # Recursively extract attachments from EML
        data = filter(lambda x: bool(x), data)  # Filter out the None attachments
        return data

    def _parse_attachment(self, headers, attachment):
        """
        Take in a list of headers and a Message object, and pre-parse the attachment
        Returns None if it isn't an attachment
        :param headers: [(header1, value1), ...]
        :param attachment: Message object to parse
        :return: [{headers}, <attachment raw data>
        """
        lower_headers = {}
        for k, v in headers:
            lower_headers[k.lower()] = v
        if self._is_attachment(lower_headers):
            newdata = self._decode_payload(attachment, additional_headers=lower_headers)
            return [lower_headers, newdata]
        else:
            self.body_attachment_hashes.append(hash(attachment))  # Append it to body, since it can't be a regular attachment
            return None

    def _extract_attachments(self, eml_obj):
        """
        Recursively parse attachments from an email object, keeping track of parsed emails using
        self.seen_attachment_hashes

        :param eml_obj: Message object
        :param level: Level of recursion. If 0 it's the top
        :return: [ [{headers}, <attachment raw data>], ...]
        """

        found_txt_body = False  # Found an attachment that could be the text body

        if hash(eml_obj) in self.processed_attachment_hashes:
            return []
        else:
            data = []
            payload = eml_obj.get_payload()
            # Check that the "attachment" isn't an attached EML file
            if isinstance(payload, list) and len(payload) == 1 and \
                    self._get_attachment_filename(eml_obj, str(uuid.uuid4()), use_subject=False).lower().endswith(".eml"):

                # CHECK RFC822 - Attached email in email, special case handling
                content_type = eml_obj["Content-Type"] or "none"
                match = re.search("message/rfc822", content_type)
                if match:
                    attached_eml = payload[0]
                    eml_obj._payload = attached_eml.as_bytes().decode('utf-8')  # Set payload manually to a string value
                    attach_headers = eml_obj.items()
                    message_content = eml_obj

                else:  # No RFC822 header
                    # The attachment could have headers, want to combine
                    parent_headers = eml_obj.items()
                    child_headers = eml_obj.get_payload()[0].items()
                    combined_headers = []
                    combined_headers.extend(parent_headers)
                    combined_headers.extend(child_headers)

                    message_content = eml_obj
                    attach_headers = combined_headers

                data.append(self._parse_attachment(attach_headers, message_content))
                self.processed_attachment_hashes.append(hash(eml_obj.get_payload()[0]))

            elif isinstance(payload, list) and len(payload) == 1 and isinstance(payload[0], email.message.Message)\
                    and isinstance(payload[0].get_payload(), StringTypes):
                # Another Very specific case of the attached email being an EML that has been parsed into an attachment
                attachment = payload[0]
                if not hash(attachment) in self.processed_attachment_hashes:
                    parent_headers = eml_obj.items()
                    child_headers = attachment.items()
                    combined_headers = []  # Combine headers to give us the most information about this possible attachment
                    combined_headers.extend(parent_headers)
                    combined_headers.extend(child_headers)
                    data.append(self._parse_attachment(combined_headers, attachment))
                    self.processed_attachment_hashes.append(hash(attachment))
            elif isinstance(payload, list):
                for attachment in payload:
                    if isinstance(attachment, email.message.Message):
                        # First condition checks whether the attachment is another email
                        # by checking original and new msg ids
                        msg_id = attachment.get('id') or attachment.get('Message-id')
                        if self.get_id() is not msg_id and msg_id is not None:
                            data.append([dict(attachment.items()), str(eml_obj)])
                        elif not hash(attachment) in self.processed_attachment_hashes:
                            # If this is the root, it's very likely that it's a body, not an attachment
                            # Make sure to only check if we haven't found the text body yet
                            if isinstance(attachment.get_payload(), StringTypes) and not found_txt_body:
                                temp_name = str(uuid.uuid4())
                                fn = self._get_attachment_filename(attachment, temp_name, use_subject=False)
                                # If fn matches the temp_name, then the name wasn't found, and it's most likely
                                # not an attachment could do filename regex here but not guaranteed to work
                                if fn == "unknown-{}".format(temp_name):
                                    found_txt_body = True   # There was an attachment parsed before that is more likely the text body
                                    continue  # Skip because there was no filename, therefore it's probably a body
                                else:
                                    tw = 2

                            data.extend(self._extract_attachments(attachment))
                            self.processed_attachment_hashes.append(hash(attachment))
                        else:
                            continue  # Skip, we've processed this before
                    else:
                        # This shouldn't be an attachment, but in case it is, add it and filter after
                        data.append(self._parse_attachment(eml_obj.items(), attachment))
            elif isinstance(payload, StringTypes):
                data.append(self._parse_attachment(eml_obj.items(), eml_obj))
            else:
                pass
                # Shouldn't ever be here!
        return data

    @staticmethod
    def _decode_payload(attachment, additional_headers=None):
        """
        Take a given email payload and get the raw unencoded data
        :param attachment: email attachment part
        :param additional_headers: additional headers with data on the attachment
        :return:
        """
        if not additional_headers:
            additional_headers = {}

        def check_all_headers(header_key):
            if header_key in attachment:
                return attachment[header_key]
            if header_key in additional_headers:
                return additional_headers[header_key]

            return None

        data = attachment.get_payload()
        old_data = data
        if data and isinstance(data[0], email.message.Message):
            old_data = data[0]
            data = data[0].get_payload()  # Email-ception

        if check_all_headers("content-transfer-encoding") is not None and check_all_headers("content-transfer-encoding").lower() == "base64":
            try:
                try:
                    data = base64_decode_to_bytes(data)
                except TypeError:
                    data = base64_decode_to_bytes(data, altchars="-_")
            except BinASCIIError:  # Email lied about the attachment type, just ignore
                pass
        # Email ception again
        elif isinstance(old_data, email.message.Message) and len(data) >= 1 and isinstance(data[0], email.message.Message):
            data = old_data.as_string()  # Go with super container

        return data
