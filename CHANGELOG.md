# CHANGELOG

# 0.4.25 2021-02-20

* SMTP send email: all recipients fix
* IMAP Ingest: outlook calendar .eml invites parsing fix

# 0.4.24 2021-02-17

* Updated Pendulum from 1.2.5 to 2.1.2

# 0.4.23 2020-11-20
* Updated attachment hook in message.py to exclude .eml files. This will keep the content type application/octet-stream for eml attachments.

# 0.4.18 - 0.4.22 2020-11-20
* Bug in python's email lib. Added overwrite for generate.py in compat dir with new string function.
* import new as_string function for pgp 
* import error on new function

# 0.4.17 - 2020-11-18
* Added non ascii support to PGP send

# 0.4.16 - 2020-11-12
* Remove encoding on sender for EML.send()

# 0.4.15 - 2020-10-27
* Send Mail to encode non-ascii chars for text and html bodies
* ingest email to properly decode non-ascii characters for headers and body

# 0.4.14 - 2020-10-22
* Send Mail to encode non-ascii chars for subject and from address.

# 0.4.13 - 2020-10-15
* Special case for RFC822 eml in eml added

# 0.4.12 - 2020-9-1
* Specific case for EML within EML added parent headers passed down to child attachment

# 0.4.11 - 2020-6-25
* Fixed tests
* Fixed HTML/TXT bodies sometimes not being processed from attachment extraction correctly
* Added a fallback for eml in eml attachment filenames when rfc822 compatible but no attachment name is given

# 0.4.10 - 2020-6-25
* Attachment from emlception filtering code

# 0.4.9 - 2020-6-24
* Attachment/body fixes

# 0.4.8 - 2020-6-23
* Attachment filename fix, eml in eml fixes

# 0.4.7 - 2020-6-23
* Misc body parsing fixes, attachment parse fix

# 0.4.6 - 2020-6-22
* Header fixes upon PGP ingestion

# 0.4.5 - 2020-6-18
* Fixed eml attachments sometimes being attached as HTML body if there's no text body

# 0.4.4 - 2020-6-17
* Fixed attachments lying about being b64, added raw fallback
* Fixed tests

# 0.4.3 - 2020-6-12
* PGP Type fixes
* Subject internationalization/url encoded text fix

# 0.4.0-0.4.2 - 2020-6-10
* PGP restructure
* Bug fixes

# 0.3.20-0.3.25 - 2020-6-5
* Misc fixes to signing, verification and encryption of EML files

## 0.3.19 - 2020-5-26
* Added option to pass parser args through PGP config
* Added SMTP relay option with option auth

## 0.3.12-0.3.18 - 2020-5-22
* Fixed PGP sending/receiving/verifying and packaging issues

## 0.3.11 - 2020-5-08
* Add signature verification

## 0.3.10 - 2020-4-27
* Added PGP subclass

## 0.3.9 - 2020-3-24
* Fixing more encoding issues

## 0.3.8 - 2020-3-23
* Fixed issue where the type was encoded incorrectly

## 0.3.6-7 - 2020-3-19
* Fixed encoding issue

## 0.3.5 - 2020-3-05
* Fixed python tests, dropped full py2 support

## 0.3.4 - 2020-3-03
* Updated tests and sorting-list for parse_regex in utils.py. Tests are py3 and py2 compatible but only py3 data is checked due to encoding differences. Added Jenkinsfile for test automation.

## 0.3.3 - 2020-2-24
* Content-Disposition Filename patch for attachments

## 0.3.2 - 2020-2-10
* Python3 setup.py fix

## 0.3.1 - 2020-2-10
* Python3 setup.py fix attempt (VERSION IS BROKEN)

## 0.3.0 - 2020-1-30
* Made email-master python2 and python3 compatible

## 0.2.6 - 2020-1-10

* Patched an MSG encoding issue where encoding didn't exist, added utf-8 fallback

## 0.2.5 - 2020-1-10

* Patched an MSG encoding issue where the encoding reported was incorrect, added a fallback encoding

## 0.2.4 - 2019-11-18

* Patched `.eml as an attachment` parsing

## 0.2.3 - 2019-10-31

* Added Changelog
* Patched MSG HTML body parsing

## 0.2.2 - 2019-09-24

* Patched MSG unicode parsing
