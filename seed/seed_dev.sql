--PGPASSWORD=postgres pg_dump -U postgres -h localhost -p 5434 -d yara -t rule --inserts > dev.sql
truncate rule CASCADE;
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (1, 'jjEncode', NULL, '{"ref": "http://blog.xanda.org/2015/06/10/yara-rule-for-jjencode/", "date": "10-June-2015", "hide": false, "author": "adnan.shukor@gmail.com", "impact": 3, "version": "1", "description": "jjencode detection"}', '2020-12-04 20:50:14.36871', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule jjEncode
{
   meta:
      description = "jjencode detection"
      ref = "http://blog.xanda.org/2015/06/10/yara-rule-for-jjencode/"
      author = "adnan.shukor@gmail.com"
      date = "10-June-2015"
      version = "1"
      impact = 3
      hide = false
   strings:
      $jjencode = /(\$|[\S]+)=~\[\]\;(\$|[\S]+)\=\{[\_]{3}\:[\+]{2}(\$|[\S]+)\,[\$]{4}\:\(\!\[\]\+["]{2}\)[\S]+/ fullword
   condition:
      $jjencode
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (2, 'Contains_hidden_PE_File_inside_a_sequence_of_numbers', '{maldoc}', '{"date": "2016-01-09", "author": "Martin Willing (https://evild3ad.com)", "filetype": "decompressed VBA macro code", "reference": "http://www.welivesecurity.com/2016/01/04/blackenergy-trojan-strikes-again-attacks-ukrainian-electric-power-industry/", "description": "Detect a hidden PE file inside a sequence of numbers (comma separated)"}', '2020-12-04 20:50:28.512003', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Contains_hidden_PE_File_inside_a_sequence_of_numbers : maldoc
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect a hidden PE file inside a sequence of numbers (comma separated)"
		reference = "http://blog.didierstevens.com/2016/01/07/blackenergy-xls-dropper/"
		reference = "http://www.welivesecurity.com/2016/01/04/blackenergy-trojan-strikes-again-attacks-ukrainian-electric-power-industry/"
		date = "2016-01-09"
		filetype = "decompressed VBA macro code"

	strings:
		$a = "= Array(" // Array of bytes
		$b = "77, 90," // MZ
		$c = "33, 84, 104, 105, 115, 32, 112, 114, 111, 103, 114, 97, 109, 32, 99, 97, 110, 110, 111, 116, 32, 98, 101, 32, 114, 117, 110, 32, 105, 110, 32, 68, 79, 83, 32, 109, 111, 100, 101, 46," // !This program cannot be run in DOS mode.

	condition:
	 	all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (3, 'MIME_MSO_ActiveMime_base64', '{maldoc}', '{"date": "2016-02-28", "author": "Martin Willing (https://evild3ad.com)", "filetype": "Office documents", "description": "Detect MIME MSO Base64 encoded ActiveMime file"}', '2020-12-04 20:50:31.209718', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule MIME_MSO_ActiveMime_base64 : maldoc
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect MIME MSO Base64 encoded ActiveMime file"
		date = "2016-02-28"
		filetype = "Office documents"

	strings:
		$mime = "MIME-Version:"
		$base64 = "Content-Transfer-Encoding: base64"
		$mso = "Content-Type: application/x-mso"
		$activemime = /Q(\x0D\x0A|)W(\x0D\x0A|)N(\x0D\x0A|)0(\x0D\x0A|)a(\x0D\x0A|)X(\x0D\x0A|)Z(\x0D\x0A|)l(\x0D\x0A|)T(\x0D\x0A|)W/

	condition:
		$mime at 0 and $base64 and $mso and $activemime
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (4, 'Word_2007_XML_Flat_OPC', '{maldoc}', '{"date": "2018-04-29", "hash1": "060c036ce059b465a05c42420efa07bf", "hash2": "2af21d35bb909a0ac081c2399d0939b1", "hash3": "72ffa688c228b0b833e69547885650fe", "author": "Martin Willing (https://evild3ad.com)", "filetype": "Office documents", "reference": "https://blogs.msdn.microsoft.com/ericwhite/2008/09/29/the-flat-opc-format/", "description": "Detect Word 2007 XML Document in the Flat OPC format w/ embedded Microsoft Office 2007+ document"}', '2020-12-04 20:50:31.32755', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule Word_2007_XML_Flat_OPC : maldoc
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect Word 2007 XML Document in the Flat OPC format w/ embedded Microsoft Office 2007+ document"
		date = "2018-04-29"
		reference = "https://blogs.msdn.microsoft.com/ericwhite/2008/09/29/the-flat-opc-format/"
		hash1 = "060c036ce059b465a05c42420efa07bf"
		hash2 = "2af21d35bb909a0ac081c2399d0939b1"
		hash3 = "72ffa688c228b0b833e69547885650fe"
		filetype = "Office documents"

	strings:
		$xml = "<?xml" // XML declaration
		$WordML = "<?mso-application progid=\"Word.Document\"?>" // XML processing instruction => A Windows OS with Microsoft Office installed will recognize the file as a MS Word document.
		$OPC = "<pkg:package" // Open XML Package
		$xmlns = "http://schemas.microsoft.com/office/2006/xmlPackage" // XML namespace => Microsoft Office 2007 XML Schema Reference
		$binaryData = "<pkg:binaryData>0M8R4KGxGuE" // Binary Part (Microsoft Office 2007+ document encoded in a Base64 string, broken into lines of 76 characters) => D0 CF 11 E0 A1 B1 1A E1 (vbaProject.bin / DOCM)
		$docm = "pkg:name=\"/word/vbaProject.bin\"" // Binary Object

	condition:
	 	$xml at 0 and $WordML and $OPC and $xmlns and $binaryData and $docm
}');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (5, 'APT_OLE_JSRat', '{maldoc,APT}', '{"Date": "2015-06-16", "author": "Rahul Mohandas", "Description": "Targeted attack using Excel/word documents"}', '2020-12-04 20:50:31.443441', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule APT_OLE_JSRat : maldoc APT
{
meta:
	author = "Rahul Mohandas"
	Date = "2015-06-16"
	Description = "Targeted attack using Excel/word documents"
strings:
	$header = {D0 CF 11 E0 A1 B1 1A E1}
	$key1 = "AAAAAAAAAA"
	$key2 = "Base64Str" nocase
	$key3 = "DeleteFile" nocase
	$key4 = "Scripting.FileSystemObject" nocase
condition:
	$header at 0 and (all of ($key*) )
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (6, 'Maldoc_APT10_MenuPass', NULL, '{"date": "2018-09-13", "author": "Colin Cowie", "reference": "https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html", "description": "Detects APT10 MenuPass Phishing"}', '2020-12-04 20:50:31.703845', '/*
   Yara Rule Set
   Author: Colin Cowie
   Date: 2018-09-13
   Identifier: APT 10 (MenuPass)
   Reference: https://www.us-cert.gov/ncas/alerts/TA17-117A
*/

/* Rule Set ----------------------------------------------------------------- */

import "hash"

rule Maldoc_APT10_MenuPass {
   meta:
      description = "Detects APT10 MenuPass Phishing"
      author = "Colin Cowie"
      reference = "https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html"
      date = "2018-09-13"
   strings:
      $s1 = "C:\\ProgramData\\padre1.txt"
      $s2 = "C:\\ProgramData\\padre2.txt"
      $s3 = "C:\\ProgramData\\padre3.txt"
      $s5 = "C:\\ProgramData\\libcurl.txt"
      $s6 = "C:\\ProgramData\\3F2E3AB9"
   condition:
      any of them or
      hash.md5(0, filesize) == "4f83c01e8f7507d23c67ab085bf79e97" or
      hash.md5(0, filesize) == "f188936d2c8423cf064d6b8160769f21" or
      hash.md5(0, filesize) == "cca227f70a64e1e7fcf5bccdc6cc25dd"
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (47, 'Tedroo', '{Spammer}', '{"date": "22/11/2015", "author": "Kevin Falcoz", "description": "Tedroo Spammer"}', '2020-12-04 20:50:40.610291', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Tedroo : Spammer
{
	meta:
		author="Kevin Falcoz"
		date="22/11/2015"
		description="Tedroo Spammer"

	strings:
		$signature1={25 73 25 73 2E 65 78 65}
		$signature2={5F 6C 6F 67 2E 74 78 74}

	condition:
		$signature1 and $signature2
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (7, 'Contains_UserForm_Object', NULL, '{"date": "2016-03-05", "author": "Martin Willing (https://evild3ad.com)", "filetype": "Office documents", "reference": "https://msdn.microsoft.com/en-us/library/office/gg264663.aspx", "description": "Detect UserForm object in MS Office document"}', '2020-12-04 20:50:31.821943', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


rule Contains_UserForm_Object
{
	meta:
		author = "Martin Willing (https://evild3ad.com)"
		description = "Detect UserForm object in MS Office document"
		reference = "https://msdn.microsoft.com/en-us/library/office/gg264663.aspx"
		date = "2016-03-05"
		filetype = "Office documents"

	strings:
		$a = "UserForm1"
		$b = "TextBox1"
		$c = "Microsoft Forms 2.0"

	condition:
	 	all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (8, 'rtf_objdata_urlmoniker_http', NULL, '{"ref": "https://blog.nviso.be/2017/04/12/analysis-of-a-cve-2017-0199-malicious-rtf-document/"}', '2020-12-04 20:50:32.030821', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule rtf_objdata_urlmoniker_http {
meta:
	ref = "https://blog.nviso.be/2017/04/12/analysis-of-a-cve-2017-0199-malicious-rtf-document/"
 strings:
 $header = "{\\rtf1"
 $objdata = "objdata 0105000002000000" nocase
 $urlmoniker = "E0C9EA79F9BACE118C8200AA004BA90B" nocase
 $http = "68007400740070003a002f002f00" nocase
 condition:
 $header at 0 and $objdata and $urlmoniker and $http
 }
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (9, 'Maldoc_Suspicious_OLE_target', NULL, '{"date": "2018-06-13", "author": "Donguk Seo", "filetype": "Office documents", "reference": "https://blog.malwarebytes.com/threat-analysis/2017/10/decoy-microsoft-word-document-delivers-malware-through-rat/", "description": "Detects maldoc With Tartgeting Suspicuios OLE"}', '2020-12-04 20:50:32.17349', 'rule Maldoc_Suspicious_OLE_target {
  meta:
    description =  "Detects maldoc With Tartgeting Suspicuios OLE"
    author = "Donguk Seo"
    reference = "https://blog.malwarebytes.com/threat-analysis/2017/10/decoy-microsoft-word-document-delivers-malware-through-rat/"
    filetype = "Office documents"
    date = "2018-06-13"
  strings:
    $env1 = /oleObject".*Target=.*.http.*.doc"/
    $env2 = /oleObject".*Target=.*.http.*.ppt"/
    $env3 = /oleObject".*Target=.*.http.*.xlx"/
  condition:
    any of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (10, 'Contains_DDE_Protocol', NULL, '{"date": "2017-10-19", "author": "Nick Beede", "filetype": "Office documents", "reference": "https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/", "description": "Detect Dynamic Data Exchange protocol in doc/docx"}', '2020-12-04 20:50:32.408701', 'rule Contains_DDE_Protocol
{
        meta:
                author = "Nick Beede"
                description = "Detect Dynamic Data Exchange protocol in doc/docx"
                reference = "https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/"
                date = "2017-10-19"
                filetype = "Office documents"

        strings:
                $doc = {D0 CF 11 E0 A1 B1 1A E1}
                $s1 = { 13 64 64 65 61 75 74 6F 20 } // !!ddeauto
                $s2 = { 13 64 64 65 20 } // !!dde
                $s3 = "dde" nocase
                $s4 = "ddeauto" nocase

        condition:
                ($doc at 0) and 2 of ($s1, $s2, $s3, $s4)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (11, 'hancitor_dropper', '{vb_win32api}', '{"date": "18AUG2016", "hash1": "03aef51be133425a0e5978ab2529890854ecf1b98a7cf8289c142a62de7acd1a", "hash2": "4b3912077ef47515b2b74bc1f39de44ddd683a3a79f45c93777e49245f0e9848", "hash3": "a78972ac6dee8c7292ae06783cfa1f918bacfe956595d30a0a8d99858ce94b5a", "author": "Jeff White - jwhite@paloaltonetworks @noottrak"}', '2020-12-04 20:50:32.65339', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
rule hancitor_dropper : vb_win32api
{
  meta:
    author = "Jeff White - jwhite@paloaltonetworks @noottrak"
    date   = "18AUG2016"
    hash1  = "03aef51be133425a0e5978ab2529890854ecf1b98a7cf8289c142a62de7acd1a"
    hash2  = "4b3912077ef47515b2b74bc1f39de44ddd683a3a79f45c93777e49245f0e9848"
    hash3  = "a78972ac6dee8c7292ae06783cfa1f918bacfe956595d30a0a8d99858ce94b5a"

  strings:
    $api_01 = { 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 }  // VirtualAlloc
    $api_02 = { 00 52 74 6C 4D 6F 76 65 4D 65 6D 6F 72 79 00 }  // RtlMoveMemory
    $api_04 = { 00 43 61 6C 6C 57 69 6E 64 6F 77 50 72 6F 63 41 00 }  // CallWindowProcAi
    $magic  = { 50 4F 4C 41 }  // POLA

  condition:
    uint32be(0) == 0xD0CF11E0 and all of ($api_*) and $magic
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (12, 'Contains_VBE_File', '{maldoc}', '{"author": "Didier Stevens (https://DidierStevens.com)", "method": "Find string starting with #@~^ and ending with ^#~@", "description": "Detect a VBE file inside a byte sequence"}', '2020-12-04 20:50:32.761526', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
  Version 0.0.1 2016/03/21
  Source code put in public domain by Didier Stevens, no Copyright
  https://DidierStevens.com
  Use at your own risk

  Shortcomings, or todo''s ;-) :

  History:
    2016/03/21: start
*/

rule Contains_VBE_File : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Detect a VBE file inside a byte sequence"
        method = "Find string starting with #@~^ and ending with ^#~@"
    strings:
        $vbe = /#@~\^.+\^#~@/
    condition:
        $vbe
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (13, 'Contains_VBA_macro_code', NULL, '{"date": "2016-01-09", "author": "evild3ad", "filetype": "Office documents", "description": "Detect a MS Office document with embedded VBA macro code"}', '2020-12-04 20:50:32.970526', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/


rule Contains_VBA_macro_code
{
	meta:
		author = "evild3ad"
		description = "Detect a MS Office document with embedded VBA macro code"
		date = "2016-01-09"
		filetype = "Office documents"

	strings:
		$officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
		$zipmagic = "PK"

		$97str1 = "_VBA_PROJECT_CUR" wide
		$97str2 = "VBAProject"
		$97str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F } // Attribute VB_

		$xmlstr1 = "vbaProject.bin"
		$xmlstr2 = "vbaData.xml"

	condition:
		($officemagic at 0 and any of ($97str*)) or ($zipmagic at 0 and any of ($xmlstr*))
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (28, 'CVE_2018_20250', '{AceArchive,UNACEV2_DLL_EXP}', '{"date": "2019-03-17", "author": "xylitol@temari.fr", "reference": "https://research.checkpoint.com/extracting-code-execution-from-winrar/", "description": "Generic rule for hostile ACE archive using CVE-2018-20250"}', '2020-12-04 20:50:36.57987', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule CVE_2018_20250 : AceArchive UNACEV2_DLL_EXP
{
    meta:
        description = "Generic rule for hostile ACE archive using CVE-2018-20250"
        author = "xylitol@temari.fr"
        date = "2019-03-17"
        reference = "https://research.checkpoint.com/extracting-code-execution-from-winrar/"
        // May only the challenge guide you
    strings:
        $string1 = "**ACE**" ascii wide
        $string2 = "*UNREGISTERED VERSION*" ascii wide
        // $hexstring1 = C:\C:\
        $hexstring1 = {?? 3A 5C ?? 3A 5C}
        // $hexstring2 = C:\C:C:..
        $hexstring2 = {?? 3A 5C ?? 3A ?? 3A 2E}
    condition:
         $string1 at 7 and $string2 at 31 and 1 of ($hexstring*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (14, 'malrtf_ole2link', '{exploit}', '{"author": "@h3x2b <tracker _AT h3x.eu>", "description": "Detect weaponized RTF documents with OLE2Link exploit"}', '2020-12-04 20:50:33.086497', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule malrtf_ole2link : exploit
{
	meta:
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect weaponized RTF documents with OLE2Link exploit"

	strings:
		//normal rtf beginning
		$rtf_format_00 = "{\\rtf1"
		//malformed rtf can have for example {\\rtA1
		$rtf_format_01 = "{\\rt"

		//having objdata structure
		$rtf_olelink_01 = "\\objdata" nocase

		//hex encoded OLE2Link
		$rtf_olelink_02 = "4f4c45324c696e6b" nocase

		//hex encoded docfile magic - doc file albilae
		$rtf_olelink_03 = "d0cf11e0a1b11ae1" nocase

		//hex encoded "http://"
		$rtf_payload_01 = "68007400740070003a002f002f00" nocase

		//hex encoded "https://"
		$rtf_payload_02 = "680074007400700073003a002f002f00" nocase

		//hex encoded "ftp://"
		$rtf_payload_03 = "6600740070003a002f002f00" nocase


	condition:
		//new_file and
		any of ($rtf_format_*)
		and all of ($rtf_olelink_*)
		and any of ($rtf_payload_*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (15, 'Maldoc_CVE_2017_11882', '{Exploit}', '{"date": "2017-10-20", "author": "Marc Salinas (@Bondey_m)", "reference": "c63ccc5c08c3863d7eb330b69f96c1bcf1e031201721754132a4c4d0baff36f8", "description": "Detects maldoc With exploit for CVE_2017_11882"}', '2020-12-04 20:50:33.310358', 'rule Maldoc_CVE_2017_11882 : Exploit {
    meta:
        description = "Detects maldoc With exploit for CVE_2017_11882"
        author = "Marc Salinas (@Bondey_m)"
        reference = "c63ccc5c08c3863d7eb330b69f96c1bcf1e031201721754132a4c4d0baff36f8"
        date = "2017-10-20"
    strings:
        $s0 = "Equation"
        $s1 = "1c000000020"
        $h0 = {1C 00 00 00 02 00}

    condition:
        $s0 and ($h0 or $s1)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (16, 'maldoc_OLE_file_magic_number', '{maldoc}', '{"author": "Didier Stevens (https://DidierStevens.com)"}', '2020-12-04 20:50:33.877197', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule maldoc_OLE_file_magic_number : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {D0 CF 11 E0}
    condition:
        $a
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (17, 'contains_base64', '{Base64}', '{"notes": "https://github.com/Yara-Rules/rules/issues/153", "author": "Jaume Martin", "version": "0.2", "description": "This rule finds for base64 strings"}', '2020-12-04 20:50:34.006188', '
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule contains_base64 : Base64
{
    meta:
        author = "Jaume Martin"
        description = "This rule finds for base64 strings"
        version = "0.2"
        notes = "https://github.com/Yara-Rules/rules/issues/153"
    strings:
        $a = /([A-Za-z0-9+\/]{4}){3,}([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/
    condition:
        $a
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (18, 'url', NULL, '{"author": "Antonio S. <asanchez@plutec.net>"}', '2020-12-04 20:50:34.125053', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule url {
    meta:
        author = "Antonio S. <asanchez@plutec.net>"
    strings:
        $url_regex = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/ wide ascii
    condition:
        $url_regex
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (19, 'IP', NULL, '{"author": "Antonio S. <asanchez@plutec.net>"}', '2020-12-04 20:50:34.334961', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule IP {
    meta:
        author = "Antonio S. <asanchez@plutec.net>"
    strings:
        $ipv4 = /([0-9]{1,3}\.){3}[0-9]{1,3}/ wide ascii
        $ipv6 = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/ wide ascii
    condition:
        any of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (20, 'domain', NULL, '{"author": "Antonio S. <asanchez@plutec.net>"}', '2020-12-04 20:50:34.467358', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule domain {
    meta:
        author = "Antonio S. <asanchez@plutec.net>"
    strings:
        $domain_regex = /([\w\.-]+)/ wide ascii
    condition:
        $domain_regex
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (21, 'Email_Generic_Phishing', '{email}', '{"Author": "Tyler <@InfoSecTyler>", "Description": "Generic rule to identify phishing emails"}', '2020-12-04 20:50:34.802887', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html)
    and open to any user or organization, as long as you use it under this license.

*/

rule Email_Generic_Phishing : email
{
  meta:
		Author = "Tyler <@InfoSecTyler>"
		Description ="Generic rule to identify phishing emails"

  strings:
    $eml_1="From:"
    $eml_2="To:"
    $eml_3="Subject:"

    $greeting_1="Hello sir/madam" nocase
    $greeting_2="Attention" nocase
    $greeting_3="Dear user" nocase
    $greeting_4="Account holder" nocase

    $url_1="Click" nocase
    $url_2="Confirm" nocase
    $url_3="Verify" nocase
    $url_4="Here" nocase
    $url_5="Now" nocase
    $url_6="Change password" nocase

    $lie_1="Unauthorized" nocase
    $lie_2="Expired" nocase
    $lie_3="Deleted" nocase
    $lie_4="Suspended" nocase
    $lie_5="Revoked" nocase
    $lie_6="Unable" nocase

  condition:
    all of ($eml*) and
    any of ($greeting*) and
    any of ($url*) and
    any of ($lie*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (29, 'CVE_2012_0158_KeyBoy', NULL, '{"file": "8307e444cad98b1b59568ad2eba5f201", "author": "Etienne Maynier <etienne@citizenlab.ca>", "description": "CVE-2012-0158 variant"}', '2020-12-04 20:50:36.697559', '/*
*
* Signature for the CVE-2012-0158 used in KeyBoy operation
* Ref https://citizenlab.org/2016/11/parliament-keyboy/
*
*/
rule CVE_2012_0158_KeyBoy {
  meta:
      author = "Etienne Maynier <etienne@citizenlab.ca>"
      description = "CVE-2012-0158 variant"
      file = "8307e444cad98b1b59568ad2eba5f201"

  strings:
      $a = "d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff09000600000000000000000000000100000001" nocase // OLE header
      $b = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" nocase // junk data
      $c = /5(\{\\b0\}|)[ ]*2006F00(\{\\b0\}|)[ ]*6F007(\{\\b0\}|)[ ]*400200045(\{\\b0\}|)[ ]*006(\{\\b0\}|)[ ]*E007(\{\\b0\}|)[ ]*400720079/ nocase
      $d = "MSComctlLib.ListViewCtrl.2"
      $e = "ac38c874503c307405347aaaebf2ac2c31ebf6e8e3" nocase //decoding shellcode


  condition:
      all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (22, 'Email_quota_limit_warning', '{mail}', '{"Author": "Tyler Linne <@InfoSecTyler>", "Description": "Rule to prevent against known email quota limit phishing campaign"}', '2020-12-04 20:50:35.131404', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or
    organization, as long as you use it under this license.
*/

rule Email_quota_limit_warning : mail
{
  meta:
		Author = "Tyler Linne <@InfoSecTyler>"
		Description ="Rule to prevent against known email quota limit phishing campaign"

  strings:
    $eml_01 = "From:" //Added eml context
    $eml_02 = "To:"
    $eml_03 = "Subject:"
    $subject1={ 44 65 61 72 20 [0-11] 20 41 63 63 6f 75 6e 74 20 55 73 65 72 73 } // Range allows for different company names to be accepted
    $hello1={ 44 65 61 72 20 [0-11] 20 41 63 63 6f 75 6e 74 20 55 73 65 72 73 }
    $body1="You have exceded" nocase
    $body2={65 2d 6d 61 69 6c 20 61 63 63 6f 75 6e 74 20 6c 69 6d 69 74 20 71 75 6f 74 61 20 6f 66 } //Range allows for different quota "upgrade" sizes
    $body3="requested to expand it within 24 hours" nocase
    $body4="e-mail account will be disable from our database" nocase
    $body5="simply click with the complete information" nocase
    $body6="requested to expand your account quota" nocase
    $body7={54 68 61 6e 6b 20 79 6f 75 20 66 6f 72 20 75 73 69 6e 67 20 [0-11] 20 57 65 62 6d 61 69 6c } // Range allows for different company names to be accepted

  condition:
    all of ($eml_*) and
    1 of ($subject*) and
    1 of ($hello*) and
    4 of ($body*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (23, 'extortion_email', NULL, '{"data": "12th May 2020", "author": "milann shrestha <Twitter - @x0verhaul>", "description": "Detects the possible extortion scam on the basis of subjects and keywords"}', '2020-12-04 20:50:35.241879', 'rule extortion_email
{
  meta:
    author = "milann shrestha <Twitter - @x0verhaul>"
		description = "Detects the possible extortion scam on the basis of subjects and keywords"
		data = "12th May 2020"

	strings:
	  $eml1="From:"
    $eml2="To:"
    $eml3="Subject:"

		// Common Subjects scammer keep for luring the targets
    $sub1 = "Hackers know password from your account."
    $sub2 = "Security Alert. Your accounts were hacked by a criminal group."
    $sub3 = "Your account was under attack! Change your credentials!"
    $sub4 = "The decision to suspend your account. Waiting for payment"
    $sub5 = "Fraudsters know your old passwords. Access data must be changed."
    $sub6 = "Your account has been hacked! You need to unlock it."
    $sub7 = "Be sure to read this message! Your personal data is threatened!"
    $sub8 = "Password must be changed now."

		// Keywords used for extortion
    $key1 = "BTC" nocase
    $key2 = "Wallet" nocase
    $key3 = "Bitcoin" nocase
    $key4 = "hours" nocase
    $key5 = "payment" nocase
    $key6 = "malware" nocase
    $key = "bitcoin address" nocase
    $key7 = "access" nocase
    $key8 = "virus" nocase

	condition:
    all of ($eml*) and
    any of ($sub*) and
    any of ($key*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (24, 'Fake_it_maintenance_bulletin', '{mail}', '{"Author": "Tyler Linne <@InfoSecTyler>", "Description": "Rule to prevent against known phishing campaign targeting American companies using Microsoft Exchange"}', '2020-12-04 20:50:35.469481', 'rule Fake_it_maintenance_bulletin : mail
{
  meta:
		Author = "Tyler Linne <@InfoSecTyler>"
		Description ="Rule to prevent against known phishing campaign targeting American companies using Microsoft Exchange"
  strings:
    $eml_1="From:"
    $eml_2="To:"
    $eml_3="Subject:"
    $subject1={49 54 20 53 45 52 56 49 43 45 20 4d 61 69 6e 74 65 6e 61 6e 63 65 20 42 75 6c 6c 65 74 69 6e} //Range is for varying date of "notification"
    $subject2={44 45 53 43 52 49 50 54 49 4f 4e 3a 20 53 65 72 76 65 72 20 55 70 67 72 61 64 65 20 4d 61 69 6e 74 65 6e 61 6e 63 65} //Range is for server name varriation
    $body1="Message prompted from IT Helpdesk Support" nocase
    $body2="We are currently undergoing server maintenance upgrade" nocase
    $body3="Upgrade is to improve our security and new mail experience" nocase
    $body4="As an active Outlook user, you are kindly instructed  to upgrade your mail account by Logging-in the below link" nocase
    $body5="Sign in to Access Upgrade" nocase
    $body6="Our goal is to provide excellent customer service" nocase
    $body7="Thanks,/n OWA - IT Helpdesk Service" nocase

  condition:
    all of ($eml_*)and
    1 of ($subject*) and
    4 of ($body*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (25, 'CVE_2013_0422', NULL, '{"cve": "CVE-2013-0422", "ref": "http://pastebin.com/JVedyrCe", "date": "12-Jan-2013", "hide": false, "author": "adnan.shukor@gmail.com", "impact": 4, "version": "1", "description": "Java Applet JMX Remote Code Execution"}', '2020-12-04 20:50:36.00711', 'rule CVE_2013_0422
{
        meta:
                description = "Java Applet JMX Remote Code Execution"
                cve = "CVE-2013-0422"
                ref = "http://pastebin.com/JVedyrCe"
                author = "adnan.shukor@gmail.com"
                date = "12-Jan-2013"
                version = "1"
                impact = 4
                hide = false
        strings:
                $0422_1 = "com/sun/jmx/mbeanserver/JmxMBeanServer" fullword
                $0422_2 = "com/sun/jmx/mbeanserver/JmxMBeanServerBuilder" fullword
                $0422_3 = "com/sun/jmx/mbeanserver/MBeanInstantiator" fullword
                $0422_4 = "findClass" fullword
                $0422_5 = "publicLookup" fullword
                $class = /sun\.org\.mozilla\.javascript\.internal\.(Context|GeneratedClassLoader)/ fullword
        condition:
                (all of ($0422_*)) or (all of them)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (26, 'MSIETabularActivex', NULL, '{"ref": "CVE-2010-0805", "hide": true, "author": "@d3t0n4t0r", "impact": 7}', '2020-12-04 20:50:36.247349', 'rule MSIETabularActivex
{
        meta:
                ref = "CVE-2010-0805"
                impact = 7
                hide = true
                author = "@d3t0n4t0r"
        strings:
                $cve20100805_1 = "333C7BC4-460F-11D0-BC04-0080C7055A83" nocase fullword
                $cve20100805_2 = "DataURL" nocase fullword
                $cve20100805_3 = "true"
        condition:
                ($cve20100805_1 and $cve20100805_3) or (all of them)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (27, 'Flash_CVE_2015_5119_APT3', '{Exploit}', '{"date": "2015-08-01", "score": 70, "author": "Florian Roth", "description": "Exploit Sample CVE-2015-5119"}', '2020-12-04 20:50:36.467047', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Flash_CVE_2015_5119_APT3 : Exploit {
    meta:
        description = "Exploit Sample CVE-2015-5119"
        author = "Florian Roth"
        score = 70
        date = "2015-08-01"
    strings:
        $s0 = "HT_exploit" fullword ascii
        $s1 = "HT_Exploit" fullword ascii
        $s2 = "flash_exploit_" ascii
        $s3 = "exp1_fla/MainTimeline" ascii fullword
        $s4 = "exp2_fla/MainTimeline" ascii fullword
        $s5 = "_shellcode_32" fullword ascii
        $s6 = "todo: unknown 32-bit target" fullword ascii
    condition:
        uint16(0) == 0x5746 and 1 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (37, 'LinuxBew', '{MALW}', '{"MD5": "27d857e12b9be5d43f935b8cc86eaabf", "date": "2017-07-10", "SHA256": "80c4d1a1ef433ac44c4fe72e6ca42395261fbca36eff243b07438263a1b1cf06", "author": "Joan Soriano / @w0lfvan", "version": "1.0", "description": "Linux.Bew Backdoor"}', '2020-12-04 20:50:38.160824', 'rule LinuxBew: MALW
{
	meta:
		description = "Linux.Bew Backdoor"
		author = "Joan Soriano / @w0lfvan"
		date = "2017-07-10"
		version = "1.0"
		MD5 = "27d857e12b9be5d43f935b8cc86eaabf"
		SHA256 = "80c4d1a1ef433ac44c4fe72e6ca42395261fbca36eff243b07438263a1b1cf06"
	strings:
		$a = "src/secp256k1.c"
		$b = "hfir.u230.org"
		$c = "tempfile-x11session"
	condition:
		all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (30, 'Linux_DirtyCow_Exploit', NULL, '{"date": "2016-10-21", "author": "Florian Roth", "reference": "http://dirtycow.ninja/", "description": "Detects Linux Dirty Cow Exploit - CVE-2012-0056 and CVE-2016-5195"}', '2020-12-04 20:50:36.813465', '
rule Linux_DirtyCow_Exploit {
   meta:
      description = "Detects Linux Dirty Cow Exploit - CVE-2012-0056 and CVE-2016-5195"
      author = "Florian Roth"
      reference = "http://dirtycow.ninja/"
      date = "2016-10-21"
   strings:
      $a1 = { 48 89 D6 41 B9 00 00 00 00 41 89 C0 B9 02 00 00 00 BA 01 00 00 00 BF 00 00 00 00 }

      $b1 = { E8 ?? FC FF FF 48 8B 45 E8 BE 00 00 00 00 48 89 C7 E8 ?? FC FF FF 48 8B 45 F0 BE 00 00 00 00 48 89 }
      $b2 = { E8 ?? FC FF FF B8 00 00 00 00 }

      $source1 = "madvise(map,100,MADV_DONTNEED);"
      $source2 = "=open(\"/proc/self/mem\",O_RDWR);"
      $source3 = ",map,SEEK_SET);"

      $source_printf1 = "mmap %x"
      $source_printf2 = "procselfmem %d"
      $source_printf3 = "madvise %d"
      $source_printf4 = "[-] failed to patch payload"
      $source_printf5 = "[-] failed to win race condition..."
      $source_printf6 = "[*] waiting for reverse connect shell..."

      $s1 = "/proc/self/mem"
      $s2 = "/proc/%d/mem"
      $s3 = "/proc/self/map"
      $s4 = "/proc/%d/map"

      $p1 = "pthread_create" fullword ascii
      $p2 = "pthread_join" fullword ascii
   condition:
      ( uint16(0) == 0x457f and $a1 ) or
      all of ($b*) or
      3 of ($source*) or
      ( uint16(0) == 0x457f and 1 of ($s*) and all of ($p*) and filesize < 20KB )
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (31, 'crime_ole_loadswf_cve_2018_4878', NULL, '{"actor": "Purported North Korean actors", "author": "Vitali Kremez, Flashpoint", "report": "https://www.flashpoint-intel.com/blog/targeted-attacks-south-korean-entities/", "version": "1.1", "reference": "hxxps://www[.]krcert[.]or[.kr/data/secNoticeView.do?bulletin_writing_sequence=26998", "vuln_type": "Remote Code Execution", "description": "Detects CVE-2018-4878", "mitigation0": "Implement Protected View for Office documents", "mitigation1": "Disable Adobe Flash", "vuln_impact": "Use-after-free", "weaponization": "Embedded in Microsoft Office first payloads", "affected_versions": "Adobe Flash 28.0.0.137 and earlier versions"}', '2020-12-04 20:50:37.036686', 'rule crime_ole_loadswf_cve_2018_4878
{
meta:
description = "Detects CVE-2018-4878"
vuln_type = "Remote Code Execution"
vuln_impact = "Use-after-free"
affected_versions = "Adobe Flash 28.0.0.137 and earlier versions"
mitigation0 = "Implement Protected View for Office documents"
mitigation1 = "Disable Adobe Flash"
weaponization = "Embedded in Microsoft Office first payloads"
actor = "Purported North Korean actors"
reference = "hxxps://www[.]krcert[.]or[.kr/data/secNoticeView.do?bulletin_writing_sequence=26998"
report = "https://www.flashpoint-intel.com/blog/targeted-attacks-south-korean-entities/"
author = "Vitali Kremez, Flashpoint"
version = "1.1"

strings:
// EMBEDDED FLASH OBJECT BIN HEADER
$header = "rdf:RDF" wide ascii

// OBJECT APPLICATION TYPE TITLE
$title = "Adobe Flex" wide ascii

// PDB PATH
$pdb = "F:\\work\\flash\\obfuscation\\loadswf\\src" wide ascii

// LOADER STRINGS
$s0 = "URLRequest" wide ascii
$s1 = "URLLoader" wide ascii
$s2 = "loadswf" wide ascii
$s3 = "myUrlReqest" wide ascii

condition:
all of ($header*) and all of ($title*) and 3 of ($s*) or all of ($pdb*) and all of ($header*) and 1 of ($s*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (32, 'CVE_2015_1701_Taihou', NULL, '{"date": "2015-05-13", "hash1": "90d17ebd75ce7ff4f15b2df951572653efe2ea17", "hash2": "acf181d6c2c43356e92d4ee7592700fa01e30ffb", "hash3": "b8aabe12502f7d55ae332905acee80a10e3bc399", "hash4": "d9989a46d590ebc792f14aa6fec30560dfe931b1", "hash5": "63d1d33e7418daf200dc4660fc9a59492ddd50d9", "score": 70, "author": "Florian Roth", "reference": "http://goo.gl/W4nU0q", "description": "CVE-2015-1701 compiled exploit code"}', '2020-12-04 20:50:37.143603', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule CVE_2015_1701_Taihou {
	meta:
		description = "CVE-2015-1701 compiled exploit code"
		author = "Florian Roth"
		reference = "http://goo.gl/W4nU0q"
		date = "2015-05-13"
		hash1 = "90d17ebd75ce7ff4f15b2df951572653efe2ea17"
		hash2 = "acf181d6c2c43356e92d4ee7592700fa01e30ffb"
		hash3 = "b8aabe12502f7d55ae332905acee80a10e3bc399"
		hash4 = "d9989a46d590ebc792f14aa6fec30560dfe931b1"
		hash5 = "63d1d33e7418daf200dc4660fc9a59492ddd50d9"
		score = 70
	strings:
		$s3 = "VirtualProtect" fullword
		$s4 = "RegisterClass"
		$s5 = "LoadIcon"
		$s6 = "PsLookupProcessByProcessId" fullword ascii
		$s7 = "LoadLibraryExA" fullword ascii
		$s8 = "gSharedInfo" fullword

		$w1 = "user32.dll" wide
		$w2 = "ntdll" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 160KB and all of ($s*) and 1 of ($w*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (33, 'JavaDeploymentToolkit', NULL, '{"ref": "CVE-2010-0887", "author": "@d3t0n4t0r", "impact": 7}', '2020-12-04 20:50:37.277439', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule JavaDeploymentToolkit
{
   meta:
      ref = "CVE-2010-0887"
      impact = 7
      author = "@d3t0n4t0r"
   strings:
      $cve20100887_1 = "CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA" nocase fullword
      $cve20100887_2 = "document.createElement(\"OBJECT\")" nocase fullword
      $cve20100887_3 = "application/npruntime-scriptable-plugin;deploymenttoolkit" nocase fullword
      $cve20100887_4 = "application/java-deployment-toolkit" nocase fullword
      $cve20100887_5 = "document.body.appendChild(" nocase fullword
      $cve20100887_6 = "launch("
      $cve20100887_7 = "-J-jar -J" nocase fullword
   condition:
      3 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (34, 'FlashNewfunction', '{decodedPDF}', '{"ref": "http://blog.xanda.org/tag/jsunpack/", "hide": true, "impact": 5}', '2020-12-04 20:50:37.41484', 'rule FlashNewfunction: decodedPDF
{
   meta:
      ref = "CVE-2010-1297"
      hide = true
      impact = 5
      ref = "http://blog.xanda.org/tag/jsunpack/"
   strings:
      $unescape = "unescape" fullword nocase
      $shellcode = /%u[A-Fa-f0-9]{4}/
      $shellcode5 = /(%u[A-Fa-f0-9]{4}){5}/
      $cve20101297 = /\/Subtype ?\/Flash/
   condition:
      ($unescape and $shellcode and $cve20101297) or ($shellcode5 and $cve20101297)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (35, 'cve_2013_0074', NULL, '{"date": "2015-07-23", "author": "Kaspersky Lab", "version": "1.0", "filetype": "Win32 EXE"}', '2020-12-04 20:50:37.551094', 'rule cve_2013_0074
{
meta:
	author = "Kaspersky Lab"
	filetype = "Win32 EXE"
	date = "2015-07-23"
	version = "1.0"

strings:
	$b2="Can''t find Payload() address" ascii wide
	$b3="/SilverApp1;component/App.xaml" ascii wide
	$b4="Can''t allocate ums after buf[]" ascii wide
	$b5="------------ START ------------"

condition:
	( (2 of ($b*)) )
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (36, 'Cerberus', '{RAT,memory}', '{"date": "2013-01-12", "author": "Jean-Philippe Teissier / @Jipe_", "version": "1.0", "filetype": "memory", "description": "Cerberus"}', '2020-12-04 20:50:38.048526', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Cerberus : RAT memory
{
	meta:
		description = "Cerberus"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-01-12"
		filetype = "memory"
		version = "1.0"

	strings:
		$checkin = "Ypmw1Syv023QZD"
		$clientpong = "wZ2pla"
		$serverping = "wBmpf3Pb7RJe"
		$generic = "cerberus" nocase

	condition:
		any of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (38, 'PittyTiger', NULL, '{"author": " (@chort0)", "description": "Detect PittyTiger Trojan via common strings"}', '2020-12-04 20:50:38.274863', 'rule PittyTiger {
  meta:
    author = " (@chort0)"
    description = "Detect PittyTiger Trojan via common strings"
    strings:
      $ptUserAgent = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.; SV1)" // missing minor digit
      $ptFC001 = "FC001" fullword
      $ptPittyTiger = "PittyTiger" fullword
      $trjHTMLerr = "trj:HTML Err." nocase fullword
      $trjworkFunc = "trj:workFunc start." nocase fullword
      $trjcmdtout = "trj:cmd time out." nocase fullword
      $trjThrtout = "trj:Thread time out." nocase fullword
      $trjCrPTdone = "trj:Create PT done." nocase fullword
      $trjCrPTerr = "trj:Create PT error: mutex already exists." nocase fullword
      $oddPippeFailed = "Create Pippe Failed!" fullword // extra ''p''
      $oddXferingFile = "Transfering File" fullword // missing ''r''
      $oddParasError = "put Paras Error:" fullword // abbreviated ''parameters''?
      $oddCmdTOutkilled = "Cmd Time Out..Cmd has been killed." fullword
condition:
  (any of ($pt*)) and (any of ($trj*)) and (any of ($odd*))
  }
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (39, 'eicar', NULL, '{"hash1": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "author": "Marc Rivero | @seifreed", "description": "Rule to detect Eicar pattern"}', '2020-12-04 20:50:38.815943', 'rule eicar
{
	meta:
		description = "Rule to detect Eicar pattern"
		author = "Marc Rivero | @seifreed"
		hash1 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

	strings:
		$s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" fullword ascii

	condition:
		all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (40, 'crime_ransomware_windows_GPGQwerty', '{crime_ransomware_windows_GPGQwerty}', '{"author": "McAfee Labs", "reference": "https://securingtomorrow.mcafee.com/mcafee-labs/ransomware-takes-open-source-path-encrypts-gnu-privacy-guard/", "description": "Detect GPGQwerty ransomware"}', '2020-12-04 20:50:38.93815', 'rule crime_ransomware_windows_GPGQwerty: crime_ransomware_windows_GPGQwerty

{

meta:

author = "McAfee Labs"

description = "Detect GPGQwerty ransomware"

reference = "https://securingtomorrow.mcafee.com/mcafee-labs/ransomware-takes-open-source-path-encrypts-gnu-privacy-guard/"

strings:

$a = "gpg.exe –recipient qwerty  -o"

$b = "%s%s.%d.qwerty"

$c = "del /Q /F /S %s$recycle.bin"

$d = "cryz1@protonmail.com"

condition:

all of them

}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (41, 'rovnix_downloader', '{downloader}', '{"author": "Intel Security", "reference": "https://blogs.mcafee.com/mcafee-labs/rovnix-downloader-sinkhole-time-checks/", "description": "Rovnix downloader with sinkhole checks"}', '2020-12-04 20:50:39.263057', 'rule rovnix_downloader : downloader
{
	meta:
		author="Intel Security"
		description="Rovnix downloader with sinkhole checks"
		reference = "https://blogs.mcafee.com/mcafee-labs/rovnix-downloader-sinkhole-time-checks/"
	strings:
			$sink1= "control"
			$sink2 = "sink"
			$sink3 = "hole"
			$sink4= "dynadot"
			$sink5= "block"
			$sink6= "malw"
			$sink7= "anti"
			$sink8= "googl"
			$sink9= "hack"
			$sink10= "trojan"
			$sink11= "abuse"
			$sink12= "virus"
			$sink13= "black"
			$sink14= "spam"
			$boot= "BOOTKIT_DLL.dll"
			$mz = { 4D 5A }
	condition:
		$mz in (0..2) and all of ($sink*) and $boot
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (42, 'Meterpreter_Reverse_Tcp', NULL, '{"author": "chort (@chort0)", "description": "Meterpreter reverse TCP backdoor in memory. Tested on Win7x64."}', '2020-12-04 20:50:39.726284', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule Meterpreter_Reverse_Tcp {
  meta: // This is the standard backdoor/RAT from Metasploit, could be used by any actor
    author = "chort (@chort0)"
    description = "Meterpreter reverse TCP backdoor in memory. Tested on Win7x64."
  strings:
    $a = { 4d 45 54 45 52 50 52 45 54 45 52 5f 54 52 41 4e 53 50 4f 52 54 5f 53 53 4c [32-48] 68 74 74 70 73 3a 2f 2f 58 58 58 58 58 58 } // METERPRETER_TRANSPORT_SSL … https://XXXXXX
    $b = { 4d 45 54 45 52 50 52 45 54 45 52 5f 55 41 } // METERPRETER_UA
    $c = { 47 45 54 20 2f 31 32 33 34 35 36 37 38 39 20 48 54 54 50 2f 31 2e 30 } // GET /123456789 HTTP/1.0
    $d = { 6d 65 74 73 72 76 2e 64 6c 6c [2-4] 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } // metsrv.dll … ReflectiveLoader

  condition:
    $a or (any of ($b, $d) and $c)
  }


');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (43, 'KelihosHlux', NULL, '{"date": "22/02/2014", "author": "@malpush", "maltype": "KelihosHlux", "description": "http://malwared.ru"}', '2020-12-04 20:50:39.847149', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule KelihosHlux
{
  meta:
	author = "@malpush"
	maltype = "KelihosHlux"
	description = "http://malwared.ru"
	date = "22/02/2014"
  strings:
    $KelihosHlux_HexString = { 73 20 7D 8B FE 95 E4 12 4F 3F 99 3F 6E C8 28 26 C2 41 D9 8F C1 6A 72 A6 CE 36 0F 73 DD 2A 72 B0 CC D1 07 8B 2B 98 73 0E 7E 8C 07 DC 6C 71 63 F4 23 27 DD 17 56 AE AB 1E 30 52 E7 54 51 F7 20 ED C7 2D 4B 72 E0 77 8E B4 D2 A8 0D 8D 6A 64 F9 B7 7B 08 70 8D EF F3 9A 77 F6 0D 88 3A 8F BB C8 89 F5 F8 39 36 BA 0E CB 38 40 BF 39 73 F4 01 DC C1 17 BF C1 76 F6 84 8F BD 87 76 BC 7F 85 41 81 BD C6 3F BC 39 BD C0 89 47 3E 92 BD 80 60 9D 89 15 6A C6 B9 89 37 C4 FF 00 3D 45 38 09 CD 29 00 90 BB B6 38 FD 28 9C 01 39 0E F9 30 A9 66 6B 19 C9 F8 4C 3E B1 C7 CB 1B C9 3A 87 3E 8E 74 E7 71 D1 }

  condition:
    $KelihosHlux_HexString
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (44, 'jeff_dev_ransomware', NULL, '{"author": "Marc Rivero | @seifreed", "reference": "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/", "description": "Rule to detect Jeff DEV Ransomware"}', '2020-12-04 20:50:39.981097', 'rule jeff_dev_ransomware {

   meta:

      description = "Rule to detect Jeff DEV Ransomware"
      author = "Marc Rivero | @seifreed"
      reference = "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/"

   strings:

      $s1 = "C:\\Users\\Umut\\Desktop\\takemeon" fullword wide
      $s2 = "C:\\Users\\Umut\\Desktop\\" fullword ascii
      $s3 = "PRESS HERE TO STOP THIS CREEPY SOUND AND VIEW WHAT HAPPENED TO YOUR COMPUTER" fullword wide
      $s4 = "WHAT YOU DO TO MY COMPUTER??!??!!!" fullword wide

   condition:

      ( uint16(0) == 0x5a4d and filesize < 5000KB ) and all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (45, 'leverage_a', NULL, '{"date": "2013/09", "author": "earada@alienvault.com", "version": "1.0", "description": "OSX/Leverage.A"}', '2020-12-04 20:50:40.234213', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule leverage_a
{
	meta:
		author = "earada@alienvault.com"
		version = "1.0"
		description = "OSX/Leverage.A"
		date = "2013/09"
	strings:
		$a1 = "ioreg -l | grep \"IOPlatformSerialNumber\" | awk -F"
		$a2 = "+:Users:Shared:UserEvent.app:Contents:MacOS:"
		$a3 = "rm ''/Users/Shared/UserEvent.app/Contents/Resources/UserEvent.icns''"
		$script1 = "osascript -e ''tell application \"System Events\" to get the hidden of every login item''"
		$script2 = "osascript -e ''tell application \"System Events\" to get the name of every login item''"
		$script3 = "osascript -e ''tell application \"System Events\" to get the path of every login item''"
		$properties = "serverVisible \x00"
	condition:
		all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (46, 'Kwampirs', NULL, '{"family": "Kwampirs", "copyright": "Symantec", "reference": "https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia", "description": "Kwampirs dropper and main payload components"}', '2020-12-04 20:50:40.347294', 'rule Kwampirs
{
 meta:
 copyright = "Symantec"
 reference = "https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia"
 family = "Kwampirs"
 description = "Kwampirs dropper and main payload components"
 strings:
$pubkey =
 {
 06 02 00 00 00 A4 00 00 52 53 41 31 00 08 00 00
 01 00 01 00 CD 74 15 BC 47 7E 0A 5E E4 35 22 A5
 97 0C 65 BE E0 33 22 F2 94 9D F5 40 97 3C 53 F9
 E4 7E DD 67 CF 5F 0A 5E F4 AD C9 CF 27 D3 E6 31
 48 B8 00 32 1D BE 87 10 89 DA 8B 2F 21 B4 5D 0A
 CD 43 D7 B4 75 C9 19 FE CC 88 4A 7B E9 1D 8C 11
 56 A6 A7 21 D8 C6 82 94 C1 66 11 08 E6 99 2C 33
 02 E2 3A 50 EA 58 D2 A7 36 EE 5A D6 8F 5D 5D D2
 9E 04 24 4A CE 4C B6 91 C0 7A C9 5C E7 5F 51 28
 4C 72 E1 60 AB 76 73 30 66 18 BE EC F3 99 5E 4B
 4F 59 F5 56 AD 65 75 2B 8F 14 0C 0D 27 97 12 71
 6B 49 08 84 61 1D 03 BA A5 42 92 F9 13 33 57 D9
 59 B3 E4 05 F9 12 23 08 B3 50 9A DA 6E 79 02 36
 EE CE 6D F3 7F 8B C9 BE 6A 7E BE 8F 85 B8 AA 82
 C6 1E 14 C6 1A 28 29 59 C2 22 71 44 52 05 E5 E6
 FE 58 80 6E D4 95 2D 57 CB 99 34 61 E9 E9 B3 3D
 90 DC 6C 26 5D 70 B4 78 F9 5E C9 7D 59 10 61 DF
 F7 E4 0C B3
 }

 $network_xor_key =
 {
 B7 E9 F9 2D F8 3E 18 57 B9 18 2B 1F 5F D9 A5 38
 C8 E7 67 E9 C6 62 9C 50 4E 8D 00 A6 59 F8 72 E0
 91 42 FF 18 A6 D1 81 F2 2B C8 29 EB B9 87 6F 58
 C2 C9 8E 75 3F 71 ED 07 D0 AC CE 28 A1 E7 B5 68
 CD CF F1 D8 2B 26 5C 31 1E BC 52 7C 23 6C 3E 6B
 8A 24 61 0A 17 6C E2 BB 1D 11 3B 79 E0 29 75 02
 D9 25 31 5F 95 E7 28 28 26 2B 31 EC 4D B3 49 D9
 62 F0 3E D4 89 E4 CC F8 02 41 CC 25 15 6E 63 1B
 10 3B 60 32 1C 0D 5B FA 52 DA 39 DF D1 42 1E 3E
 BD BC 17 A5 96 D9 43 73 3C 09 7F D2 C6 D4 29 83
 3E 44 44 6C 97 85 9E 7B F0 EE 32 C3 11 41 A3 6B
 A9 27 F4 A3 FB 2B 27 2B B6 A6 AF 6B 39 63 2D 91
 75 AE 83 2E 1E F8 5F B5 65 ED B3 40 EA 2A 36 2C
 A6 CF 8E 4A 4A 3E 10 6C 9D 28 49 66 35 83 30 E7
 45 0E 05 ED 69 8D CF C5 40 50 B1 AA 13 74 33 0F
 DF 41 82 3B 1A 79 DC 3B 9D C3 BD EA B1 3E 04 33
 }

$decrypt_string =
 {
 85 DB 75 09 85 F6 74 05 89 1E B0 01 C3 85 FF 74
 4F F6 C3 01 75 4A 85 F6 74 46 8B C3 D1 E8 33 C9
 40 BA 02 00 00 00 F7 E2 0F 90 C1 F7 D9 0B C8 51
 E8 12 28 00 00 89 06 8B C8 83 C4 04 33 C0 85 DB
 74 16 8B D0 83 E2 0F 8A 92 1C 33 02 10 32 14 38
 40 88 11 41 3B C3 72 EA 66 C7 01 00 00 B0 01 C3
 32 C0 C3
 }

 $init_strings =
 {
 55 8B EC 83 EC 10 33 C9 B8 0D 00 00 00 BA 02 00
 00 00 F7 E2 0F 90 C1 53 56 57 F7 D9 0B C8 51 E8
 B3 27 00 00 BF 05 00 00 00 8D 77 FE BB 4A 35 02
 10 2B DE 89 5D F4 BA 48 35 02 10 4A BB 4C 35 02
 10 83 C4 04 2B DF A3 C8 FC 03 10 C7 45 FC 00 00
 00 00 8D 4F FC 89 55 F8 89 5D F0 EB 06
 }

 condition:
 2 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (48, 'Odinaff_swift', '{malware,odinaff,swift,raw}', '{"date": "2016/10/27", "author": "@j0sm1", "filetype": "binary", "reference": "https://www.symantec.com/security_response/writeup.jsp?docid=2016-083006-4847-99", "description": "Odinaff malware"}', '2020-12-04 20:50:41.24536', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/

import "pe"

rule Odinaff_swift : malware odinaff swift raw{
        meta:
                author = "@j0sm1"
                date = "2016/10/27"
                description = "Odinaff malware"
                reference = "https://www.symantec.com/security_response/writeup.jsp?docid=2016-083006-4847-99"
                filetype = "binary"

        strings:

                $s1 = "getapula.pdb"
                $i1 = "wtsapi32.dll"
                $i2 = "cmpbk32.dll"
                $i3 = "PostMessageA"
                $i4 = "PeekMessageW"
                $i5 = "DispatchMessageW"
                $i6 = "WTSEnumerateSessionsA"

        condition:
                ($s1 or pe.exports("Tyman32")) and (2 of ($i*))
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (49, 'ws_f0xy_downloader', NULL, '{"author": "Nick Griffin (Websense)", "description": "f0xy malware downloader"}', '2020-12-04 20:50:41.536219', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule ws_f0xy_downloader {
  meta:
    description = "f0xy malware downloader"
    author = "Nick Griffin (Websense)"

  strings:
    $mz="MZ"
    $string1="bitsadmin /transfer"
    $string2="del rm.bat"
    $string3="av_list="

  condition:
    ($mz at 0) and (all of ($string*))
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (50, 'Win32Toxic', '{tox,ransomware}', '{"date": "2015-06-02", "hash0": "70624c13be4d8a4c1361be38b49cb3eb", "hash1": "4f20d25cd3ae2e5c63d451d095d97046", "hash2": "e0473434cc83b57c4b579d585d4c4c57", "hash3": "c52090d184b63e5cc71b524153bb079e", "hash4": "7ac0b49baba9914b234cde62058c96a5", "hash5": "048c007de4902b6f4731fde45fa8e6a9", "hash6": "238ef3e35b14e304c87b9c62f18953a9", "hash7": "8908ccd681f66429c578a889e6e708e1", "hash8": "de9fe2b7d9463982cc77c78ee51e4d51", "hash9": "37add8d26a35a3dc9700b92b67625fa4", "author": "@GelosSnake", "hash10": "a0f30e89a3431fca1d389f90dba1d56e", "hash11": "d4d0658302c731003bf0683127618bd9", "hash12": "d1d89e1c7066f41c1d30985ac7b569db", "hash13": "97d52d7281dfae8ff9e704bf30ce2484", "hash14": "2cc85be01e86e0505697cf61219e66da", "hash15": "02ecfb44b9b11b846ea8233d524ecda3", "hash16": "703a6ebe71131671df6bc92086c9a641", "hash17": "df23629b4a4aed05d6a453280256c05a", "hash18": "07466ff2572f16c63e1fee206b081d11", "hash19": "792a1c0971775d32bad374b288792468", "hash20": "fb7fd5623fa6b7791a221fad463223cd", "hash21": "83a562aab1d66e5d170f091b2ae6a213", "hash22": "99214c8c9ff4653b533dc1b19a21d389", "hash23": "a92aec198eee23a3a9a145e64d0250ee", "hash24": "e0f7e6b96ca72b9755965b9dac3ce77e", "hash25": "f520fc947a6d5edb87aa01510bee9c8d", "hash26": "6d7babbe5e438539a9fa2c5d6128d3b4", "hash27": "3133c2231fcee5d6b0b4c988a5201da1", "hash28": "e5b1d198edc413376e0c0091566198e4", "hash29": "50515b5a6e717976823895465d5dc684", "hash30": "510389e8c7f22f2076fc7c5388e01220", "hash31": "60573c945aa3b8cfaca0bdb6dd7d2019", "hash32": "394187056697463eba97382018dfe151", "hash33": "045a5d3c95e28629927c72cf3313f4cd", "hash34": "70951624eb06f7db0dcab5fc33f49127", "hash35": "5def9e3f7b15b2a75c80596b5e24e0f4", "hash36": "35a42fb1c65ebd7d763db4abb26d33b0", "hash37": "b0030f5072864572f8e6ba9b295615fc", "hash38": "62706f48689f1ba3d1d79780010b8739", "hash39": "be86183fa029629ee9c07310cd630871", "hash40": "9755c3920d3a38eb1b5b7edbce6d4914", "hash41": "cb42611b4bed97d152721e8db5abd860", "hash42": "5475344d69fc6778e12dc1cbba23b382", "hash43": "8c1bf70742b62dec1b350a4e5046c7b6", "hash44": "6a6541c0f63f45eff725dec951ec90a7", "hash45": "a592c5bee0d81ee127cbfbcb4178afe8", "hash46": "b74c6d86ec3904f4d73d05b2797f1cc3", "hash47": "28d76fd4dd2dbfc61b0c99d2ad08cd8e", "hash48": "fc859ae67dc1596ac3fdd79b2ed02910", "hash49": "cb65d5e929da8ff5c8434fd8d36e5dfb", "hash50": "888dd1acce29cd37f0696a0284ab740a", "hash51": "0e3e231c255a5eefefd20d70c247d5f0", "hash52": "e5ebe35d934106f9f4cebbd84e04534b", "hash53": "3b580f1fa0c961a83920ce32b4e4e86d", "hash54": "d807a704f78121250227793ea15aa9c4", "hash55": "db462159bddc0953444afd7b0d57e783", "hash56": "2ed4945fb9e6202c10fad0761723cb0e", "hash57": "51183ab4fd2304a278e36d36b5fb990c", "hash58": "65d602313c585c8712ea0560a655ddeb", "hash59": "0128c12d4a72d14bb67e459b3700a373", "hash60": "5d3dfc161c983f8e820e59c370f65581", "hash61": "d4dd475179cd9f6180d5b931e8740ed6", "hash62": "5dd3782ce5f94686448326ddbbac934c", "hash63": "c85c6171a7ff05d66d497ad0d73a51ed", "hash64": "b42dda2100da688243fe85a819d61e2e", "hash65": "a5cf8f2b7d97d86f4d8948360f3db714", "hash66": "293cae15e4db1217ea72581836a6642c", "hash67": "56c3a5bae3cb1d0d315c1353ae67cf58", "hash68": "c86dc1d0378cc0b579a11d873ac944e7", "hash69": "54cef0185798f3ec1f4cb95fad4ddd7c", "hash70": "eb2eff9838043b67e8024ccadcfe1a8f", "hash71": "78778fe62ee28ef949eec2e7e5961ca8", "hash72": "e75c5762471a490d49b79d01da745498", "hash73": "1564d3e27b90a166a0989a61dc3bd646", "hash74": "59ba111403842c1f260f886d69e8757d", "hash75": "d840dfbe52a04665e40807c9d960cccc", "hash76": "77f543f4a8f54ecf84b15da8e928d3f9", "hash77": "bd9512679fdc1e1e89a24f6ebe0d5ad8", "hash78": "202f042d02be4f6469ed6f2e71f42c04", "hash79": "28f827673833175dd9094002f2f9b780", "hash80": "0ff10287b4c50e0d11ab998a28529415", "hash81": "644daa2b294c5583ce6aa8bc68f1d21f", "hash82": "1c9db47778a41775bbcb70256cc1a035", "hash83": "c203bc5752e5319b81cf1ca970c3ca96", "hash84": "656f2571e4f5172182fc970a5b21c0e7", "hash85": "c17122a9864e3bbf622285c4d5503282", "hash86": "f9e3a9636b45edbcef2ee28bd6b1cfbb", "hash87": "291ff8b46d417691a83c73a9d3a30cc9", "hash88": "1217877d3f7824165bb28281ccc80182", "hash89": "18419d775652f47a657c5400d4aef4a3", "hash90": "04417923bf4f2be48dd567dfd33684e2", "hash91": "31efe902ec6a5ab9e6876cfe715d7c84", "hash92": "a2e4472c5097d7433b91d65579711664", "hash93": "98854d7aba1874c39636ff3b703a1ed1", "hash94": "5149f0e0a56b33e7bbed1457aab8763f", "hash95": "7a4338193ce12529d6ae5cfcbb1019af", "hash96": "aa7f37206aba3cbe5e11d336424c549a", "hash97": "51cad5d45cdbc2940a66d044d5a8dabf", "hash98": "85edb7b8dee5b60e3ce32e1286207faa", "hash99": "34ca5292ae56fea78ba14abe8fe11f06", "hash100": "154187f07621a9213d77a18c0758960f", "hash101": "4e633f0478b993551db22afddfa22262", "hash102": "5c50e4427fe178566cada96b2afbc2d4", "hash103": "263001ac21ef78c31f4ca7ad2e7f191d", "hash104": "53fd9e7500e3522065a2dabb932d9dc5", "hash105": "48043dc55718eb9e5b134dac93ebb5f6", "hash106": "ca19a1b85363cfed4d36e3e7b990c8b6", "hash107": "41b5403a5443a3a84f0007131173c126", "hash108": "6f3833bc6e5940155aa804e58500da81", "hash109": "9bd50fcfa7ca6e171516101673c4e795", "hash110": "6d52ba0d48d5bf3242cd11488c75b9a7", "hash111": "c52afb663ff4165e407f53a82e34e1d5", "hash112": "5a16396d418355731c6d7bb7b21e05f7", "hash113": "05559db924e71cccee87d21b968d0930", "hash114": "824312bf8e8e7714616ba62997467fa8", "hash115": "dfec435e6264a0bfe47fc5239631903c", "hash116": "3512e7da9d66ca62be3418bead2fb091", "hash117": "7ad4df88db6f292e7ddeec7cf63fa2bc", "hash118": "d512da73d0ca103df3c9e7c074babc99", "hash119": "c622b844388c16278d1bc768dcfbbeab", "hash120": "170ffa1cd19a1cecc6dae5bdd10efb58", "hash121": "3a19c91c1c0baa7dd4a9def2e0b7c3e9", "hash122": "3b7ce3ceb8d2b85ab822f355904d47ce", "hash123": "a7bac2ace1f04a7ad440bd2f5f811edc", "hash124": "66594a62d8c98e1387ec8deb3fe39431", "hash125": "a1add9e5d7646584fd4140528d02e4c3", "hash126": "11328bbf5a76535e53ab35315321f904", "hash127": "048f19d79c953e523675e96fb6e417a9", "hash128": "eb65fc2922eafd62defd978a3215814b", "hash129": "51cc9987f86a76d75bf335a8864ec250", "hash130": "a7f91301712b5a3cc8c3ab9c119530ce", "hash131": "de976a5b3d603161a737e7b947fdbb9a", "hash132": "288a3659cc1aec47530752b3a31c232b", "hash133": "91da679f417040558059ccd5b1063688", "hash134": "4ce9a0877b5c6f439f3e90f52eb85398", "hash135": "1f9e097ff9724d4384c09748a71ef99d", "hash136": "7d8a64a94e71a5c24ad82e8a58f4b7e6", "hash137": "db119e3c6b57d9c6b739b0f9cbaeb6fd", "hash138": "52c9d25179bf010a4bb20d5b5b4e0615", "hash139": "4b9995578d51fb891040a7f159613a99", "description": "https://blogs.mcafee.com/mcafee-labs/meet-tox-ransomware-for-the-rest-of-us", "yaragenerator": "https://github.com/Xen0ph0n/YaraGenerator", "sample_filetype": "exe"}', '2020-12-04 20:50:41.825282', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"


rule Win32Toxic : tox ransomware
{
meta:
	author = "@GelosSnake"
	date = "2015-06-02"
	description = "https://blogs.mcafee.com/mcafee-labs/meet-tox-ransomware-for-the-rest-of-us"
	hash0 = "70624c13be4d8a4c1361be38b49cb3eb"
	hash1 = "4f20d25cd3ae2e5c63d451d095d97046"
	hash2 = "e0473434cc83b57c4b579d585d4c4c57"
	hash3 = "c52090d184b63e5cc71b524153bb079e"
	hash4 = "7ac0b49baba9914b234cde62058c96a5"
	hash5 = "048c007de4902b6f4731fde45fa8e6a9"
	hash6 = "238ef3e35b14e304c87b9c62f18953a9"
	hash7 = "8908ccd681f66429c578a889e6e708e1"
	hash8 = "de9fe2b7d9463982cc77c78ee51e4d51"
	hash9 = "37add8d26a35a3dc9700b92b67625fa4"
	hash10 = "a0f30e89a3431fca1d389f90dba1d56e"
	hash11 = "d4d0658302c731003bf0683127618bd9"
	hash12 = "d1d89e1c7066f41c1d30985ac7b569db"
	hash13 = "97d52d7281dfae8ff9e704bf30ce2484"
	hash14 = "2cc85be01e86e0505697cf61219e66da"
	hash15 = "02ecfb44b9b11b846ea8233d524ecda3"
	hash16 = "703a6ebe71131671df6bc92086c9a641"
	hash17 = "df23629b4a4aed05d6a453280256c05a"
	hash18 = "07466ff2572f16c63e1fee206b081d11"
	hash19 = "792a1c0971775d32bad374b288792468"
	hash20 = "fb7fd5623fa6b7791a221fad463223cd"
	hash21 = "83a562aab1d66e5d170f091b2ae6a213"
	hash22 = "99214c8c9ff4653b533dc1b19a21d389"
	hash23 = "a92aec198eee23a3a9a145e64d0250ee"
	hash24 = "e0f7e6b96ca72b9755965b9dac3ce77e"
	hash25 = "f520fc947a6d5edb87aa01510bee9c8d"
	hash26 = "6d7babbe5e438539a9fa2c5d6128d3b4"
	hash27 = "3133c2231fcee5d6b0b4c988a5201da1"
	hash28 = "e5b1d198edc413376e0c0091566198e4"
	hash29 = "50515b5a6e717976823895465d5dc684"
	hash30 = "510389e8c7f22f2076fc7c5388e01220"
	hash31 = "60573c945aa3b8cfaca0bdb6dd7d2019"
	hash32 = "394187056697463eba97382018dfe151"
	hash33 = "045a5d3c95e28629927c72cf3313f4cd"
	hash34 = "70951624eb06f7db0dcab5fc33f49127"
	hash35 = "5def9e3f7b15b2a75c80596b5e24e0f4"
	hash36 = "35a42fb1c65ebd7d763db4abb26d33b0"
	hash37 = "b0030f5072864572f8e6ba9b295615fc"
	hash38 = "62706f48689f1ba3d1d79780010b8739"
	hash39 = "be86183fa029629ee9c07310cd630871"
	hash40 = "9755c3920d3a38eb1b5b7edbce6d4914"
	hash41 = "cb42611b4bed97d152721e8db5abd860"
	hash42 = "5475344d69fc6778e12dc1cbba23b382"
	hash43 = "8c1bf70742b62dec1b350a4e5046c7b6"
	hash44 = "6a6541c0f63f45eff725dec951ec90a7"
	hash45 = "a592c5bee0d81ee127cbfbcb4178afe8"
	hash46 = "b74c6d86ec3904f4d73d05b2797f1cc3"
	hash47 = "28d76fd4dd2dbfc61b0c99d2ad08cd8e"
	hash48 = "fc859ae67dc1596ac3fdd79b2ed02910"
	hash49 = "cb65d5e929da8ff5c8434fd8d36e5dfb"
	hash50 = "888dd1acce29cd37f0696a0284ab740a"
	hash51 = "0e3e231c255a5eefefd20d70c247d5f0"
	hash52 = "e5ebe35d934106f9f4cebbd84e04534b"
	hash53 = "3b580f1fa0c961a83920ce32b4e4e86d"
	hash54 = "d807a704f78121250227793ea15aa9c4"
	hash55 = "db462159bddc0953444afd7b0d57e783"
	hash56 = "2ed4945fb9e6202c10fad0761723cb0e"
	hash57 = "51183ab4fd2304a278e36d36b5fb990c"
	hash58 = "65d602313c585c8712ea0560a655ddeb"
	hash59 = "0128c12d4a72d14bb67e459b3700a373"
	hash60 = "5d3dfc161c983f8e820e59c370f65581"
	hash61 = "d4dd475179cd9f6180d5b931e8740ed6"
	hash62 = "5dd3782ce5f94686448326ddbbac934c"
	hash63 = "c85c6171a7ff05d66d497ad0d73a51ed"
	hash64 = "b42dda2100da688243fe85a819d61e2e"
	hash65 = "a5cf8f2b7d97d86f4d8948360f3db714"
	hash66 = "293cae15e4db1217ea72581836a6642c"
	hash67 = "56c3a5bae3cb1d0d315c1353ae67cf58"
	hash68 = "c86dc1d0378cc0b579a11d873ac944e7"
	hash69 = "54cef0185798f3ec1f4cb95fad4ddd7c"
	hash70 = "eb2eff9838043b67e8024ccadcfe1a8f"
	hash71 = "78778fe62ee28ef949eec2e7e5961ca8"
	hash72 = "e75c5762471a490d49b79d01da745498"
	hash73 = "1564d3e27b90a166a0989a61dc3bd646"
	hash74 = "59ba111403842c1f260f886d69e8757d"
	hash75 = "d840dfbe52a04665e40807c9d960cccc"
	hash76 = "77f543f4a8f54ecf84b15da8e928d3f9"
	hash77 = "bd9512679fdc1e1e89a24f6ebe0d5ad8"
	hash78 = "202f042d02be4f6469ed6f2e71f42c04"
	hash79 = "28f827673833175dd9094002f2f9b780"
	hash80 = "0ff10287b4c50e0d11ab998a28529415"
	hash81 = "644daa2b294c5583ce6aa8bc68f1d21f"
	hash82 = "1c9db47778a41775bbcb70256cc1a035"
	hash83 = "c203bc5752e5319b81cf1ca970c3ca96"
	hash84 = "656f2571e4f5172182fc970a5b21c0e7"
	hash85 = "c17122a9864e3bbf622285c4d5503282"
	hash86 = "f9e3a9636b45edbcef2ee28bd6b1cfbb"
	hash87 = "291ff8b46d417691a83c73a9d3a30cc9"
	hash88 = "1217877d3f7824165bb28281ccc80182"
	hash89 = "18419d775652f47a657c5400d4aef4a3"
	hash90 = "04417923bf4f2be48dd567dfd33684e2"
	hash91 = "31efe902ec6a5ab9e6876cfe715d7c84"
	hash92 = "a2e4472c5097d7433b91d65579711664"
	hash93 = "98854d7aba1874c39636ff3b703a1ed1"
	hash94 = "5149f0e0a56b33e7bbed1457aab8763f"
	hash95 = "7a4338193ce12529d6ae5cfcbb1019af"
	hash96 = "aa7f37206aba3cbe5e11d336424c549a"
	hash97 = "51cad5d45cdbc2940a66d044d5a8dabf"
	hash98 = "85edb7b8dee5b60e3ce32e1286207faa"
	hash99 = "34ca5292ae56fea78ba14abe8fe11f06"
	hash100 = "154187f07621a9213d77a18c0758960f"
	hash101 = "4e633f0478b993551db22afddfa22262"
	hash102 = "5c50e4427fe178566cada96b2afbc2d4"
	hash103 = "263001ac21ef78c31f4ca7ad2e7f191d"
	hash104 = "53fd9e7500e3522065a2dabb932d9dc5"
	hash105 = "48043dc55718eb9e5b134dac93ebb5f6"
	hash106 = "ca19a1b85363cfed4d36e3e7b990c8b6"
	hash107 = "41b5403a5443a3a84f0007131173c126"
	hash108 = "6f3833bc6e5940155aa804e58500da81"
	hash109 = "9bd50fcfa7ca6e171516101673c4e795"
	hash110 = "6d52ba0d48d5bf3242cd11488c75b9a7"
	hash111 = "c52afb663ff4165e407f53a82e34e1d5"
	hash112 = "5a16396d418355731c6d7bb7b21e05f7"
	hash113 = "05559db924e71cccee87d21b968d0930"
	hash114 = "824312bf8e8e7714616ba62997467fa8"
	hash115 = "dfec435e6264a0bfe47fc5239631903c"
	hash116 = "3512e7da9d66ca62be3418bead2fb091"
	hash117 = "7ad4df88db6f292e7ddeec7cf63fa2bc"
	hash118 = "d512da73d0ca103df3c9e7c074babc99"
	hash119 = "c622b844388c16278d1bc768dcfbbeab"
	hash120 = "170ffa1cd19a1cecc6dae5bdd10efb58"
	hash121 = "3a19c91c1c0baa7dd4a9def2e0b7c3e9"
	hash122 = "3b7ce3ceb8d2b85ab822f355904d47ce"
	hash123 = "a7bac2ace1f04a7ad440bd2f5f811edc"
	hash124 = "66594a62d8c98e1387ec8deb3fe39431"
	hash125 = "a1add9e5d7646584fd4140528d02e4c3"
	hash126 = "11328bbf5a76535e53ab35315321f904"
	hash127 = "048f19d79c953e523675e96fb6e417a9"
	hash128 = "eb65fc2922eafd62defd978a3215814b"
	hash129 = "51cc9987f86a76d75bf335a8864ec250"
	hash130 = "a7f91301712b5a3cc8c3ab9c119530ce"
	hash131 = "de976a5b3d603161a737e7b947fdbb9a"
	hash132 = "288a3659cc1aec47530752b3a31c232b"
	hash133 = "91da679f417040558059ccd5b1063688"
	hash134 = "4ce9a0877b5c6f439f3e90f52eb85398"
	hash135 = "1f9e097ff9724d4384c09748a71ef99d"
	hash136 = "7d8a64a94e71a5c24ad82e8a58f4b7e6"
	hash137 = "db119e3c6b57d9c6b739b0f9cbaeb6fd"
	hash138 = "52c9d25179bf010a4bb20d5b5b4e0615"
	hash139 = "4b9995578d51fb891040a7f159613a99"
	sample_filetype = "exe"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "n:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t;<<t;<<t;<<t;<<t;<<t;<<t;<<t;<<t<<<t;<<t;<<t;<<"
	$string1 = "t;<<t;<<t<<<t<<"
	$string2 = ">>><<<"
condition:
	2 of them
}


');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (51, 'Hsdfihdf', '{banking,malware}', '{"date": "2014-04-06", "hash0": "db1675c74a444fd35383d9a45631cada", "hash1": "f48ba39df38056449a3e9a1a7289f657", "author": "Adam Ziaja <adam@adamziaja.com> http://adamziaja.com", "filetype": "exe", "description": "Polish banking malware"}', '2020-12-04 20:50:42.07127', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
rule Hsdfihdf: banking malware
{
meta:
	author = "Adam Ziaja <adam@adamziaja.com> http://adamziaja.com"
	date = "2014-04-06"
	description = "Polish banking malware"
	hash0 = "db1675c74a444fd35383d9a45631cada"
	hash1 = "f48ba39df38056449a3e9a1a7289f657"
	filetype = "exe"
strings:
	$s0 = "ANSI_CHARSET"
	$s1 = "][Vee_d_["
	$s2 = "qfcD:6<"
	$s3 = "%-%/%1%3%5%7%9%;%"
	$s4 = "imhzxsc\\WWKD<.)w"
	$s5 = "Vzlarf\\]VOZVMskf"
	$s6 = "JKWFAp\\Z"
	$s7 = "<aLLwhg"
	$s8 = "bdLeftToRight"
	$s9 = "F/.pTC7"
	$s10 = "O><8,)-$ "
	$s11 = "mjeUB>D.''8)5\\\\vhe["
	$s12 = "JGiVRk[W]PL("
	$s13 = "zwWNNG:8"
	$s14 = "zv7,''$"
	$a0 = "#hsdfihdf"
	$a1 = "polska.irc.pl"
	$b0 = "firehim@o2.pl"
	$b1 = "firehim@go2.pl"
	$b2 = "firehim@tlen.pl"
	$c0 = "cyberpunks.pl"
	$c1 = "kaper.phrack.pl"
	$c2 = "serwer.uk.to"
	$c3 = "ns1.ipv4.hu"
	$c4 = "scorebot.koth.hu"
	$c5 = "esopoland.pl"
condition:
	14 of ($s*) or all of ($a*) or 1 of ($b*) or 2 of ($c*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (52, 'XOR_DDosv1', '{DDoS}', '{"author": "Akamai CSIRT", "description": "Rule to detect XOR DDos infection"}', '2020-12-04 20:50:42.778821', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule XOR_DDosv1 : DDoS
{
  meta:
    author = "Akamai CSIRT"
    description = "Rule to detect XOR DDos infection"
  strings:
    $st0 = "BB2FA36AAA9541F0"
    $st1 = "md5="
    $st2 = "denyip="
    $st3 = "filename="
    $st4 = "rmfile="
    $st5 = "exec_packet"
    $st6 = "build_iphdr"
  condition:
    all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (53, 'BlackRev', NULL, '{"date": "2013-05-21", "author": "Dennis Schwarz", "origin": "https://github.com/arbor/yara/blob/master/blackrev.yara", "description": "Black Revolution DDoS Malware. http://www.arbornetworks.com/asert/2013/05/the-revolution-will-be-written-in-delphi/"}', '2020-12-04 20:50:42.913735', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.

*/

rule BlackRev
{
   meta:
      author = "Dennis Schwarz"
      date = "2013-05-21"
      description = "Black Revolution DDoS Malware. http://www.arbornetworks.com/asert/2013/05/the-revolution-will-be-written-in-delphi/"
      origin = "https://github.com/arbor/yara/blob/master/blackrev.yara"

   strings:
      $base1 = "http"
      $base2 = "simple"
      $base3 = "loginpost"
      $base4 = "datapost"

      $opt1 = "blackrev"
      $opt2 = "stop"
      $opt3 = "die"
      $opt4 = "sleep"
      $opt5 = "syn"
      $opt6 = "udp"
      $opt7 = "udpdata"
      $opt8 = "icmp"
      $opt9 = "antiddos"
      $opt10 = "range"
      $opt11 = "fastddos"
      $opt12 = "slowhttp"
      $opt13 = "allhttp"
      $opt14 = "tcpdata"
      $opt15 = "dataget"

   condition:
      all of ($base*) and 5 of ($opt*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (54, 'Wabot', '{Worm}', '{"date": "14/08/2015", "author": "Kevin Falcoz", "description": "Wabot Trojan Worm"}', '2020-12-04 20:50:43.270323', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule Wabot : Worm
{
	meta:
		author="Kevin Falcoz"
		date="14/08/2015"
		description="Wabot Trojan Worm"

	strings:
		$signature1={43 3A 5C 6D 61 72 69 6A 75 61 6E 61 2E 74 78 74}
		$signature2={73 49 52 43 34}

	condition:
		$signature1 and $signature2
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (55, 'ransom_comodosec_mrcr1', NULL, '{"date": "2017/01", "author": " J from THL <j@techhelplist.com>", "maltype": "Ransomware", "version": 1, "filetype": "memory", "reference": "https://virustotal.com/en/file/75c82fd18fcf8a51bc1b32a89852d90978fa5e7a55281f42b0a1de98d14644fa/analysis/"}', '2020-12-04 20:50:43.390269', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule ransom_comodosec_mrcr1 {

        meta:
                author = " J from THL <j@techhelplist.com>"
                date = "2017/01"
                reference = "https://virustotal.com/en/file/75c82fd18fcf8a51bc1b32a89852d90978fa5e7a55281f42b0a1de98d14644fa/analysis/"
                version = 1
                maltype = "Ransomware"
                filetype = "memory"

        strings:
                $text01 = "WebKitFormBoundary"
                $text02 = "Start NetworkScan"
                $text03 = "Start DriveScan"
                $text04 = "Start CryptFiles"
                $text05 = "cmd /c vssadmin delete shadows /all /quiet"
                $text06 = "isAutorun:"
                $text07 = "isNetworkScan:"
                $text08 = "isUserDataLast:"
                $text09 = "isCryptFileNames:"
                $text10 = "isChangeFileExts:"
                $text11 = "isPowerOffWindows:"
                $text12 = "GatePath:"
                $text13 = "GatePort:"
                $text14 = "DefaultCryptKey:"
                $text15 = "UserAgent:"
                $text16 = "Mozilla_"
                $text17 = "On Error Resume Next"
                $text18 = "Content-Disposition: form-data; name=\"uid\""
                $text19 = "Content-Disposition: form-data; name=\"uname\""
                $text20 = "Content-Disposition: form-data; name=\"cname\""
                $regx21 = /\|[0-9a-z]{2,5}\|\|[0-9a-z]{2,5}\|\|[0-9a-z]{2,5}\|\|[0-9a-z]{2,5}\|/


    condition:
        10 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (70, 'LinuxHelios', '{MALW}', '{"MD5": "1a35193f3761662a9a1bd38b66327f49", "date": "2017-10-19", "SHA256": "72c2e804f185bef777e854fe86cff3e86f00290f32ae8b3cb56deedf201f1719", "author": "Joan Soriano / @w0lfvan", "version": "1.0", "description": "Linux.Helios"}', '2020-12-04 20:50:46.758427', 'rule LinuxHelios: MALW
{
	meta:
		description = "Linux.Helios"
		author = "Joan Soriano / @w0lfvan"
		date = "2017-10-19"
		version = "1.0"
		MD5 = "1a35193f3761662a9a1bd38b66327f49"
		SHA256 = "72c2e804f185bef777e854fe86cff3e86f00290f32ae8b3cb56deedf201f1719"
	strings:
		$a = "LIKE A GOD!!! IP:%s User:%s Pass:%s"
		$b = "smack"
		$c = "PEACE OUT IMMA DUP\n"
	condition:
		all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (56, 'sitrof_fortis_scar', NULL, '{"date": "2018/23", "author": "J from THL <j@techhelplist.com>", "maltype": "Stealer", "version": 2, "filetype": "memory", "reference1": "https://www.virustotal.com/#/file/59ab6cb69712d82f3e13973ecc7e7d2060914cea6238d338203a69bac95fd96c/community", "reference2": "ETPRO rule 2806032, ETPRO TROJAN Win32.Scar.hhrw POST"}', '2020-12-04 20:50:43.625256', 'rule sitrof_fortis_scar {

    meta:
        author = "J from THL <j@techhelplist.com>"
        date = "2018/23"
        reference1 = "https://www.virustotal.com/#/file/59ab6cb69712d82f3e13973ecc7e7d2060914cea6238d338203a69bac95fd96c/community"
	reference2 = "ETPRO rule 2806032, ETPRO TROJAN Win32.Scar.hhrw POST"
	version = 2
        maltype = "Stealer"
        filetype = "memory"

    strings:

	$a = "?get&version"
	$b = "?reg&ver="
	$c = "?get&exe"
	$d = "?get&download"
	$e = "?get&module"
	$f = "&ver="
	$g = "&comp="
	$h = "&addinfo="
	$i = "%s@%s; %s %s \"%s\" processor(s)"
	$j = "User-Agent: fortis"

    condition:
        6 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (57, 'locdoor_ransomware', NULL, '{"author": "Marc Rivero | @seifreed", "reference": "https://twitter.com/leotpsc/status/1036180615744376832", "description": "Rule to detect Locdoor/DryCry"}', '2020-12-04 20:50:43.735178', 'rule locdoor_ransomware {

   meta:

      description = "Rule to detect Locdoor/DryCry"
      author = "Marc Rivero | @seifreed"
      reference = "https://twitter.com/leotpsc/status/1036180615744376832"

   strings:

      $s1 = "copy \"Locdoor.exe\" \"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\temp00000000.exe\"" fullword ascii
      $s2 = "copy wscript.vbs C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\wscript.vbs" fullword ascii
      $s3 = "!! Your computer''s important files have been encrypted! Your computer''s important files have been encrypted!" fullword ascii
      $s4 = "echo CreateObject(\"SAPI.SpVoice\").Speak \"Your computer''s important files have been encrypted! " fullword ascii
      $s5 = "! Your computer''s important files have been encrypted! " fullword ascii
      $s7 = "This program is not supported on your operating system." fullword ascii
      $s8 = "echo Your computer''s files have been encrypted to Locdoor Ransomware! To make a recovery go to localbitcoins.com and create a wa" ascii
      $s9 = "Please enter the password." fullword ascii

   condition:

      ( uint16(0) == 0x5a4d and filesize < 600KB ) and all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (58, 'NionSpy', '{win32}', '{"reference": "https://blogs.mcafee.com/mcafee-labs/taking-a-close-look-at-data-stealing-nionspy-file-infector", "description": "Triggers on old and new variants of W32/NionSpy file infector"}', '2020-12-04 20:50:43.84149', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule NionSpy : win32
{
meta:
description = "Triggers on old and new variants of W32/NionSpy file infector"
reference = "https://blogs.mcafee.com/mcafee-labs/taking-a-close-look-at-data-stealing-nionspy-file-infector"
strings:
$variant2015_infmarker = "aCfG92KXpcSo4Y94BnUrFmnNk27EhW6CqP5EnT"
$variant2013_infmarker = "ad6af8bd5835d19cc7fdc4c62fdf02a1"
$variant2013_string = "%s?cstorage=shell&comp=%s"
condition:
uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and 1 of ($variant*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (59, 'DDosTf', NULL, '{"author": "benkow_ - MalwareMustDie", "reference": "http://blog.malwaremustdie.org/2016/01/mmd-0048-2016-ddostf-new-elf-windows.html", "description": "Rule to detect ELF.DDosTf infection"}', '2020-12-04 20:50:44.164558', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule DDosTf
{

meta:
    author = "benkow_ - MalwareMustDie"
    reference = "http://blog.malwaremustdie.org/2016/01/mmd-0048-2016-ddostf-new-elf-windows.html"
    description = "Rule to detect ELF.DDosTf infection"

strings:
    $st0 = "ddos.tf"
    $st1 = {E8 AE BE E7 BD AE 54 43  50 5F 4B 45 45 50 49 4E 54 56 4C E9 94 99 E8 AF AF EF BC 9A 00} /*TCP_KEEPINTVL*/
    $st2 = {E8 AE BE E7 BD AE 54 43  50 5F 4B 45 45 50 43 4E 54 E9 94 99 E8 AF AF EF BC 9A 00} /*TCP_KEEPCNT*/
    $st3 = "Accept-Language: zh"
    $st4 = "%d Kb/bps|%d%%"

condition:
    all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (60, 'Arkei', '{Arkei}', '{"Date": "2018/07/10", "Hash": "5632c89fe4c7c2c87b69d787bbf0a5b4cc535f1aa02699792888c60e0ef88fc5", "Author": "Fumik0_", "Description": "Arkei Stealer"}', '2020-12-04 20:50:44.97696', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule Arkei : Arkei
{
    meta:
        Author = "Fumik0_"
        Description = "Arkei Stealer"
        Date = "2018/07/10"
        Hash = "5632c89fe4c7c2c87b69d787bbf0a5b4cc535f1aa02699792888c60e0ef88fc5"

    strings:
        $s1 = "Arkei" wide ascii
        $s2 = "/server/gate" wide ascii
        $s3 = "/server/grubConfig" wide ascii
        $s4 = "\\files\\" wide ascii
        $s5 = "SQLite" wide ascii

    condition:
        all of ($s*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (61, 'MSILStealer', NULL, '{"author": "https://github.com/hwvs", "reference": "https://github.com/quasar/QuasarRAT", "description": "Detects strings from C#/VB Stealers and QuasarRat", "last_modified": "2019-11-21"}', '2020-12-04 20:50:45.088255', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule MSILStealer
{
    meta:
        description = "Detects strings from C#/VB Stealers and QuasarRat"
        reference = "https://github.com/quasar/QuasarRAT"
        author = "https://github.com/hwvs"
        last_modified = "2019-11-21"

    strings:
        $ = "Firefox does not have any profiles, has it ever been launched?" wide ascii
        $ = "Firefox is not installed, or the install path could not be located" wide ascii
        $ = "No installs of firefox recorded in its key." wide ascii
        $ = "{0}\\\\FileZilla\\\\recentservers.xml" wide ascii
        $ = "{1}{0}Cookie Name: {2}{0}Value: {3}{0}Path" wide ascii
        $ = "[PRIVATE KEY LOCATION: \\\"{0}\\\"]" wide ascii

    condition:
        1 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (62, 'APT_Uppercut', NULL, '{"date": "2018-09-13", "author": "Colin Cowie", "reference": "https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html", "description": "Detects APT10 MenuPass Uppercut"}', '2020-12-04 20:50:45.196328', 'import "hash"

rule APT_Uppercut {
  meta:
     description = "Detects APT10 MenuPass Uppercut"
     author = "Colin Cowie"
     reference = "https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html"
     date = "2018-09-13"
  strings:
     $ip1 = "51.106.53.147"
     $ip2 = "153.92.210.208"
     $ip3 = "eservake.jetos.com"
     $c1 = "0x97A168D9697D40DD" wide
     $c2 = "0x7CF812296CCC68D5" wide
     $c3 = "0x652CB1CEFF1C0A00" wide
     $c4 = "0x27595F1F74B55278" wide
     $c5 = "0xD290626C85FB1CE3" wide
     $c6 = "0x409C7A89CFF0A727" wide
  condition:
     any of them or
     hash.md5(0, filesize) == "aa3f303c3319b14b4829fe2faa5999c1" or
     hash.md5(0, filesize) == "126067d634d94c45084cbe1d9873d895" or
     hash.md5(0, filesize) == "fce54b4886cac5c61eda1e7605483ca3"
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (63, 'BernhardPOS', NULL, '{"md5": "e49820ef02ba5308ff84e4c8c12e7c3d", "score": 70, "author": "Nick Hoffman / Jeremy Humble", "source": "Morphick Inc.", "reference": "http://morphick.com/blog/2015/7/14/bernhardpos-new-pos-malware-discovered-by-morphick", "description": "BernhardPOS Credit Card dumping tool", "last_update": "2015-07-14"}', '2020-12-04 20:50:45.297094', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule BernhardPOS {
     meta:
          author = "Nick Hoffman / Jeremy Humble"
          last_update = "2015-07-14"
          source = "Morphick Inc."
          description = "BernhardPOS Credit Card dumping tool"
          reference = "http://morphick.com/blog/2015/7/14/bernhardpos-new-pos-malware-discovered-by-morphick"
          md5 = "e49820ef02ba5308ff84e4c8c12e7c3d"
          score = 70
     strings:
          $shellcode_kernel32_with_junk_code = { 33 c0 83 ?? ?? 83 ?? ?? 64 a1 30 00 00 00 83 ?? ?? 83 ?? ?? 8b 40 0c 83 ?? ?? 83 ?? ?? 8b 40 14 83 ?? ?? 83 ?? ?? 8b 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 00 83 ?? ?? 83 ?? ?? 8b 40 10 83 ?? ?? }
          $mutex_name = "OPSEC_BERNHARD"
          $build_path = "C:\\bernhard\\Debug\\bernhard.pdb"
          $string_decode_routine = { 55 8b ec 83 ec 50 53 56 57 a1 ?? ?? ?? ?? 89 45 f8 66 8b 0d ?? ?? ?? ?? 66 89 4d fc 8a 15 ?? ?? ?? ?? 88 55 fe 8d 45 f8 50 ff ?? ?? ?? ?? ?? 89 45 f0 c7 45 f4 00 00 00 00 ?? ?? 8b 45 f4 83 c0 01 89 45 f4 8b 45 08 50 ff ?? ?? ?? ?? ?? 39 45 f4 ?? ?? 8b 45 08 03 45 f4 0f be 08 8b 45 f4 99 f7 7d f0 0f be 54 15 f8 33 ca 8b 45 08 03 45 f4 88 08 ?? ?? 5f 5e 5b 8b e5 5d }
     condition:
          any of them
 }
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (64, 'almashreq_agent_dotnet', '{almashreq_agent_dotnet}', '{"date": "2019-05-12", "author": "J from THL <j@techhelplist.com> with thx to @malwrhunterteam !!1!", "maltype": "agent", "filetype": "memory", "reference1": "https://twitter.com/JayTHL/status/1127334608142503936", "reference2": "https://www.virustotal.com/#/file/f6e1e425650abc6c0465758edf3c089a1dde5b9f58d26a50d3b8682cc38f12c8/details", "reference3": "https://www.virustotal.com/#/file/7e4231dc2bdab53f494b84bc13c6cb99478a6405405004c649478323ed5a9071/detection", "reference4": "https://www.virustotal.com/#/file/3cbaf6ddba3869ab68baf458afb25d2c8ba623153c43708bad2f312c4663161b/detection", "reference5": "https://www.virustotal.com/#/file/0f5424614b3519a340198dd82ad0abc9711a23c3283dc25b519affe5d2959a92/detection", "description": "Memory rule for a .net RAT/Agent first found with .pdb referencing almashreq"}', '2020-12-04 20:50:45.401578', '

rule almashreq_agent_dotnet : almashreq_agent_dotnet
{
    meta:
        description = "Memory rule for a .net RAT/Agent first found with .pdb referencing almashreq"
	author = "J from THL <j@techhelplist.com> with thx to @malwrhunterteam !!1!"
        date = "2019-05-12"
        reference1 = "https://twitter.com/JayTHL/status/1127334608142503936"
        reference2 = "https://www.virustotal.com/#/file/f6e1e425650abc6c0465758edf3c089a1dde5b9f58d26a50d3b8682cc38f12c8/details"
        reference3 = "https://www.virustotal.com/#/file/7e4231dc2bdab53f494b84bc13c6cb99478a6405405004c649478323ed5a9071/detection"
        reference4 = "https://www.virustotal.com/#/file/3cbaf6ddba3869ab68baf458afb25d2c8ba623153c43708bad2f312c4663161b/detection"
        reference5 = "https://www.virustotal.com/#/file/0f5424614b3519a340198dd82ad0abc9711a23c3283dc25b519affe5d2959a92/detection"
        maltype = "agent"
	filetype = "memory"

    strings:
        $s01 = "WriteElementString(@\"PCName\"," wide
        $s02 = "WriteElementString(@\"Command\"," wide
        $s03 = "WriteElementStringRaw(@\"commandID\"," wide
	$s04 = /^Try Run$/ wide
        $s05 = " is running in PC :" wide
        $s06 = "SOAPAction: \"http://tempuri.org/Set\"" wide
        $s07 = "Try Run</obj><name>" wide
        $s08 = "Disable</obj><name>" wide
        $s09 = "http://tempuri.org/" wide

 	condition:
 		7 of them
}

');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (65, 'Erebus', '{ransom}', '{"MD5": "27d857e12b9be5d43f935b8cc86eaabf", "date": "2017-06-23", "ref1": "http://blog.trendmicro.com/trendlabs-security-intelligence/erebus-resurfaces-as-linux-ransomware/", "SHA256": "0b7996bca486575be15e68dba7cbd802b1e5f90436ba23f802da66292c8a055f", "author": "Joan Soriano / @joanbtl", "version": "1.0", "description": "Erebus Ransomware"}', '2020-12-04 20:50:45.518611', 'rule Erebus: ransom
{
	meta:
		description = "Erebus Ransomware"
		author = "Joan Soriano / @joanbtl"
		date = "2017-06-23"
		version = "1.0"
		MD5 = "27d857e12b9be5d43f935b8cc86eaabf"
		SHA256 = "0b7996bca486575be15e68dba7cbd802b1e5f90436ba23f802da66292c8a055f"
		ref1 = "http://blog.trendmicro.com/trendlabs-security-intelligence/erebus-resurfaces-as-linux-ransomware/"
	strings:
		$a = "/{5f58d6f0-bb9c-46e2-a4da-8ebc746f24a5}//log.log"
		$b = "EREBUS IS BEST."
	condition:
		all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (66, 'TreasureHunt', NULL, '{"ref": "http://www.minerva-labs.com/#!Cybercriminals-Adopt-the-Mossad-Emblem/c7a5/573da2d60cf2f90ca6f6e3ed", "date": "2016/06", "author": "Minerva Labs", "maltype": "Point of Sale (POS) Malware", "filetype": "exe"}', '2020-12-04 20:50:45.962457', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule TreasureHunt
  {
    meta:
      author = "Minerva Labs"
      ref ="http://www.minerva-labs.com/#!Cybercriminals-Adopt-the-Mossad-Emblem/c7a5/573da2d60cf2f90ca6f6e3ed"
      date = "2016/06"
      maltype = "Point of Sale (POS) Malware"
      filetype = "exe"

    strings:
      $a = "treasureHunter.pdb"
      $b = "jucheck"
      $c = "cmdLineDecrypted"

    condition:
      all of them
}

');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (67, 'Backdoored_ssh', NULL, '{"actor": "Energetic Bear/Crouching Yeti", "author": "Kaspersky", "reference": "https://securelist.com/energetic-bear-crouching-yeti/85345/"}', '2020-12-04 20:50:46.202603', 'rule Backdoored_ssh {
meta:
author = "Kaspersky"
reference = "https://securelist.com/energetic-bear-crouching-yeti/85345/"
actor = "Energetic Bear/Crouching Yeti"
strings:
$a1 = "OpenSSH"
$a2 = "usage: ssh"
$a3 = "HISTFILE"
condition:
uint32(0) == 0x464c457f and filesize<1000000 and all of ($a*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (68, 'Adzok', '{binary,RAT,Adzok}', '{"ref": "http://malwareconfig.com/stats/Adzok", "date": "2015/05", "author": " Kevin Breen <kevin@techanarchy.net>", "maltype": "Remote Access Trojan", "Versions": "Free 1.0.0.3,", "filetype": "jar", "Description": "Adzok Rat"}', '2020-12-04 20:50:46.425406', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule Adzok : binary RAT Adzok
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		Description = "Adzok Rat"
		Versions = "Free 1.0.0.3,"
		date = "2015/05"
		ref = "http://malwareconfig.com/stats/Adzok"
		maltype = "Remote Access Trojan"
		filetype = "jar"

	strings:
		$a1 = "config.xmlPK"
		$a2 = "key.classPK"
		$a3 = "svd$1.classPK"
		$a4 = "svd$2.classPK"
    	$a5 = "Mensaje.classPK"
		$a6 = "inic$ShutdownHook.class"
		$a7 = "Uninstall.jarPK"
		$a8 = "resources/icono.pngPK"

	condition:
    7 of ($a*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (69, 'sigma_ransomware', NULL, '{"date": "20180509", "author": "J from THL <j@techhelplist.com>", "maltype": "Ransomware", "version": 1, "filetype": "memory", "reference1": "https://www.virustotal.com/#/file/705ad78bf5503e6022f08da4c347afb47d4e740cfe6c39c08550c740c3be96ba", "reference2": "https://www.virustotal.com/#/file/bb3533440c27a115878ae541aba3bda02d441f3ea1864b868862255aabb0c8ff"}', '2020-12-04 20:50:46.6495', '
rule sigma_ransomware {

  meta:
    author = "J from THL <j@techhelplist.com>"
    date = "20180509"
    reference1 = "https://www.virustotal.com/#/file/705ad78bf5503e6022f08da4c347afb47d4e740cfe6c39c08550c740c3be96ba"
    reference2 = "https://www.virustotal.com/#/file/bb3533440c27a115878ae541aba3bda02d441f3ea1864b868862255aabb0c8ff"
    version = 1
    maltype = "Ransomware"
    filetype = "memory"

  strings:
    $a = ".php?"
    $b = "uid="
    $c = "&uname="
    $d = "&os="
    $e = "&pcname="
    $f = "&total="
    $g = "&country="
    $h = "&network="
    $i = "&subid="

  condition:
    all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (71, 'TROJAN_Notepad', NULL, '{"MD5": "106E63DBDA3A76BEEB53A8BBD8F98927", "Date": "4Jun13", "File": "notepad.exe v 1.1", "Author": "RSA_IR"}', '2020-12-04 20:50:47.083335', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule TROJAN_Notepad {
    meta:
        Author = "RSA_IR"
        Date     = "4Jun13"
        File     = "notepad.exe v 1.1"
        MD5      = "106E63DBDA3A76BEEB53A8BBD8F98927"
    strings:
        $s1 = "75BAA77C842BE168B0F66C42C7885997"
        $s2 = "B523F63566F407F3834BCC54AAA32524"
    condition:
        $s1 or $s2
}


');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (72, 'Windows_Malware', '{Azorult_V2}', '{"date": "2017-09-30", "author": "Xylitol xylitol@temari.fr", "reference": "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=4819&p=30867", "description": "Match first two bytes, strings, and parts of routines present in Azorult"}', '2020-12-04 20:50:47.523733', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

import "cuckoo"
rule Windows_Malware : Azorult_V2
    {
            meta:
                    author = "Xylitol xylitol@temari.fr"
                    date = "2017-09-30"
                    description = "Match first two bytes, strings, and parts of routines present in Azorult"
                    reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=4819&p=30867"
                    // May only the challenge guide you
            strings:
                    $mz = {4D 5A}
                    $string1 = "ST234LMUV56CklAopq78Brstuvwxyz01NOPQRmGHIJKWXYZabcdefgDEFhijn9+/" wide ascii // Azorult custom base64-like alphabet
                    $string2 = "SYSInfo.txt"
                    $string3 = "CookieList.txt"
                    $string4 = "Passwords.txt"
                    $constant1 = {85 C0 74 40 85 D2 74 31 53 56 57 89 C6 89 D7 8B 4F FC 57} // Azorult grabs .txt and .dat files from Desktop
                    $constant2 = {68 ?? ?? ?? ?? FF 75 FC 68 ?? ?? ?? ?? 8D 45 F8 BA 03 00} // Portion of code from Azorult self-delete function
            condition:
                    ($mz at 0 and all of ($string*) and ($constant1 or $constant2) or cuckoo.sync.mutex(/Ad48qw4d6wq84d56as|Adkhvhhydhasdasashbc/))
    }
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (73, 'TeslaCrypt', NULL, '{"author": "CCN-CERT", "version": "1.0", "description": "Regla para detectar Tesla con md5"}', '2020-12-04 20:50:47.636', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule TeslaCrypt {
meta:
    description = "Regla para detectar Tesla con md5"
    author = "CCN-CERT"
    version = "1.0"
strings:
    $ = { 4E 6F 77 20 69 74 27 73 20 25 49 3A 25 4D 25 70 2E 00 00 00 76 61 6C 20 69 73 20 25 64 0A 00 00 }
condition:
    all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (74, 'Backdoor_Jolob', NULL, '{"ref": "https://github.com/reed1713", "maltype": "Backdoor.Jolob", "reference": "http://www.symantec.com/connect/blogs/new-flash-zero-day-linked-yet-more-watering-hole-attacks", "description": "the backdoor registers an auto start service with the display name \\\"Network Access Management Agent\\\" pointing to the dll netfilter.dll. This is accomplished without notifying the user via the sysprep UAC bypass method."}', '2020-12-04 20:50:47.752899', 'rule Backdoor_Jolob
{
	meta:
		maltype = "Backdoor.Jolob"
    ref = "https://github.com/reed1713"
		reference = "http://www.symantec.com/connect/blogs/new-flash-zero-day-linked-yet-more-watering-hole-attacks"
		description = "the backdoor registers an auto start service with the display name \"Network Access Management Agent\" pointing to the dll netfilter.dll. This is accomplished without notifying the user via the sysprep UAC bypass method."
	strings:
		$type = "Microsoft-Windows-Security-Auditing"
		$eventid = "4673"
		$data1 = "Security"
		$data2 = "SeCreateGlobalPrivilege"
		$data3 = "Windows\\System32\\sysprep\\sysprep.exe" nocase

		$type1 = "Microsoft-Windows-Security-Auditing"
		$eventid1 = "4688"
		$data4 = "Windows\\System32\\sysprep\\sysprep.exe" nocase

		$type2 = "Service Control Manager"
		$eventid2 = "7036"
		$data5 = "Network Access Management Agent"
		$data6 = "running"

		$type3 = "Service Control Manager"
		$eventid3 = "7045"
		$data7 = "Network Access Management Agent"
		$data8 = "user mode service"
		$data9 = "auto start"
    condition:
    	all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (75, 'SNOWGLOBE_Babar_Malware', NULL, '{"date": "2015/02/18", "hash": "27a0a98053f3eed82a51cdefbdfec7bb948e1f36", "score": 80, "author": "Florian Roth", "reference": "http://motherboard.vice.com/read/meet-babar-a-new-malware-almost-certainly-created-by-france", "description": "Detects the Babar Malware used in the SNOWGLOBE attacks - file babar.exe"}', '2020-12-04 20:50:47.866138', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule SNOWGLOBE_Babar_Malware
{

    meta:
        description = "Detects the Babar Malware used in the SNOWGLOBE attacks - file babar.exe"
        author = "Florian Roth"
        reference = "http://motherboard.vice.com/read/meet-babar-a-new-malware-almost-certainly-created-by-france"
        date = "2015/02/18"
        hash = "27a0a98053f3eed82a51cdefbdfec7bb948e1f36"
        score = 80

    strings:
        $mz = { 4d 5a }
        $z0 = "admin\\Desktop\\Babar64\\Babar64\\obj\\DllWrapper" ascii fullword
        $z1 = "User-Agent: Mozilla/4.0 (compatible; MSI 6.0;" ascii fullword
        $z2 = "ExecQueryFailled!" fullword ascii
        $z3 = "NBOT_COMMAND_LINE" fullword
        $z4 = "!!!EXTRACT ERROR!!!File Does Not Exists-->[%s]" fullword
        $s1 = "/s /n %s \"%s\"" fullword ascii
        $s2 = "%%WINDIR%%\\%s\\%s" fullword ascii
        $s3 = "/c start /wait " fullword ascii
        $s4 = "(D;OICI;FA;;;AN)(A;OICI;FA;;;BG)(A;OICI;FA;;;SY)(A;OICI;FA;;;LS)" ascii
        $x1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\" fullword ascii
        $x2 = "%COMMON_APPDATA%" fullword ascii
        $x4 = "CONOUT$" fullword ascii
        $x5 = "cmd.exe" fullword ascii
        $x6 = "DLLPATH" fullword ascii

    condition:
        ( $mz at 0 ) and filesize < 1MB and (( 1 of ($z*) and 1 of ($x*) ) or ( 3 of ($s*) and 4 of ($x*) ) )
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (76, 'Win32_Buzus_Softpulse', NULL, '{"date": "2015-05-13", "hash": "2f6df200e63a86768471399a74180466d2e99ea9", "score": 75, "author": "Florian Roth", "description": "Trojan Buzus / Softpulse"}', '2020-12-04 20:50:47.975811', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Win32_Buzus_Softpulse
{

    meta:
        description = "Trojan Buzus / Softpulse"
        author = "Florian Roth"
        date = "2015-05-13"
        hash = "2f6df200e63a86768471399a74180466d2e99ea9"
        score = 75

    strings:
        $x1 = "pi4izd6vp0.com" fullword ascii
        $s1 = "SELECT * FROM Win32_Process" fullword wide
        $s4 = "CurrentVersion\\Uninstall\\avast" fullword wide
        $s5 = "Find_RepeatProcess" fullword ascii
        $s6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\" fullword wide
        $s7 = "myapp.exe" fullword ascii
        $s14 = "/c ping -n 1 www.google" wide

    condition:
        uint16(0) == 0x5a4d and ( ( $x1 and 2 of ($s*) ) or all of ($s*) )
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (77, 'IotReaper', '{MALW}', '{"MD5": "95b448bdf6b6c97a33e1d1dbe41678eb", "date": "2017-10-30", "SHA256": "b463ca6c3ec7fa19cd318afdd2fa2365fa9e947771c21c4bd6a3bc2120ba7f28", "author": "Joan Soriano / @w0lfvan", "version": "1.0", "description": "Linux.IotReaper"}', '2020-12-04 20:50:48.086223', 'rule IotReaper: MALW
{
	meta:
		description = "Linux.IotReaper"
		author = "Joan Soriano / @w0lfvan"
		date = "2017-10-30"
		version = "1.0"
		MD5 = "95b448bdf6b6c97a33e1d1dbe41678eb"
		SHA256 = "b463ca6c3ec7fa19cd318afdd2fa2365fa9e947771c21c4bd6a3bc2120ba7f28"
	strings:
		$a = "weruuoqweiur.com"
		$b = "rm -f /tmp/ftpupload.sh \n"
		$c = "%02x-%02x-%02x-%02x-%02x-%02x"
	condition:
		all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (78, 'pico_ransomware', NULL, '{"author": "Marc Rivero | @seifreed", "reference": "https://twitter.com/siri_urz/status/1035138577934557184", "description": "Rule to detect Pico Ransomware"}', '2020-12-04 20:50:48.193091', 'rule pico_ransomware {

   meta:

      description = "Rule to detect Pico Ransomware"
      author = "Marc Rivero | @seifreed"
      reference = "https://twitter.com/siri_urz/status/1035138577934557184"

   strings:

      $s1 = "C:\\Users\\rikfe\\Desktop\\Ransomware\\ThanatosSource\\Release\\Ransomware.pdb" fullword ascii
      $s2 = "\\Downloads\\README.txt" fullword ascii
      $s3 = "\\Music\\README.txt" fullword ascii
      $s4 = "\\Videos\\README.txt" fullword ascii
      $s5 = "\\Pictures\\README.txt" fullword ascii
      $s6 = "\\Desktop\\README.txt" fullword ascii
      $s7 = "\\Documents\\README.txt" fullword ascii
      $s8 = "/c taskkill /im " fullword ascii
      $s9 = "\\AppData\\Roaming\\" fullword ascii
      $s10 = "gMozilla/5.0 (Windows NT 6.1) Thanatos/1.1" fullword wide
      $s11 = "AppData\\Roaming" fullword ascii
      $s12 = "\\Downloads" fullword ascii
      $s13 = "operator co_await" fullword ascii

   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB ) and all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (79, 'Cobalt_functions', NULL, '{"url": "https://www.securityartwork.es/2017/06/16/analisis-del-powershell-usado-fin7/", "author": "@j0sm1", "description": "Detect functions coded with ROR edi,D; Detect CobaltStrike used by differents groups APT"}', '2020-12-04 20:50:48.848585', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule Cobalt_functions
{

    meta:

        author="@j0sm1"
        url="https://www.securityartwork.es/2017/06/16/analisis-del-powershell-usado-fin7/"
        description="Detect functions coded with ROR edi,D; Detect CobaltStrike used by differents groups APT"

    strings:

        $h1={58 A4 53 E5} // VirtualAllocEx
        $h2={4C 77 26 07} // LoadLibraryEx
        $h3={6A C9 9C C9} // DNSQuery_UTF8
        $h4={44 F0 35 E0} // Sleep
        $h5={F4 00 8E CC} // lstrlen

    condition:
        2 of ( $h* )
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (80, 'Emotets', NULL, '{"date": "2017-10-18", "author": "pekeinfo", "description": "Emotets"}', '2020-12-04 20:50:48.983354', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Emotets{
meta:
  author = "pekeinfo"
  date = "2017-10-18"
  description = "Emotets"
strings:
  $mz = { 4d 5a }
  $cmovnz={ 0f 45 fb 0f 45 de }
  $mov_esp_0={ C7 04 24 00 00 00 00 89 44 24 0? }
  $_eax={ 89 E? 8D ?? 24 ?? 89 ?? FF D0 83 EC 04 }
condition:
  ($mz at 0 and $_eax in( 0x2854..0x4000)) and ($cmovnz or $mov_esp_0)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (81, 'glassrat', '{RAT}', '{"author": "Brian Wallace @botnet_hunter"}', '2020-12-04 20:50:49.125776', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
rule glassrat: RAT
{
   meta:
        author = "Brian Wallace @botnet_hunter"
   strings:
    	$a = "PostQuitMessage"
        $b = "pwlfnn10,gzg"
        $c = "update.dll"
        $d = "_winver"
   condition:
    	all of them

}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (82, 'Maze', NULL, '{"tlp": "White", "date": "2019-11", "author": "@bartblaze", "description": "Identifies Maze ransomware in memory or unpacked."}', '2020-12-04 20:50:49.468787', 'rule Maze
{
meta:
	description = "Identifies Maze ransomware in memory or unpacked."
	author = "@bartblaze"
	date = "2019-11"
	tlp = "White"

strings:
	$ = "Enc: %s" ascii wide
	$ = "Encrypting whole system" ascii wide
	$ = "Encrypting specified folder in --path parameter..." ascii wide
	$ = "!Finished in %d ms!" ascii wide
	$ = "--logging" ascii wide
	$ = "--nomutex" ascii wide
	$ = "--noshares" ascii wide
	$ = "--path" ascii wide
	$ = "Logging enabled | Maze" ascii wide
	$ = "NO SHARES | " ascii wide
	$ = "NO MUTEX | " ascii wide
	$ = "Encrypting:" ascii wide
	$ = "You need to buy decryptor in order to restore the files." ascii wide
	$ = "Dear %s, your files have been encrypted by RSA-2048 and ChaCha algorithms" ascii wide
	$ = "%s! Alert! %s! Alert! Dear %s Your files have been encrypted by %s! Attention! %s" ascii wide
	$ = "DECRYPT-FILES.txt" ascii wide fullword

condition:
	5 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (83, 'PE_File_pyinstaller', NULL, '{"author": "Didier Stevens (https://DidierStevens.com)", "reference": "https://isc.sans.edu/diary/21057", "description": "Detect PE file produced by pyinstaller"}', '2020-12-04 20:50:49.57906', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

import "pe"

rule PE_File_pyinstaller
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Detect PE file produced by pyinstaller"
        reference = "https://isc.sans.edu/diary/21057"
    strings:
        $a = "pyi-windows-manifest-filename"
    condition:
        pe.number_of_resources > 0 and $a
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (84, 'screenlocker_5h311_1nj3c706', NULL, '{"author": "Marc Rivero | @seifreed", "reference": "https://twitter.com/demonslay335/status/1038060120461266944", "description": "Rule to detect the screenlocker 5h311_1nj3c706"}', '2020-12-04 20:50:49.907644', 'rule screenlocker_5h311_1nj3c706 {

   meta:

      description = "Rule to detect the screenlocker 5h311_1nj3c706"
      author = "Marc Rivero | @seifreed"
      reference = "https://twitter.com/demonslay335/status/1038060120461266944"

   strings:

      $s1 = "C:\\Users\\Hoang Nam\\source\\repos\\WindowsApp22\\WindowsApp22\\obj\\Debug\\WindowsApp22.pdb" fullword ascii
      $s2 = "cmd.exe /cREG add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop /v NoChangingWallPaper /t REG_DWOR" wide
      $s3 = "C:\\Users\\file1.txt" fullword wide
      $s4 = "C:\\Users\\file2.txt" fullword wide
      $s5 = "C:\\Users\\file.txt" fullword wide
      $s6 = " /v Wallpaper /t REG_SZ /d %temp%\\IMG.jpg /f" fullword wide
      $s7 = " /v DisableAntiSpyware /t REG_DWORD /d 1 /f" fullword wide
      $s8 = "All your file has been locked. You must pay money to have a key." fullword wide
      $s9 = "After we receive Bitcoin from you. We will send key to your email." fullword wide

   condition:

      ( uint16(0) == 0x5a4d and filesize < 200KB ) and all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (190, 'onimiki', NULL, '{"author": "Olivier Bilodeau <bilodeau@eset.com>", "source": "https://github.com/eset/malware-ioc/", "contact": "windigo@eset.sk", "created": "2014-02-06", "license": "BSD 2-Clause", "malware": "Linux/Onimiki", "operation": "Windigo", "reference": "http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf", "description": "Linux/Onimiki malicious DNS server"}', '2020-12-04 20:51:16.882855', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

// Operation Windigo yara rules
// For feedback or questions contact us at: windigo@eset.sk
// https://github.com/eset/malware-ioc/
//
// These yara rules are provided to the community under the two-clause BSD
// license as follows:
//
// Copyright (c) 2014, ESET
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
rule onimiki
{

  meta:
    description = "Linux/Onimiki malicious DNS server"
    malware = "Linux/Onimiki"
    operation = "Windigo"
    author = "Olivier Bilodeau <bilodeau@eset.com>"
    created = "2014-02-06"
    reference = "http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf"
    contact = "windigo@eset.sk"
    source = "https://github.com/eset/malware-ioc/"
    license = "BSD 2-Clause"

  strings:
    // code from offset: 0x46CBCD
    $a1 = {43 0F B6 74 2A 0E 43 0F  B6 0C 2A 8D 7C 3D 00 8D}
    $a2 = {74 35 00 8D 4C 0D 00 89  F8 41 F7 E3 89 F8 29 D0}
    $a3 = {D1 E8 01 C2 89 F0 C1 EA  04 44 8D 0C 92 46 8D 0C}
    $a4 = {8A 41 F7 E3 89 F0 44 29  CF 29 D0 D1 E8 01 C2 89}
    $a5 = {C8 C1 EA 04 44 8D 04 92  46 8D 04 82 41 F7 E3 89}
    $a6 = {C8 44 29 C6 29 D0 D1 E8  01 C2 C1 EA 04 8D 04 92}
    $a7 = {8D 04 82 29 C1 42 0F B6  04 21 42 88 84 14 C0 01}
    $a8 = {00 00 42 0F B6 04 27 43  88 04 32 42 0F B6 04 26}
    $a9 = {42 88 84 14 A0 01 00 00  49 83 C2 01 49 83 FA 07}

  condition:
    all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (85, 'CorkowDLL', NULL, '{"reference": "IB-Group | http://www.group-ib.ru/brochures/Group-IB-Corkow-Report-EN.pdf", "description": "Rule to detect the Corkow DLL files"}', '2020-12-04 20:50:51.001726', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule CorkowDLL
{

    meta:
        description = "Rule to detect the Corkow DLL files"
        reference = "IB-Group | http://www.group-ib.ru/brochures/Group-IB-Corkow-Report-EN.pdf"

    strings:
        $mz = { 4d 5a }
        $binary1 = {60 [0-8] 9C [0-8] BB ?? ?? ?? ?? [0-8] 81 EB ?? ?? ?? ?? [0-8] E8 ?? 00 00 00 [0-8] 58 [0-8] 2B C3}
        $binary2 = {(FF75??|53)FF7510FF750CFF7508E8????????[3-9]C9C20C 00}
        $export1 = "Control_RunDLL"
        $export2 = "ServiceMain"
        $export3 = "DllGetClassObject"

    condition:
        ($mz at 0) and ($binary1 and $binary2) and any of ($export*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (86, 'OpClandestineWolf', NULL, '{"log": "false", "date": "2015-06-23", "alert": true, "hash0": "1a4b710621ef2e69b1f7790ae9b7a288", "hash1": "917c92e8662faf96fffb8ffe7b7c80fb", "hash2": "975b458cb80395fa32c9dda759cb3f7b", "hash3": "3ed34de8609cd274e49bbd795f21acc4", "hash4": "b1a55ec420dd6d24ff9e762c7b753868", "hash5": "afd753a42036000ad476dcd81b56b754", "hash6": "fad20abf8aa4eda0802504d806280dd7", "hash7": "ab621059de2d1c92c3e7514e4b51751a", "hash8": "510b77a4b075f09202209f989582dbea", "hash9": "d1b1abfcc2d547e1ea1a4bb82294b9a3", "author": "NDF", "hash10": "4692337bf7584f6bda464b9a76d268c1", "hash11": "7cae5757f3ba9fef0a22ca0d56188439", "hash12": "1a7ba923c6aa39cc9cb289a17599fce0", "hash13": "f86db1905b3f4447eb5728859f9057b5", "hash14": "37c6d1d3054e554e13d40ea42458ebed", "hash15": "3e7430a09a44c0d1000f76c3adc6f4fa", "hash16": "98eb249e4ddc4897b8be6fe838051af7", "hash17": "1b57a7fad852b1d686c72e96f7837b44", "hash18": "ffb84b8561e49a8db60e0001f630831f", "hash19": "98eb249e4ddc4897b8be6fe838051af7", "hash20": "dfb4025352a80c2d81b84b37ef00bcd0", "hash21": "4457e89f4aec692d8507378694e0a3ba", "hash22": "48de562acb62b469480b8e29821f33b8", "hash23": "7a7eed9f2d1807f55a9308e21d81cccd", "hash24": "6817b29e9832d8fd85dcbe4af176efb6", "source": " https://www.fireeye.com/blog/threat-research/2015/06/operation-clandestine-wolf-adobe-flash-zero-day.html", "weight": 10, "version": 1, "description": "Operation Clandestine Wolf signature based on OSINT from 06.23.15", "alert_severity": "HIGH"}', '2020-12-04 20:50:51.255973', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule OpClandestineWolf
{

   meta:
        alert_severity = "HIGH"
        log = "false"
        author = "NDF"
        weight = 10
        alert = true
        source = " https://www.fireeye.com/blog/threat-research/2015/06/operation-clandestine-wolf-adobe-flash-zero-day.html"
        version = 1
        date = "2015-06-23"
        description = "Operation Clandestine Wolf signature based on OSINT from 06.23.15"
        hash0 = "1a4b710621ef2e69b1f7790ae9b7a288"
        hash1 = "917c92e8662faf96fffb8ffe7b7c80fb"
        hash2 = "975b458cb80395fa32c9dda759cb3f7b"
        hash3 = "3ed34de8609cd274e49bbd795f21acc4"
        hash4 = "b1a55ec420dd6d24ff9e762c7b753868"
        hash5 = "afd753a42036000ad476dcd81b56b754"
        hash6 = "fad20abf8aa4eda0802504d806280dd7"
        hash7 = "ab621059de2d1c92c3e7514e4b51751a"
        hash8 = "510b77a4b075f09202209f989582dbea"
        hash9 = "d1b1abfcc2d547e1ea1a4bb82294b9a3"
        hash10 = "4692337bf7584f6bda464b9a76d268c1"
        hash11 = "7cae5757f3ba9fef0a22ca0d56188439"
        hash12 = "1a7ba923c6aa39cc9cb289a17599fce0"
        hash13 = "f86db1905b3f4447eb5728859f9057b5"
        hash14 = "37c6d1d3054e554e13d40ea42458ebed"
        hash15 = "3e7430a09a44c0d1000f76c3adc6f4fa"
        hash16 = "98eb249e4ddc4897b8be6fe838051af7"
        hash17 = "1b57a7fad852b1d686c72e96f7837b44"
        hash18 = "ffb84b8561e49a8db60e0001f630831f"
        hash19 = "98eb249e4ddc4897b8be6fe838051af7"
        hash20 = "dfb4025352a80c2d81b84b37ef00bcd0"
        hash21 = "4457e89f4aec692d8507378694e0a3ba"
        hash22 = "48de562acb62b469480b8e29821f33b8"
        hash23 = "7a7eed9f2d1807f55a9308e21d81cccd"
        hash24 = "6817b29e9832d8fd85dcbe4af176efb6"

   strings:
        $s0 = "flash.Media.Sound()"
        $s1 = "call Kernel32!VirtualAlloc(0x1f140000hash$=0x10000hash$=0x1000hash$=0x40)"
        $s2 = "{4D36E972-E325-11CE-BFC1-08002BE10318}"
        $s3 = "NetStream"

    condition:
        all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (87, 'dubrute', '{bruteforcer,toolkit}', '{"date": "2015-09-05", "author": "Christian Rebischke (@sh1bumi)", "family": "Hackingtool/Bruteforcer", "description": "Rules for DuBrute Bruteforcer", "in_the_wild": true}', '2020-12-04 20:50:51.365383', 'rule dubrute : bruteforcer toolkit
{
    meta:
        author = "Christian Rebischke (@sh1bumi)"
        date = "2015-09-05"
        description = "Rules for DuBrute Bruteforcer"
        in_the_wild = true
        family = "Hackingtool/Bruteforcer"

    strings:
        $a = "WBrute"
        $b = "error.txt"
        $c = "good.txt"
        $d = "source.txt"
        $e = "bad.txt"
        $f = "Generator IP@Login;Password"

    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D

        and

        //check for dubrute specific strings
        $a and $b and $c and $d and $e and $f
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (88, 'kpot', NULL, '{"date": "2018-08-29", "author": " J from THL <j@techhelplist.com>", "maltype": "Stealer", "version": 1, "filetype": "memory", "reference1": "https://www.virustotal.com/#/file/4e87a0794bf73d06ac1ce4a37e33eb832ff4c89fb9e4266490c7cef9229d27a7/detection", "reference2": "ETPRO TROJAN KPOT Stealer Check-In [2832358]", "reference3": "ETPRO TROJAN KPOT Stealer Exfiltration [2832359]"}', '2020-12-04 20:50:51.610276', '
rule kpot
{

    meta:
        author = " J from THL <j@techhelplist.com>"
        date = "2018-08-29"
        reference1 = "https://www.virustotal.com/#/file/4e87a0794bf73d06ac1ce4a37e33eb832ff4c89fb9e4266490c7cef9229d27a7/detection"
        reference2 = "ETPRO TROJAN KPOT Stealer Check-In [2832358]"
        reference3 = "ETPRO TROJAN KPOT Stealer Exfiltration [2832359]"
        version = 1
        maltype = "Stealer"
        filetype = "memory"

    strings:
        $text01 = "bot_id=%s"
        $text02 = "x64=%d"
        $text03 = "is_admin=%d"
        $text04 = "IL=%d"
        $text05 = "os_version=%d"
        $text06 = "IP: %S"
        $text07 = "MachineGuid: %s"
        $text08 = "CPU: %S (%d cores)"
        $text09 = "RAM: %S MB"
        $text10 = "Screen: %dx%d"
        $text11 = "PC: %s"
        $text12 = "User: %s"
        $text13 = "LT: %S (UTC+%d:%d)"
        $text14 = "%s/%s.php"
        $text15 = "Host: %s"
        $text16 = "username_value"
        $text17 = "password_value"
        $text18 = "name_on_card"
        $text19 = "last_four"
        $text20 = "exp_month"
        $text21 = "exp_year"
        $text22 = "bank_name"


    condition:
        16 of them
}

');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (89, 'Agenttesla', NULL, '{"author": "Stormshield", "version": "1.0", "reference": "https://thisissecurity.stormshield.com/2018/01/12/agent-tesla-campaign/", "description": "Detecting HTML strings used by Agent Tesla malware"}', '2020-12-04 20:50:51.974321', '
rule Agenttesla
{
    meta:
        description = "Detecting HTML strings used by Agent Tesla malware"
        author = "Stormshield"
        reference = "https://thisissecurity.stormshield.com/2018/01/12/agent-tesla-campaign/"
        version = "1.0"

    strings:
        $html_username    = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_pc_name     = "<br>PC&nbsp;Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_os_name     = "<br>OS&nbsp;Full&nbsp;Name&nbsp;&nbsp;: " wide ascii
        $html_os_platform = "<br>OS&nbsp;Platform&nbsp;&nbsp;&nbsp;: " wide ascii
        $html_clipboard   = "<br><span style=font-style:normal;text-decoration:none;text-transform:none;color:#FF0000;><strong>[clipboard]</strong></span>" wide ascii

    condition:
        3 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (90, 'MALW_FakePyPI', NULL, '{"tlp": "white", "date": "2017-09", "author": "@bartblaze", "reference": "http://www.nbu.gov.sk/skcsirt-sa-20170909-pypi/", "description": "Identifies fake PyPI Packages."}', '2020-12-04 20:50:52.218949', 'rule MALW_FakePyPI
{
meta:
	description = "Identifies fake PyPI Packages."
	author = "@bartblaze"
	reference = "http://www.nbu.gov.sk/skcsirt-sa-20170909-pypi/"
	date = "2017-09"
	tlp = "white"

strings:
	$ = "# Welcome Here! :)"
	$ = "# just toy, no harm :)"
	$ = "[0x76,0x21,0xfe,0xcc,0xee]"

condition:
	all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (91, 'MALW_KeyBase', NULL, '{"tlp": "White", "date": "2019-02", "author": "@bartblaze", "description": "Identifies KeyBase aka Kibex."}', '2020-12-04 20:50:52.426995', 'rule MALW_KeyBase
{
meta:
	description = "Identifies KeyBase aka Kibex."
	author = "@bartblaze"
	date = "2019-02"
	tlp = "White"

strings:
	$s1 = " End:]" ascii wide
	$s2 = "Keystrokes typed:" ascii wide
	$s3 = "Machine Time:" ascii wide
	$s4 = "Text:" ascii wide
	$s5 = "Time:" ascii wide
	$s6 = "Window title:" ascii wide

	$x1 = "&application=" ascii wide
	$x2 = "&clipboardtext=" ascii wide
	$x3 = "&keystrokestyped=" ascii wide
	$x4 = "&link=" ascii wide
	$x5 = "&username=" ascii wide
	$x6 = "&windowtitle=" ascii wide
	$x7 = "=drowssap&" ascii wide
	$x8 = "=emitenihcam&" ascii wide

condition:
	uint16(0) == 0x5a4d and (
		5 of ($s*) or 6 of ($x*) or
		( 4 of ($s*) and 4 of ($x*) )
	)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (92, 'zoxPNG_RAT', NULL, '{"Date": "2014/11/14", "Author": "Novetta Advanced Research Group", "Reference": "http://www.novetta.com/wp-content/uploads/2014/11/ZoxPNG.pdf", "Description": "ZoxPNG RAT, url inside"}', '2020-12-04 20:50:52.528298', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/

import "pe"

rule zoxPNG_RAT
{
    meta:
        Author      = "Novetta Advanced Research Group"
        Date        = "2014/11/14"
        Description = "ZoxPNG RAT, url inside"
        Reference   = "http://www.novetta.com/wp-content/uploads/2014/11/ZoxPNG.pdf"

    strings:
        $url = "png&w=800&h=600&ei=CnJcUcSBL4rFkQX444HYCw&zoom=1&ved=1t:3588,r:1,s:0,i:92&iact=rc&dur=368&page=1&tbnh=184&tbnw=259&start=0&ndsp=20&tx=114&ty=58"

    condition:
        $url
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (93, 'EliseLotusBlossom', NULL, '{"ref": "https://www.paloaltonetworks.com/resources/research/unit42-operation-lotus-blossom.html", "date": "2015-06-23", "author": "Jose Ramon Palanco", "description": "Elise Backdoor Trojan"}', '2020-12-04 20:50:52.75078', 'rule EliseLotusBlossom
{

meta:
    author = "Jose Ramon Palanco"
    date = "2015-06-23"
    description = "Elise Backdoor Trojan"
    ref = "https://www.paloaltonetworks.com/resources/research/unit42-operation-lotus-blossom.html"

strings:
    $magic = { 4d 5a }
    $s1 = "\",Update" wide
    $s2 = "LoaderDLL.dll"
    $s3 = "Kernel32.dll"
    $s4 = "{5947BACD-63BF-4e73-95D7-0C8A98AB95F2}"
    $s5 = "\\Network\\" wide
    $s6 = "0SSSSS"
    $s7 = "441202100205"
    $s8 = "0WWWWW"

condition:
    $magic at 0 and all of ($s*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (94, 'RAT_Orcus', NULL, '{"date": "2017/01", "author": " J from THL <j@techhelplist.com> with thx to MalwareHunterTeam", "maltype": "RAT", "version": 1, "filetype": "memory", "reference": "https://virustotal.com/en/file/0ef747363828342c184303f2d6fbead054200e9c223e5cfc4777cda03006e317/analysis/"}', '2020-12-04 20:50:53.204261', 'rule RAT_Orcus
{

    meta:
        author = " J from THL <j@techhelplist.com> with thx to MalwareHunterTeam"
        date = "2017/01"
        reference = "https://virustotal.com/en/file/0ef747363828342c184303f2d6fbead054200e9c223e5cfc4777cda03006e317/analysis/"
        version = 1
        maltype = "RAT"
        filetype = "memory"

    strings:
        $text01 = "Orcus.CommandManagement"
        $text02 = "Orcus.Commands."
        $text03 = "Orcus.Config."
        $text04 = "Orcus.Connection."
        $text05 = "Orcus.Core."
        $text06 = "Orcus.exe"
        $text07 = "Orcus.Extensions."
        $text08 = "Orcus.InstallationPromptForm"
        $text09 = "Orcus.MainForm."
        $text10 = "Orcus.Native."
        $text11 = "Orcus.Plugins."
        $text12 = "orcus.plugins.dll"
        $text13 = "Orcus.Properties."
        $text14 = "Orcus.Protection."
        $text15 = "Orcus.Share."
        $text16 = "Orcus.Shared"
        $text17 = "Orcus.StaticCommands"
        $text18 = "Orcus.Utilities."
        $text19 = "\\Projects\\Orcus\\Source\\Orcus."
        $text20 = ".orcus.plugins.dll.zip"
        $text21 = ".orcus.shared.dll.zip"
        $text22 = ".orcus.shared.utilities.dll.zip"
        $text23 = ".orcus.staticcommands.dll.zip"
        $text24 = "HvncCommunication"
        $text25 = "HvncAction"
        $text26 = "hvncDesktop"
        $text27 = ".InstallationPromptForm"
        $text28 = "RequestKeyLogCommand"
        $text29 = "get_KeyLogFile"
        $text30 = "LiveKeyloggerCommand"
        $text31 = "ORCUS.STATICCOMMANDS, VERSION="
        $text32 = "PrepareOrcusFileToRemove"
        $text33 = "ConvertFromOrcusValueKind"

    condition:
        13 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (95, 'Kraken_Bot_Sample', '{bot}', '{"date": "2015-05-07", "hash": "798e9f43fc199269a3ec68980eb4d91eb195436d", "score": 90, "author": "Florian Roth", "reference": "https://blog.gdatasoftware.com/blog/article/dissecting-the-kraken.html", "description": "Kraken Bot Sample - file inf.bin"}', '2020-12-04 20:50:53.316389', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Kraken_Bot_Sample : bot {
	meta:
		description = "Kraken Bot Sample - file inf.bin"
		author = "Florian Roth"
		reference = "https://blog.gdatasoftware.com/blog/article/dissecting-the-kraken.html"
		date = "2015-05-07"
		hash = "798e9f43fc199269a3ec68980eb4d91eb195436d"
		score = 90
	strings:
		$s2 = "%s=?getname" fullword ascii
		$s4 = "&COMPUTER=^" fullword ascii
		$s5 = "xJWFwcGRhdGElAA=" fullword ascii /* base64 encoded string ''%appdata%'' */
		$s8 = "JVdJTkRJUi" fullword ascii /* base64 encoded string ''%WINDIR'' */
		$s20 = "btcplug" fullword ascii
	condition:
		uint16(0) == 0x5a4d and all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (96, 'agenttesla_smtp_variant', NULL, '{"date": "2018/2", "author": "J from THL <j@techhelplist.com> with thx to @Fumik0_ !!1!", "maltype": "Stealer", "version": 1, "filetype": "memory", "reference1": "https://www.virustotal.com/#/file/1198865bc928a7a4f7977aaa36af5a2b9d5a949328b89dd87c541758516ad417/detection", "reference2": "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/tspy_negasteal.a", "reference3": "Agent Tesla == negasteal -- @coldshell"}', '2020-12-04 20:50:53.552771', 'rule agenttesla_smtp_variant {

    meta:
        author = "J from THL <j@techhelplist.com> with thx to @Fumik0_ !!1!"
        date = "2018/2"
	reference1 = "https://www.virustotal.com/#/file/1198865bc928a7a4f7977aaa36af5a2b9d5a949328b89dd87c541758516ad417/detection"
	reference2 = "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/tspy_negasteal.a"
	reference3 = "Agent Tesla == negasteal -- @coldshell"
	version = 1
        maltype = "Stealer"
        filetype = "memory"

    strings:
		$a = "type={"
		$b = "hwid={"
		$c = "time={"
		$d = "pcname={"
		$e = "logdata={"
		$f = "screen={"
		$g = "ipadd={"
		$h = "webcam_link={"
		$i = "screen_link={"
		$j = "site_username={"
		$k = "[passwords]"

    condition:
        6 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (97, 'MiniAsp3_mem', '{memory}', '{"author": "chort (@chort0)", "description": "Detect MiniASP3 in memory"}', '2020-12-04 20:50:53.67857', 'rule MiniAsp3_mem : memory {
  meta: author = "chort (@chort0)"
  description = "Detect MiniASP3 in memory"
  strings:
    $pdb = "MiniAsp3\\Release\\MiniAsp.pdb" fullword
    $httpAbout = "http://%s/about.htm" fullword
    $httpResult = "http://%s/result_%s.htm" fullword
    $msgInetFail = "open internet failed…" fullword
    $msgRunErr = "run error!" fullword
    $msgRunOk = "run ok!" fullword
    $msgTimeOutM0 = "time out,change to mode 0" fullword
    $msgCmdNull = "command is null!" fullword
condition:
  ($pdb and (all of ($http*)) and any of ($msg*))
  }

');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (98, 'Powerkatz_DLL_Generic', NULL, '{"date": "2016-02-05", "hash1": "c20f30326fcebad25446cf2e267c341ac34664efad5c50ff07f0738ae2390eae", "hash2": "1e67476281c1ec1cf40e17d7fc28a3ab3250b474ef41cb10a72130990f0be6a0", "hash3": "49e7bac7e0db87bf3f0185e9cf51f2539dbc11384fefced465230c4e5bce0872", "score": 80, "author": "Florian Roth", "reference": "PowerKatz Analysis", "super_rule": 1, "description": "Detects Powerkatz - a Mimikatz version prepared to run in memory via Powershell (overlap with other Mimikatz versions is possible)"}', '2020-12-04 20:50:53.800072', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-05
	Identifier: Powerkatz
*/

rule Powerkatz_DLL_Generic {
	meta:
		description = "Detects Powerkatz - a Mimikatz version prepared to run in memory via Powershell (overlap with other Mimikatz versions is possible)"
		author = "Florian Roth"
		reference = "PowerKatz Analysis"
		date = "2016-02-05"
		super_rule = 1
		score = 80
		hash1 = "c20f30326fcebad25446cf2e267c341ac34664efad5c50ff07f0738ae2390eae"
		hash2 = "1e67476281c1ec1cf40e17d7fc28a3ab3250b474ef41cb10a72130990f0be6a0"
		hash3 = "49e7bac7e0db87bf3f0185e9cf51f2539dbc11384fefced465230c4e5bce0872"
	strings:
		$s1 = "%3u - Directory ''%s'' (*.kirbi)" fullword wide
		$s2 = "%*s  pPublicKey         : " fullword wide
		$s3 = "ad_hoc_network_formed" fullword wide
		$s4 = "<3 eo.oe ~ ANSSI E>" fullword wide
		$s5 = "\\*.kirbi" fullword wide

		$c1 = "kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" fullword wide
		$c2 = "kuhl_m_lsadump_getComputerAndSyskey ; kuhl_m_lsadump_getSyskey KO" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them ) or 2 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (99, 'wineggdrop', '{portscanner,toolkit}', '{"date": "2015-09-05", "author": "Christian Rebischke (@sh1bumi)", "family": "Hackingtool/Portscanner", "description": "Rules for TCP Portscanner VX.X by WinEggDrop", "in_the_wild": true}', '2020-12-04 20:50:54.064576', 'rule wineggdrop : portscanner toolkit
{
    meta:
        author = "Christian Rebischke (@sh1bumi)"
        date = "2015-09-05"
        description = "Rules for TCP Portscanner VX.X by WinEggDrop"
        in_the_wild = true
        family = "Hackingtool/Portscanner"

    strings:
        $a = { 54 43 50 20 50 6f 72 74 20 53 63 61 6e 6e 65 72
               20 56 3? 2e 3? 20 42 79 20 57 69 6e 45 67 67 44
               72 6f 70 0a }
        $b = "Result.txt"
        $c = "Usage:   %s TCP/SYN StartIP [EndIP] Ports [Threads] [/T(N)] [/(H)Banner] [/Save]\n"

    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D

        and

        //check for wineggdrop specific strings
        $a and $b and $c
}

');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (100, 'Retefe', NULL, '{"author": "bartblaze", "description": "Retefe"}', '2020-12-04 20:50:54.803083', '
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Retefe
{
meta:
	author = "bartblaze"
	description = "Retefe"
strings:
	$string0 = "01050000"
	$string1 = "00000000"
	$string2 = "5061636b61676500"
	$string3 = "000000000000000000000000000000000000000000000000000000000000000000000000000000"
	$string4 = "{\\stylesheet{ Normal;}{\\s1 heading 1;}{\\s2 heading 2;}}"
	$string5 = "02000000"
condition:
	5 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (101, 'legion_777', NULL, '{"ref": "https://github.com/Daxda/malware-analysis/tree/master/malware_samples/legion", "date": "2016/6/6", "author": "Daxda (https://github.com/Daxda)", "sample": "SHA256: 14d22359e76cf63bf17268cad24bac03663c8b2b8028b869f5cec10fe3f75548", "category": "Ransomware", "description": "Detects an UPX-unpacked .777 ransomware binary."}', '2020-12-04 20:50:54.919469', 'rule legion_777
{
    meta:
        author = "Daxda (https://github.com/Daxda)"
        date = "2016/6/6"
        description = "Detects an UPX-unpacked .777 ransomware binary."
        ref = "https://github.com/Daxda/malware-analysis/tree/master/malware_samples/legion"
        category = "Ransomware"
        sample = "SHA256: 14d22359e76cf63bf17268cad24bac03663c8b2b8028b869f5cec10fe3f75548"

    strings:
        $s1 = "http://tuginsaat.com/wp-content/themes/twentythirteen/stats.php"
        $s2 = "read_this_file.txt" wide // Ransom note filename.
        $s3 = "seven_legion@india.com" // Part of the format string used to rename files.
        $s4 = {46 4f 52 20 44 45 43 52 59 50 54 20 46 49 4c 45 53 0d 0a 53 45 4e 44 20 4f
               4e 45 20 46 49 4c 45 20 49 4e 20 45 2d 4d 41 49 4c 0d 0a 73 65 76 65 6e 5f
               6c 65 67 69 6f 6e 40 69 6e 64 69 61 2e 63 6f 6d } // Ransom note content.
        $s5 = "%s._%02i-%02i-%02i-%02i-%02i-%02i_$%s$.777" // Renaming format string.

    condition:
        4 of ($s*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (102, 'Fareit_Trojan_Oct15', NULL, '{"date": "2015-10-18", "hash1": "230ca0beba8ae712cfe578d2b8ec9581ce149a62486bef209b04eb11d8c088c3", "hash2": "3477d6bfd8313d37fedbd3d6ba74681dd7cb59040cabc2991655bdce95a2a997", "hash3": "408fa0bd4d44de2940605986b554e8dab42f5d28a6a525b4bc41285e37ab488d", "hash4": "76669cbe6a6aac4aa52dbe9d2e027ba184bf3f0b425f478e8c049637624b5dae", "hash5": "9486b73eac92497e703615479d52c85cfb772b4ca6c846ef317729910e7c545f", "hash6": "c3300c648aebac7bf1d90f58ea75660c78604410ca0fa705d3b8ec1e0a45cdd9", "hash7": "ff83e9fcfdec4ffc748e0095391f84a8064ac958a274b9684a771058c04cb0fa", "score": 80, "author": "Florian Roth", "reference": "http://goo.gl/5VYtlU", "super_rule": 1, "description": "Detects Fareit Trojan from Sep/Oct 2015 Wave"}', '2020-12-04 20:50:55.036008', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-10-18
	Identifier: Fareit Oct 2015
*/

rule Fareit_Trojan_Oct15 {
	meta:
		description = "Detects Fareit Trojan from Sep/Oct 2015 Wave"
		author = "Florian Roth"
		reference = "http://goo.gl/5VYtlU"
		date = "2015-10-18"
		score = 80
		super_rule = 1
		hash1 = "230ca0beba8ae712cfe578d2b8ec9581ce149a62486bef209b04eb11d8c088c3"
		hash2 = "3477d6bfd8313d37fedbd3d6ba74681dd7cb59040cabc2991655bdce95a2a997"
		hash3 = "408fa0bd4d44de2940605986b554e8dab42f5d28a6a525b4bc41285e37ab488d"
		hash4 = "76669cbe6a6aac4aa52dbe9d2e027ba184bf3f0b425f478e8c049637624b5dae"
		hash5 = "9486b73eac92497e703615479d52c85cfb772b4ca6c846ef317729910e7c545f"
		hash6 = "c3300c648aebac7bf1d90f58ea75660c78604410ca0fa705d3b8ec1e0a45cdd9"
		hash7 = "ff83e9fcfdec4ffc748e0095391f84a8064ac958a274b9684a771058c04cb0fa"
	strings:
		$s1 = "ebai.exe" fullword wide
		$s2 = "Origina" fullword wide
	condition:
		uint16(0) == 0x5a4d and $s1 in (0..30000) and $s2 in (0..30000)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (103, 'lateral_movement', NULL, '{"date": "3/12/2014", "author": "https://github.com/reed1713", "description": "methodology sig looking for signs of lateral movement"}', '2020-12-04 20:50:55.247234', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule lateral_movement
{
	meta:
		date = "3/12/2014"
		author = "https://github.com/reed1713"
    description = "methodology sig looking for signs of lateral movement"
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="PsExec.exe"

		$type1="Microsoft-Windows-Security-Auditing"
		$eventid1="4688"
		$data1="Windows\\System32\\net.exe"

		$type2="Microsoft-Windows-Security-Auditing"
		$eventid2="4688"
		$data2="Windows\\System32\\at.exe"
	condition:
		($type and $eventid and $data) or ($type1 and $eventid1 and $data1) or ($type2 and $eventid2 and $data2)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (104, 'PoS_Malware_fastpos', '{FastPOS,POS,keylogger}', '{"date": "2016-05-18", "author": "Trend Micro, Inc.", "reference": "http://documents.trendmicro.com/assets/fastPOS-quick-and-easy-credit-card-theft.pdf", "description": "Used to detect FastPOS keyloggger + scraper", "sample_filetype": "exe"}', '2020-12-04 20:50:55.353506', '
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule PoS_Malware_fastpos : FastPOS POS keylogger
{
meta:
author = "Trend Micro, Inc."
date = "2016-05-18"
description = "Used to detect FastPOS keyloggger + scraper"
reference = "http://documents.trendmicro.com/assets/fastPOS-quick-and-easy-credit-card-theft.pdf"
sample_filetype = "exe"
strings:
$string1 = "uniqyeidclaxemain"
$string2 = "http://%s/cdosys.php"
$string3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
$string4 = "\\The Hook\\Release\\The Hook.pdb" nocase
condition:
all of ($string*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (112, 'GoziRule', '{Gozi,Family}', '{"ref": "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html", "author": "CCN-CERT", "version": "1.0", "description": "Win32.Gozi"}', '2020-12-04 20:50:57.310473', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule GoziRule : Gozi Family {
meta:
    description = "Win32.Gozi"
    author = "CCN-CERT"
    version = "1.0"
    ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
strings:
    $ = {63 00 6F 00 6F 00 6B 00 69 00 65 00 73 00 2E 00 73 00 71 00 6C 00 69 00 74 00 65 00 2D 00 6A 00 6F 00 75 00 72 00 6E 00 61 00 6C 00 00 00 4F 50 45 52 41 2E 45 58 45 00}
condition:
    all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (105, 'LogPOS', NULL, '{"md5": "af13e7583ed1b27c4ae219e344a37e2b", "author": "Morphick Security", "description": "Detects Versions of LogPOS"}', '2020-12-04 20:50:55.929672', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"
rule LogPOS
{
    meta:
        author = "Morphick Security"
        description = "Detects Versions of LogPOS"
        md5 = "af13e7583ed1b27c4ae219e344a37e2b"
    strings:
        $mailslot = "\\\\.\\mailslot\\LogCC"
        $get = "GET /%s?encoding=%c&t=%c&cc=%I64d&process="
        //64A130000000      mov eax, dword ptr fs:[0x30]
        //8B400C        mov eax, dword ptr [eax + 0xc]
        //8B401C        mov eax, dword ptr [eax + 0x1c]
        //8B4008        mov eax, dword ptr [eax + 8]
        $sc = {64 A1 30 00 00 00 8B 40 0C 8B 40 1C 8B 40 08 }
    condition:
        $sc and 1 of ($mailslot,$get)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (106, 'lost_door', '{Trojan}', '{"date": "23/02/2013", "author": "Kevin Falcoz", "description": "Lost Door"}', '2020-12-04 20:50:56.037047', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule lost_door : Trojan
{
	meta:
		author="Kevin Falcoz"
		date="23/02/2013"
		description="Lost Door"

	strings:
		$signature1={45 44 49 54 5F 53 45 52 56 45 52} /*EDIT_SERVER*/

	condition:
		$signature1
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (107, 'xRAT', '{RAT}', '{"ref": "http://malwareconfig.com/stats/xRat", "date": "2014/04", "author": " Kevin Breen <kevin@techanarchy.net>", "maltype": "Remote Access Trojan", "filetype": "exe"}', '2020-12-04 20:50:56.14618', 'rule xRAT : RAT
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/xRat"
        maltype = "Remote Access Trojan"
        filetype = "exe"

    strings:
        $v1a = "DecodeProductKey"
        $v1b = "StartHTTPFlood"
        $v1c = "CodeKey"
        $v1d = "MESSAGEBOX"
        $v1e = "GetFilezillaPasswords"
        $v1f = "DataIn"
        $v1g = "UDPzSockets"
        $v1h = {52 00 54 00 5F 00 52 00 43 00 44 00 41 00 54 00 41}

        $v2a = "<URL>k__BackingField"
        $v2b = "<RunHidden>k__BackingField"
        $v2c = "DownloadAndExecute"
        $v2d = "-CHECK & PING -n 2 127.0.0.1 & EXIT" wide
        $v2e = "england.png" wide
        $v2f = "Showed Messagebox" wide
    condition:
        all of ($v1*) or all of ($v2*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (108, 'xRAT20', '{RAT}', '{"date": "2015-08-20", "hash0": "cda610f9cba6b6242ebce9f31faf5d9c", "hash1": "60d7b0d2dfe937ac6478807aa7043525", "hash2": "d1b577fbfd25cc5b873b202cfe61b5b8", "hash3": "1820fa722906569e3f209d1dab3d1360", "hash4": "8993b85f5c138b0afacc3ff04a2d7871", "hash5": "0c231ed8a800b0f17f897241f1d5f4e3", "hash8": "2c198e3e0e299a51e5d955bb83c62a5e", "author": "Rottweiler", "maltype": "Remote Access Trojan", "description": "Identifies xRAT 2.0 samples", "yaragenerator": "https://github.com/Xen0ph0n/YaraGenerator", "sample_filetype": "exe"}', '2020-12-04 20:50:56.360133', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule xRAT20 : RAT
{
meta:
	author = "Rottweiler"
	date = "2015-08-20"
	description = "Identifies xRAT 2.0 samples"
	maltype = "Remote Access Trojan"
	hash0 = "cda610f9cba6b6242ebce9f31faf5d9c"
	hash1 = "60d7b0d2dfe937ac6478807aa7043525"
	hash2 = "d1b577fbfd25cc5b873b202cfe61b5b8"
	hash3 = "1820fa722906569e3f209d1dab3d1360"
	hash4 = "8993b85f5c138b0afacc3ff04a2d7871"
	hash5 = "0c231ed8a800b0f17f897241f1d5f4e3"
	hash1 = "60d7b0d2dfe937ac6478807aa7043525"
	hash8 = "2c198e3e0e299a51e5d955bb83c62a5e"
	sample_filetype = "exe"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "GetDirectory: File not found" wide
	$string1 = "<>m__Finally8"
	$string2 = "Secure"
	$string3 = "ReverseProxyClient"
	$string4 = "DriveDisplayName"
	$string5 = "<IsError>k__BackingField"
	$string6 = "set_InstallPath"
	$string7 = "memcmp"
	$string8 = "urlHistory"
	$string9 = "set_AllowAutoRedirect"
	$string10 = "lpInitData"
	$string11 = "reader"
	$string12 = "<FromRawDataGlobal>d__f"
	$string13 = "mq.png" wide
	$string14 = "remove_KeyDown"
	$string15 = "ProtectedData"
	$string16 = "m_hotkeys"
	$string17 = "get_Hour"
	$string18 = "\\mozglue.dll" wide
condition:
	18 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (109, 'stampado_overlay', NULL, '{"md5": "6337f0938e4a9c0ef44ab99deb0ef466", "date": "2016-07", "author": "Fernando Merces, FTR, Trend Micro", "reference": "", "description": "Catches Stampado samples looking for \\\\r at the beginning of PE overlay section"}', '2020-12-04 20:50:56.467658', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule stampado_overlay
{
meta:
description = "Catches Stampado samples looking for \\r at the beginning of PE overlay section"
reference = ""
author = "Fernando Merces, FTR, Trend Micro"
date = "2016-07"
md5 = "a393b9536a1caa34914636d3da7378b5"
md5 = "dbf3707a9cd090853a11dda9cfa78ff0"
md5 = "dd5686ca7ec28815c3cf3ed3dbebdff2"
md5 = "6337f0938e4a9c0ef44ab99deb0ef466"

condition:
pe.characteristics == 0x122 and
pe.number_of_sections == 5 and
pe.imports("VERSION.dll", "VerQueryValueW") and uint8(pe.sections[4].raw_data_offset + pe.sections[4].raw_data_size) == 0x0d

}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (110, 'VirutFileInfector', NULL, '{"data": "2017/08/04", "author": "D00RT <@D00RT_RM>", "reference": "http://reversingminds-blog.logdown.com", "description": "Virut (unknown version) fileinfector detection", "infected_sample1": "5755f09d445a5dcab3ea92d978c7c360", "infected_sample2": "2766e8e78ee10264cf1a3f5f4a16ff00"}', '2020-12-04 20:50:56.583295', 'rule VirutFileInfector
{
	meta:
    	author = "D00RT <@D00RT_RM>"
    	data = "2017/08/04"

        description = "Virut (unknown version) fileinfector detection"
        reference = "http://reversingminds-blog.logdown.com"

        infected_sample1 = "5755f09d445a5dcab3ea92d978c7c360"
        infected_sample2 = "68e508108ed94c8c391c70ef1d15e0f8"
        infected_sample2 = "2766e8e78ee10264cf1a3f5f4a16ff00"

	strings:
    	$sign = { F9 E8 22 00 00 00 ?? 31 EB 56 }
        $func = { 52 C1 E9 1D 68 31 D4 00 00 58 5A 81 C1 94 01 00 00 80 4D 00 F0 89 6C 24 04 F7 D1 81 6C 24 04 }

    condition:
    	$sign and $func
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (111, 'PoetRat_Doc', NULL, '{"Data": "6th May 2020", "Author": "Nishan Maharjan", "Description": "A yara rule to catch PoetRat Word Document"}', '2020-12-04 20:50:56.879273', 'rule PoetRat_Doc
{
    meta:
        Author = "Nishan Maharjan"
        Description = "A yara rule to catch PoetRat Word Document"
        Data = "6th May 2020"
    strings:
        $pythonRegEx = /(\.py$|\.pyc$|\.pyd$|Python)/  // checking for python strings

        // Python file strings in the word documents
        $pythonFile1 = "launcher.py"
        $zipFile = "smile.zip"
        $pythonFile2 = "smile_funs.py"
        $pythonFile3 = "frown.py"
        $pythonFile4 = "backer.py"
        $pythonFile5 = "smile.py"
        $pythonFile6 = "affine.py"

        // dlls and cmd strings
        $dlls = /\.dll/
        $cmd = "cmd"
        $exe = ".exe"
    condition:
    all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (217, 'xbot007', '{android}', '{"reference": "https://github.com/maldroid/maldrolyzer/blob/master/plugins/xbot007.py"}', '2020-12-04 20:51:23.593424', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/


rule xbot007 : android
{
	meta:
		reference = "https://github.com/maldroid/maldrolyzer/blob/master/plugins/xbot007.py"

	strings:
		$a = "xbot007"

	condition:
		any of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (113, 'Scieron', NULL, '{"ref": "http://www.symantec.com/connect/tr/blogs/scarab-attackers-took-aim-select-russian-targets-2012", "date": "22.01.15", "author": "Symantec Security Response"}', '2020-12-04 20:50:57.415024', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Scieron
{
    meta:
        author = "Symantec Security Response"
        ref = "http://www.symantec.com/connect/tr/blogs/scarab-attackers-took-aim-select-russian-targets-2012"
        date = "22.01.15"

    strings:
        // .text:10002069 66 83 F8 2C                       cmp     ax, '',''
        // .text:1000206D 74 0C                             jz      short loc_1000207B
        // .text:1000206F 66 83 F8 3B                       cmp     ax, '';''
        // .text:10002073 74 06                             jz      short loc_1000207B
        // .text:10002075 66 83 F8 7C                       cmp     ax, ''|''
        // .text:10002079 75 05                             jnz     short loc_10002080
        $code1 = {66 83 F? 2C 74 0C 66 83 F? 3B 74 06 66 83 F? 7C 75 05}

        // .text:10001D83 83 F8 09                          cmp     eax, 9          ; switch 10 cases
        // .text:10001D86 0F 87 DB 00 00 00                 ja      loc_10001E67    ; jumptable 10001D8C default case
        // .text:10001D8C FF 24 85 55 1F 00+                jmp     ds:off_10001F55[eax*4] ; switch jump
        $code2 = {83 F? 09 0F 87 ?? 0? 00 00 FF 24}

        $str1  = "IP_PADDING_DATA" wide ascii
        $str2  = "PORT_NUM" wide ascii

    condition:
        all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (114, 'GEN_PowerShell', NULL, '{"author": "https://github.com/interleaved", "description": "Generic PowerShell Malware Rule"}', '2020-12-04 20:50:57.528448', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule GEN_PowerShell
{

    meta:
        description = "Generic PowerShell Malware Rule"
        author = "https://github.com/interleaved"

    strings:
        $s1 = "powershell"
        $s2 = "-ep bypass" nocase
        $s3 = "-nop" nocase
        $s10 = "-executionpolicy bypass" nocase
        $s4 = "-win hidden" nocase
        $s5 = "-windowstyle hidden" nocase
        $s11 = "-w hidden" nocase
        /*$s6 = "-noni" fullword ascii*/
        /*$s7 = "-noninteractive" fullword ascii*/
        $s8 = "-enc" nocase
        $s9 = "-encodedcommand" nocase

    condition:
        $s1 and (($s2 or $s3 or $s10) and ($s4 or $s5 or $s11) and ($s8 or $s9))
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (115, 'Sakurel_backdoor', NULL, '{"ref": "https://github.com/reed1713", "maltype": "Sakurel backdoor", "reference": "http://www.microsoft.com/security/portal/threat/encyclopedia/entry.aspx?Name=Trojan:Win32/Sakurel.A#tab=2", "description": "malware creates a process in the temp directory and performs the sysprep UAC bypass method."}', '2020-12-04 20:50:57.880666', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule Sakurel_backdoor
{
	meta:
		maltype = "Sakurel backdoor"
    ref = "https://github.com/reed1713"
		reference = "http://www.microsoft.com/security/portal/threat/encyclopedia/entry.aspx?Name=Trojan:Win32/Sakurel.A#tab=2"
		description = "malware creates a process in the temp directory and performs the sysprep UAC bypass method."
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="Windows\\System32\\sysprep\\sysprep.exe" nocase

		$type1="Microsoft-Windows-Security-Auditing"
		$eventid1="4688"
		$data1="AppData\\Local\\Temp\\MicroMedia\\MediaCenter.exe" nocase
	condition:
		all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (116, 'Tinba2', '{banking}', '{"date": "2015/11/07", "hash1": "c7f662594f07776ab047b322150f6ed0", "hash2": "dc71ef1e55f1ddb36b3c41b1b95ae586", "hash3": "b788155cb82a7600f2ed1965cffc1e88", "author": "n3sfox <n3sfox@gmail.com>", "filetype": "memory", "reference": "https://securityintelligence.com/tinba-malware-reloaded-and-attacking-banks-around-the-world", "description": "Tinba 2 (DGA) banking trojan"}', '2020-12-04 20:50:58.115461', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/

rule Tinba2 : banking {
        meta:
                author = "n3sfox <n3sfox@gmail.com>"
                date = "2015/11/07"
                description = "Tinba 2 (DGA) banking trojan"
                reference = "https://securityintelligence.com/tinba-malware-reloaded-and-attacking-banks-around-the-world"
                filetype = "memory"
                hash1 = "c7f662594f07776ab047b322150f6ed0"
                hash2 = "dc71ef1e55f1ddb36b3c41b1b95ae586"
                hash3 = "b788155cb82a7600f2ed1965cffc1e88"

        strings:
                $str1 = "MapViewOfFile"
                $str2 = "OpenFileMapping"
                $str3 = "NtCreateUserProcess"
                $str4 = "NtQueryDirectoryFile"
                $str5 = "RtlCreateUserThread"
                $str6 = "DeleteUrlCacheEntry"
                $str7 = "PR_Read"
                $str8 = "PR_Write"
                $pubkey = "BEGIN PUBLIC KEY"
                $code1 = {50 87 44 24 04 6A ?? E8}

        condition:
                all of ($str*) and $pubkey and $code1
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (117, 'TidePool_Malware', NULL, '{"date": "2016-05-24", "hash1": "9d0a47bdf00f7bd332ddd4cf8d95dd11ebbb945dda3d72aac512512b48ad93ba", "hash2": "67c4e8ab0f12fae7b4aeb66f7e59e286bd98d3a77e5a291e8d58b3cfbc1514ed", "hash3": "2252dcd1b6afacde3f94d9557811bb769c4f0af3cb7a48ffe068d31bb7c30e18", "hash4": "38f2c86041e0446730479cdb9c530298c0c4936722975c4e7446544fd6dcac9f", "hash5": "9d0a47bdf00f7bd332ddd4cf8d95dd11ebbb945dda3d72aac512512b48ad93ba", "author": "Florian Roth", "reference": "http://goo.gl/m2CXWR", "description": "Detects TidePool malware mentioned in Ke3chang report by Palo Alto Networks"}', '2020-12-04 20:50:58.580444', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-05-24
	Identifier: TidePool (Ke3chang)
*/

/* APTKe3chang */

rule TidePool_Malware
{

    meta:
        description = "Detects TidePool malware mentioned in Ke3chang report by Palo Alto Networks"
        author = "Florian Roth"
        reference = "http://goo.gl/m2CXWR"
        date = "2016-05-24"
        hash1 = "9d0a47bdf00f7bd332ddd4cf8d95dd11ebbb945dda3d72aac512512b48ad93ba"
        hash2 = "67c4e8ab0f12fae7b4aeb66f7e59e286bd98d3a77e5a291e8d58b3cfbc1514ed"
        hash3 = "2252dcd1b6afacde3f94d9557811bb769c4f0af3cb7a48ffe068d31bb7c30e18"
        hash4 = "38f2c86041e0446730479cdb9c530298c0c4936722975c4e7446544fd6dcac9f"
        hash5 = "9d0a47bdf00f7bd332ddd4cf8d95dd11ebbb945dda3d72aac512512b48ad93ba"

    strings:
        $x1 = "Content-Disposition: form-data; name=\"m1.jpg\"" fullword ascii
        $x2 = "C:\\PROGRA~2\\IEHelper\\mshtml.dll" fullword wide
        $x3 = "C:\\DOCUME~1\\ALLUSE~1\\IEHelper\\mshtml.dll" fullword wide
        $x4 = "IEComDll.dat" fullword ascii
        $s1 = "Content-Type: multipart/form-data; boundary=----=_Part_%x" fullword wide
        $s2 = "C:\\Windows\\System32\\rundll32.exe" fullword wide
        $s3 = "network.proxy.socks_port\", " fullword ascii

    condition:
        ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) ) ) or ( 4 of them )
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (118, 'pony', NULL, '{"date": "2014-08-16", "author": "Brian Wallace @botnet_hunter", "description": "Identify Pony", "author_email": "bwall@ballastsecurity.net"}', '2020-12-04 20:50:58.685546', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
rule pony {
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-08-16"
        description = "Identify Pony"
	strings:
    	$s1 = "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"
    	$s2 = "YUIPWDFILE0YUIPKDFILE0YUICRYPTED0YUI1.0"
    	$s3 = "POST %s HTTP/1.0"
    	$s4 = "Accept-Encoding: identity, *;q=0"

    	//$useragent1 = "Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)"
    	//$useragent2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/5.0)"
    condition:
        $s1 and $s2 and $s3 and $s4
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (119, 'alina', NULL, '{"date": "2014-08-09", "author": "Brian Wallace @botnet_hunter", "description": "Identify Alina", "author_email": "bwall@ballastsecurity.net"}', '2020-12-04 20:50:58.789215', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
rule alina
{
	meta:
		author = "Brian Wallace @botnet_hunter"
		author_email = "bwall@ballastsecurity.net"
		date = "2014-08-09"
		description = "Identify Alina"
	strings:
		$s1 = "Alina v1.0"
		$s2 = "POST"
		$s3 = "1[0-2])[0-9]"

	condition:
        	all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (120, 'jRAT_conf', '{RAT}', '{"date": "2013-10-11", "ref1": "https://github.com/MalwareLu/config_extractor/blob/master/config_jRAT.py", "ref2": "http://www.ghettoforensics.com/2013/10/dumping-malware-configuration-data-from.html", "author": "Jean-Philippe Teissier / @Jipe_", "version": "1.0", "filetype": "memory", "description": "jRAT configuration"}', '2020-12-04 20:50:58.998952', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"
rule jRAT_conf : RAT
{
	meta:
		description = "jRAT configuration"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-10-11"
		filetype = "memory"
		version = "1.0"
		ref1 = "https://github.com/MalwareLu/config_extractor/blob/master/config_jRAT.py"
		ref2 = "http://www.ghettoforensics.com/2013/10/dumping-malware-configuration-data-from.html"

	strings:
		$a = /port=[0-9]{1,5}SPLIT/

	condition:
		$a
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (121, 'volgmer', NULL, '{"ref": "https://www.us-cert.gov/ncas/alerts/TA17-318B", "description": "Malformed User Agent"}', '2020-12-04 20:50:59.210561', 'rule volgmer
{
meta:
    description = "Malformed User Agent"
    ref = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
strings:
    $s = "Mozillar/"
condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $s
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (122, 'suspicious_packer_section', '{packer,PE}', '{"date": "2016/10/21", "author": "@j0sm1", "filetype": "binary", "reference": "http://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/", "description": "The packer/protector section names/keywords"}', '2020-12-04 20:50:59.317931', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule suspicious_packer_section : packer PE {

    meta:

        author = "@j0sm1"
        date = "2016/10/21"
        description = "The packer/protector section names/keywords"
        reference = "http://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/"
        filetype = "binary"

    strings:

        $s1 = ".aspack" wide ascii
        $s2 = ".adata" wide ascii
        $s3 = "ASPack" wide ascii
        $s4 = ".ASPack" wide ascii
        $s5 = ".ccg" wide ascii
        $s6 = "BitArts" wide ascii
        $s7 = "DAStub" wide ascii
        $s8 = "!EPack" wide ascii
        $s9 = "FSG!" wide ascii
        $s10 = "kkrunchy" wide ascii
        $s11 = ".mackt" wide ascii
        $s12 = ".MaskPE" wide ascii
        $s13 = "MEW" wide ascii
        $s14 = ".MPRESS1" wide ascii
        $s15 = ".MPRESS2" wide ascii
        $s16 = ".neolite" wide ascii
        $s17 = ".neolit" wide ascii
        $s18 = ".nsp1" wide ascii
        $s19 = ".nsp2" wide ascii
        $s20 = ".nsp0" wide ascii
        $s21 = "nsp0" wide ascii
        $s22 = "nsp1" wide ascii
        $s23 = "nsp2" wide ascii
        $s24 = ".packed" wide ascii
        $s25 = "pebundle" wide ascii
        $s26 = "PEBundle" wide ascii
        $s27 = "PEC2TO" wide ascii
        $s28 = "PECompact2" wide ascii
        $s29 = "PEC2" wide ascii
        $s30 = "pec1" wide ascii
        $s31 = "pec2" wide ascii
        $s32 = "PEC2MO" wide ascii
        $s33 = "PELOCKnt" wide ascii
        $s34 = ".perplex" wide ascii
        $s35 = "PESHiELD" wide ascii
        $s36 = ".petite" wide ascii
        $s37 = "ProCrypt" wide ascii
        $s38 = ".RLPack" wide ascii
        $s39 = "RCryptor" wide ascii
        $s40 = ".RPCrypt" wide ascii
        $s41 = ".sforce3" wide ascii
        $s42 = ".spack" wide ascii
        $s43 = ".svkp" wide ascii
        $s44 = "Themida" wide ascii
        $s45 = ".Themida" wide ascii
        $s46 = ".packed" wide ascii
        $s47 = ".Upack" wide ascii
        $s48 = ".ByDwing" wide ascii
        $s49 = "UPX0" wide ascii
        $s50 = "UPX1" wide ascii
        $s51 = "UPX2" wide ascii
        $s52 = ".UPX0" wide ascii
        $s53 = ".UPX1" wide ascii
        $s54 = ".UPX2" wide ascii
        $s55 = ".vmp0" wide ascii
        $s56 = ".vmp1" wide ascii
        $s57 = ".vmp2" wide ascii
        $s58 = "VProtect" wide ascii
        $s59 = "WinLicen" wide ascii
        $s60 = "WWPACK" wide ascii
        $s61 = ".yP" wide ascii
        $s62 = ".y0da" wide ascii
        $s63 = "UPX!" wide ascii

    condition:
        // DOS stub signature                           PE signature
        uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (
            for any of them : ( $ in (0..1024) )
        )
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (123, 'CAP_HookExKeylogger', NULL, '{"author": "Brian C. Bell -- @biebsmalwareguy", "reference": "https://github.com/DFIRnotes/rules/blob/master/CAP_HookExKeylogger.yar"}', '2020-12-04 20:50:59.434722', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule CAP_HookExKeylogger
{

meta:
    author = "Brian C. Bell -- @biebsmalwareguy"
    reference = "https://github.com/DFIRnotes/rules/blob/master/CAP_HookExKeylogger.yar"

    strings:
    $str_Win32hookapi = "SetWindowsHookEx" nocase
    $str_Win32llkey = "WH_KEYBOARD_LL" nocase
    $str_Win32key = "WH_KEYBOARD" nocase

    condition:
        2 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (124, 'Molerats_certs', NULL, '{"Date": "2013/08/23", "Author": "FireEye Labs", "Reference": "https://www.fireeye.com/blog/threat-research/2013/08/operation-molerats-middle-east-cyber-attacks-using-poison-ivy.html", "Description": "this rule detections code signed with certificates used by the Molerats actor"}', '2020-12-04 20:50:59.541571', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Molerats_certs
{

    meta:
        Author      = "FireEye Labs"
        Date        = "2013/08/23"
        Description = "this rule detections code signed with certificates used by the Molerats actor"
        Reference   = "https://www.fireeye.com/blog/threat-research/2013/08/operation-molerats-middle-east-cyber-attacks-using-poison-ivy.html"

    strings:
        $cert1 = { 06 50 11 A5 BC BF 83 C0 93 28 16 5E 7E 85 27 75 }
        $cert2 = { 03 e1 e1 aa a5 bc a1 9f ba 8c 42 05 8b 4a bf 28 }
        $cert3 = { 0c c0 35 9c 9c 3c da 00 d7 e9 da 2d c6 ba 7b 6d }

    condition:
        1 of ($cert*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (125, 'LuaBot', '{MALW}', '{"MD5": "9df3372f058874fa964548cbb74c74bf", "SHA1": "89226865501ee7d399354656d870b4a9c02db1d3", "date": "2017-06-07", "ref1": "http://blog.malwaremustdie.org/2016/09/mmd-0057-2016-new-elf-botnet-linuxluabot.html", "author": "Joan Soriano / @joanbtl", "version": "1.0", "description": "LuaBot"}', '2020-12-04 20:50:59.650797', 'rule LuaBot : MALW
{
        meta:
                description = "LuaBot"
                author = "Joan Soriano / @joanbtl"
                date = "2017-06-07"
                version = "1.0"
                MD5 = "9df3372f058874fa964548cbb74c74bf"
                SHA1 = "89226865501ee7d399354656d870b4a9c02db1d3"
                ref1 = "http://blog.malwaremustdie.org/2016/09/mmd-0057-2016-new-elf-botnet-linuxluabot.html"

        strings:
                $a = "LUA_PATH"
                $b = "Hi. Happy reversing, you can mail me: luabot@yandex.ru"
                $c = "/tmp/lua_XXXXXX"
                $d = "NOTIFY"
                $e = "UPDATE"

        condition:
                all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (126, 'yordanyan_activeagent', NULL, '{"date": "2018-10-04", "author": "J from THL <j@techhelplist.com>", "maltype": "Botnet", "filetype": "memory", "reference1": "https://www.virustotal.com/#/file/a2e34bfd5a9789837bc2d580e87ec11b9f29c4a50296ef45b06e3895ff399746/detection", "reference2": "ETPRO TROJAN Win32.ActiveAgent CnC Create", "description": "Memory string yara for Yordanyan ActiveAgent"}', '2020-12-04 20:51:00.042897', '
rule yordanyan_activeagent {
	meta:
		description = "Memory string yara for Yordanyan ActiveAgent"
		author = "J from THL <j@techhelplist.com>"
		reference1 = "https://www.virustotal.com/#/file/a2e34bfd5a9789837bc2d580e87ec11b9f29c4a50296ef45b06e3895ff399746/detection"
		reference2 = "ETPRO TROJAN Win32.ActiveAgent CnC Create"
		date = "2018-10-04"
		maltype = "Botnet"
		filetype = "memory"

	strings:
		// the wide strings are 16bit bigendian strings in memory. strings -e b memdump.file
		$s01 = "I''m KeepRunner!" wide
		$s02 = "I''m Updater!" wide
		$s03 = "Starting Download..." wide
		$s04 = "Download Complete!" wide
		$s05 = "Running New Agent and terminating updater!" wide
		$s06 = "Can''t Run downloaded file!" wide
		$s07 = "Retrying download and run!" wide
		$s08 = "Can''t init Client." wide
		$s09 = "Client initialised -" wide
		$s10 = "Client not found!" wide
		$s11 = "Client signed." wide
		$s12 = "GetClientData" wide
		$s13 = "&counter=" wide
		$s14 = "&agent_file_version=" wide
		$s15 = "&agent_id=" wide
		$s16 = "mac_address=" wide
		$s17 = "Getting Attachments" wide
		$s18 = "public_name" wide
		$s19 = "Yor agent id =" wide
		$s20 = "Yor agent version =" wide
		$s21 = "Last agent version =" wide
		$s22 = "Agent is last version." wide
		$s23 = "Updating Agent" wide
		$s24 = "Terminating RunKeeper" wide
		$s25 = "Terminating RunKeeper: Done" wide
		$s26 = "ActiveAgent" ascii
		$s27 = "public_name" ascii

	condition:
		15 of them

}


');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (127, 'FVEY_ShadowBrokers_Jan17_Screen_Strings', NULL, '{"date": "2017-01-08", "author": "Florian Roth", "reference": "https://bit.no.com:43110/theshadowbrokers.bit/post/message7/", "description": "Detects strings derived from the ShadowBroker''s leak of Windows tools/exploits"}', '2020-12-04 20:51:00.155225', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-08
   Identifier: ShadowBroker Screenshot Rules
*/

/* Rule Set ----------------------------------------------------------------- */

rule FVEY_ShadowBrokers_Jan17_Screen_Strings
{

   meta:
      description = "Detects strings derived from the ShadowBroker''s leak of Windows tools/exploits"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message7/"
      date = "2017-01-08"

   strings:
      $x1 = "Danderspritz" ascii wide fullword
      $x2 = "DanderSpritz" ascii wide fullword
      $x3 = "PeddleCheap" ascii wide fullword
      $x4 = "ChimneyPool Addres" ascii wide fullword
      $a1 = "Getting remote time" fullword ascii
      $a2 = "RETRIEVED" fullword ascii
      $b1 = "Added Ops library to Python search path" fullword ascii
      $b2 = "target: z0.0.0.1" fullword ascii
      $c1 = "Psp_Avoidance" fullword ascii
      $c2 = "PasswordDump" fullword ascii
      $c3 = "InjectDll" fullword ascii
      $c4 = "EventLogEdit" fullword ascii
      $c5 = "ProcessModify" fullword ascii
      $d1 = "Mcl_NtElevation" fullword ascii wide
      $d2 = "Mcl_NtNativeApi" fullword ascii wide
      $d3 = "Mcl_ThreatInject" fullword ascii wide
      $d4 = "Mcl_NtMemory" fullword ascii wide

   condition:
      filesize < 2000KB and (1 of ($x*) or all of ($a*) or 1 of ($b*) or ( uint16(0) == 0x5a4d and 1 of ($c*) ) or 3 of ($c*) or ( uint16(0) == 0x5a4d and 3 of ($d*) ))
}

');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (128, 'backdoor_apt_pcclient', NULL, '{"date": "2012-10", "author": "@patrickrolsen", "maltype": "APT.PCCLient", "version": "0.1", "filetype": "DLL", "description": "Detects the dropper: 869fa4dfdbabfabe87d334f85ddda234 AKA dw20.dll/msacm32.drv dropped by 4a85af37de44daf5917f545c6fd03902 (RTF)"}', '2020-12-04 20:51:00.358862', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule backdoor_apt_pcclient
{

    meta:
        author = "@patrickrolsen"
        maltype = "APT.PCCLient"
        filetype = "DLL"
        version = "0.1"
        description = "Detects the dropper: 869fa4dfdbabfabe87d334f85ddda234 AKA dw20.dll/msacm32.drv dropped by 4a85af37de44daf5917f545c6fd03902 (RTF)"
        date = "2012-10"

    strings:
        $magic = { 4d 5a } // MZ
        $string1 = "www.micro1.zyns.com"
        $string2 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)"
        $string3 = "msacm32.drv" wide
        $string4 = "C:\\Windows\\Explorer.exe" wide
        $string5 = "Elevation:Administrator!" wide
        $string6 = "C:\\Users\\cmd\\Desktop\\msacm32\\Release\\msacm32.pdb"

    condition:
        $magic at 0 and 4 of ($string*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (129, 'Ransom', '{Crypren}', '{"Author": "@pekeinfo", "weight": 1, "reference": "https://github.com/pekeinfo/DecryptCrypren"}', '2020-12-04 20:51:00.667332', 'rule Ransom : Crypren{
    meta:
        weight = 1
        Author = "@pekeinfo"
        reference = "https://github.com/pekeinfo/DecryptCrypren"
    strings:
        $a = "won''t be able to recover your files anymore.</p>"
        $b = {6A 03 68 ?? ?? ?? ?? B9 74 F1 AE 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 98 3A 00 00 FF D6 6A 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ??}
        $c = "Please restart your computer and wait for instructions for decrypting your files"
    condition:
        any of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (130, 'Mirai_Okiru', NULL, '{"date": "2018-01-05", "reference": "https://www.reddit.com/r/LinuxMalware/comments/7p00i3/quick_notes_for_okiru_satori_variant_of_mirai/", "description": "Detects Mirai Okiru MALW"}', '2020-12-04 20:51:00.880649', '/* Yara rule to detect Mirai Okiru generic
   This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html)
   and  open to any user or organization, as long as you use it under this license.
*/


rule Mirai_Okiru {
	meta:
		description = "Detects Mirai Okiru MALW"
		reference = "https://www.reddit.com/r/LinuxMalware/comments/7p00i3/quick_notes_for_okiru_satori_variant_of_mirai/"
		date = "2018-01-05"

	strings:
		$hexsts01 = { 68 7f 27 70 60 62 73 3c 27 28 65 6e 69 28 65 72 }
		$hexsts02 = { 74 7e 65 68 7f 27 73 61 73 77 3c 27 28 65 6e 69 }
		// noted some Okiru variant doesnt have below function, uncomment to seek specific x86 bins
    // $st07 = "iptables -F\n" fullword nocase wide ascii

	condition:
    		all of them
		and is__elf
		and is__Mirai_gen7
		and filesize < 100KB
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (142, 'Derkziel', NULL, '{"md5": "f5956953b7a4acab2e6fa478c0015972", "date": "2015-11", "site": "https://zoo.mlw.re/samples/f5956953b7a4acab2e6fa478c0015972", "author": "The Malware Hunter", "filetype": "pe", "reference": "https://bhf.su/threads/137898/", "description": "Derkziel info stealer (Steam, Opera, Yandex, ...)"}', '2020-12-04 20:51:03.54201', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Derkziel
{

    meta:
        description = "Derkziel info stealer (Steam, Opera, Yandex, ...)"
        author = "The Malware Hunter"
        filetype = "pe"
        date = "2015-11"
        md5 = "f5956953b7a4acab2e6fa478c0015972"
        site = "https://zoo.mlw.re/samples/f5956953b7a4acab2e6fa478c0015972"
        reference = "https://bhf.su/threads/137898/"

    strings:
        $drz = "{!}DRZ{!}"
        $ua = "User-Agent: Uploador"
        $steam = "SteamAppData.vdf"
        $login = "loginusers.vdf"
        $config = "config.vdf"

    condition:
        all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (131, 'sig_8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93', NULL, '{"date": "2017-10-24", "hash1": "8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93", "author": "Christiaan Beek", "source": "https://pastebin.com/Y7pJv3tK", "reference": "BadRabbit", "description": "Bad Rabbit Ransomware"}', '2020-12-04 20:51:01.233965', 'import "pe"

rule sig_8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93 {
   meta:
      description = "Bad Rabbit Ransomware"
      author = "Christiaan Beek"
      reference = "BadRabbit"
      date = "2017-10-24"
      hash1 = "8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93"
      source = "https://pastebin.com/Y7pJv3tK"
   strings:
      $x1 = "schtasks /Create /SC ONCE /TN viserion_%u /RU SYSTEM /TR \"%ws\" /ST %02d:%02d:00" fullword wide
      $x2 = "need to do is submit the payment and get the decryption password." fullword ascii
      $s3 = "If you have already got the password, please enter it below." fullword ascii
      $s4 = "dispci.exe" fullword wide
      $s5 = "\\\\.\\GLOBALROOT\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)" fullword wide
      $s6 = "Run DECRYPT app at your desktop after system boot" fullword ascii
      $s7 = "Enter password#1: " fullword wide
      $s8 = "Enter password#2: " fullword wide
      $s9 = "C:\\Windows\\cscc.dat" fullword wide
      $s10 = "schtasks /Delete /F /TN %ws" fullword wide
      $s11 = "Password#1: " fullword ascii
      $s12 = "\\AppData" fullword wide
      $s13 = "Readme.txt" fullword wide
      $s14 = "Disk decryption completed" fullword wide
      $s15 = "Files decryption completed" fullword wide
      $s16 = "http://diskcryptor.net/" fullword wide
      $s17 = "Your personal installation key#1:" fullword ascii
      $s18 = ".3ds.7z.accdb.ai.asm.asp.aspx.avhd.back.bak.bmp.brw.c.cab.cc.cer.cfg.conf.cpp.crt.cs.ctl.cxx.dbf.der.dib.disk.djvu.doc.docx.dwg." wide
      $s19 = "Disable your anti-virus and anti-malware programs" fullword wide
      $s20 = "bootable partition not mounted" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
        filesize < 400KB and
        pe.imphash() == "94f57453c539227031b918edd52fc7f1" and
        ( 1 of ($x*) or 4 of them )
      ) or ( all of them )
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (132, 'FUDCrypter', NULL, '{"author": "https://github.com/hwvs", "reference": "https://github.com/gigajew/FudCrypt/", "description": "Detects unmodified FUDCrypt samples", "last_modified": "2019-11-21"}', '2020-12-04 20:51:01.340406', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule FUDCrypter
{
    meta:
        description = "Detects unmodified FUDCrypt samples"
        reference = "https://github.com/gigajew/FudCrypt/"
        author = "https://github.com/hwvs"
        last_modified = "2019-11-21"

    strings:
        $ = "OcYjzPUtJkNbLOABqYvNbvhZf" wide ascii
        $ = "gwiXxyIDDtoYzgMSRGMckRbJi" wide ascii
        $ = "BclWgISTcaGjnwrzSCIuKruKm" wide ascii
        $ = "CJyUSiUNrIVbgksjxpAMUkAJJ" wide ascii
        $ = "fAMVdoPUEyHEWdxQIEJPRYbEN" wide ascii
        $ = "CIGQUctdcUPqUjoucmcoffECY" wide ascii
        $ = "wcZfHOgetgAExzSoWFJFQdAyO" wide ascii
        $ = "DqYKDnIoLeZDWYlQWoxZnpfPR" wide ascii
        $ = "MkhMoOHCbGUMqtnRDJKnBYnOj" wide ascii
        $ = "sHEqLMGglkBAOIUfcSAgMvZfs" wide ascii
        $ = "JtZApJhbFAIFxzHLjjyEQvtgd" wide ascii
        $ = "IIQrSWZEMmoQIKGuxxwoTwXka" wide ascii

    condition:
        1 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (133, 'BoousetCode', NULL, '{"author": "Seth Hardy", "description": "Boouset code tricks", "last_modified": "2014-06-19"}', '2020-12-04 20:51:01.565184', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule BoousetCode
{

    meta:
        description = "Boouset code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-19"

    strings:
        $boousetdat = { C6 ?? ?? ?? ?? 00 62 C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 75 }

    condition:
        any of them
}

');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (134, 'XHide', '{MALW}', '{"MD5": "c644c04bce21dacdeb1e6c14c081e359", "date": "2017-12-01", "SHA256": "59f5b21ef8a570c02453b5edb0e750a42a1382f6", "author": "Joan Soriano / @w0lfvan", "version": "1.0", "description": "XHide - Process Faker"}', '2020-12-04 20:51:01.789112', 'rule XHide: MALW
{
	meta:
		description = "XHide - Process Faker"
		author = "Joan Soriano / @w0lfvan"
		date = "2017-12-01"
		version = "1.0"
		MD5 = "c644c04bce21dacdeb1e6c14c081e359"
		SHA256 = "59f5b21ef8a570c02453b5edb0e750a42a1382f6"
	strings:
		$a = "XHide - Process Faker"
		$b = "Fakename: %s PidNum: %d"
	condition:
		all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (135, 'Crimson', '{RAT}', '{"ref": "http://malwareconfig.com/stats/Crimson", "date": "2015/05", "author": " Kevin Breen <kevin@techanarchy.net>", "maltype": "Remote Access Trojan", "filetype": "jar", "Description": "Crimson Rat"}', '2020-12-04 20:51:02.101073', 'rule Crimson: RAT
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		Description = "Crimson Rat"
		date = "2015/05"
		ref = "http://malwareconfig.com/stats/Crimson"
		maltype = "Remote Access Trojan"
		filetype = "jar"

	strings:
		$a1 = "com/crimson/PK"
		$a2 = "com/crimson/bootstrapJar/PK"
		$a3 = "com/crimson/permaJarMulti/PermaJarReporter$1.classPK"
		$a4 = "com/crimson/universal/containers/KeyloggerLog.classPK"
        $a5 = "com/crimson/universal/UploadTransfer.classPK"

	condition:
        all of ($a*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (136, 'BeEF_browser_hooked', NULL, '{"date": "2015-10-07", "hash1": "587e611f49baf63097ad2421ad0299b7b8403169ec22456fb6286abf051228db", "author": "Pasquale Stirparo", "description": "Yara rule related to hook.js, BeEF Browser hooking capability"}', '2020-12-04 20:51:02.230589', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
	This Yara Rule is to be considered as "experimental"
	It reperesents a first attempt to detect BeEF hook function in memory
	It still requires further refinement

*/

/* experimental */

rule BeEF_browser_hooked
{
	meta:
		description = "Yara rule related to hook.js, BeEF Browser hooking capability"
		author = "Pasquale Stirparo"
		date = "2015-10-07"
		hash1 = "587e611f49baf63097ad2421ad0299b7b8403169ec22456fb6286abf051228db"

	strings:
		$s0 = "mitb.poisonAnchor" wide ascii
		$s1 = "this.request(this.httpproto" wide ascii
		$s2 = "beef.logger.get_dom_identifier" wide ascii
		$s3 = "return (!!window.opera" wide ascii
		$s4 = "history.pushState({ Be:\"EF\" }" wide ascii
		$s5 = "window.navigator.userAgent.match(/Opera\\/9\\.80.*Version\\/10\\./)" wide ascii
		$s6 = "window.navigator.userAgent.match(/Opera\\/9\\.80.*Version\\/11\\./)" wide ascii
		$s7 = "window.navigator.userAgent.match(/Avant TriCore/)" wide ascii
		$s8 = "window.navigator.userAgent.match(/Iceweasel" wide ascii
		$s9 = "mitb.sniff(" wide ascii
		$s10 = "Method XMLHttpRequest.open override" wide ascii
		$s11 = ".browser.hasWebSocket" wide ascii
		$s12 = ".mitb.poisonForm" wide ascii
		$s13 = "resolved=require.resolve(file,cwd||" wide ascii
		$s14 = "if (document.domain == domain.replace(/(\\r\\n|\\n|\\r)/gm" wide ascii
		$s15 = "beef.net.request" wide ascii
		$s16 = "uagent.search(engineOpera)" wide ascii
		$s17 = "mitb.sniff" wide ascii
		$s18 = "beef.logger.start" wide ascii

	condition:
		all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (143, 'mimikatz_kirbi_ticket', NULL, '{"author": "Benjamin DELPY (gentilkiwi); Didier Stevens", "description": "KiRBi ticket for mimikatz"}', '2020-12-04 20:51:03.909592', 'rule mimikatz_kirbi_ticket
{
	meta:
		description		= "KiRBi ticket for mimikatz"
		author			= "Benjamin DELPY (gentilkiwi); Didier Stevens"

	strings:
		$asn1			= { 76 82 ?? ?? 30 82 ?? ?? a0 03 02 01 05 a1 03 02 01 16 }
		$asn1_84		= { 76 84 ?? ?? ?? ?? 30 84 ?? ?? ?? ?? a0 84 00 00 00 03 02 01 05 a1 84 00 00 00 03 02 01 16 }

	condition:
		$asn1 at 0 or $asn1_84 at 0
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (137, 'Generic_ATMPot', '{Generic_ATMPot}', '{"date": "2019-02-24", "author": "xylitol@temari.fr", "reference": "https://securelist.com/atm-robber-winpot/89611/", "description": "Generic rule for Winpot aka ATMPot"}', '2020-12-04 20:51:02.336974', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule Generic_ATMPot : Generic_ATMPot
{
    meta:
        description = "Generic rule for Winpot aka ATMPot"
        author = "xylitol@temari.fr"
        date = "2019-02-24"
        reference = "https://securelist.com/atm-robber-winpot/89611/"
        // May only the challenge guide you
    strings:
        $api1 = "CSCCNG" ascii wide
        $api2 = "CscCngOpen" ascii wide
        $api3 = "CscCngClose" ascii wide
        $string1 = "%d,%02d;" ascii wide
/*
0xD:
.text:004022EC FF 15 20 70 40 00             CALL DWORD PTR DS:[407020]  ; cscwcng.CscCngDispense
.text:004022F2 F6 C4 80                      TEST AH,80
winpot:
.text:004019D4 FF 15 24 60 40 00             CALL DWORD PTR DS:[406024]  ; cscwcng.CscCngDispense
.text:004019DA F6 C4 80                      TEST AH,80
*/
        $hex1 = { FF 15 ?? ?? ?? ?? F6 C4 80 }
/*
0xD...: 0040506E  25 31 5B 31 2D 34 5D 56 41 4C 3D 25 38 5B 30 2D 39 5D: %1[1-4]VAL=%8[0-9]
winpot: 0040404D  25 31 5B 30 2D 39 5D 56 41 4C 3D 25 38 5B 30 2D 39 5D: %1[0-9]VAL=%8[0-9]
*/
        $hex2 = { 25 31 5B ?? 2D ?? 5D 56 41 4C 3D 25 38 5B 30 2D 39 5D }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (138, 'Predator_The_Thief', '{Predator_The_Thief}', '{"date": "2018/10/12", "author": "Fumik0_", "source": "https://fumik0.com/2018/10/15/predator-the-thief-in-depth-analysis-v2-3-5/", "description": "Yara rule for Predator The Thief v2.3.5 & +"}', '2020-12-04 20:51:02.44441', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule Predator_The_Thief : Predator_The_Thief {
   meta:
        description = "Yara rule for Predator The Thief v2.3.5 & +"
        author = "Fumik0_"
        date = "2018/10/12"
        source = "https://fumik0.com/2018/10/15/predator-the-thief-in-depth-analysis-v2-3-5/"
   strings:
        $mz = { 4D 5A }

        $hex1 = { BF 00 00 40 06 }
        $hex2 = { C6 04 31 6B }
        $hex3 = { C6 04 31 63 }
        $hex4 = { C6 04 31 75 }
        $hex5 = { C6 04 31 66 }

        $s1 = "sqlite_" ascii wide
   condition:
        $mz at 0 and all of ($hex*) and all of ($s*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (139, 'hancitor', NULL, '{"date": "2018-09-18", "author": "J from THL <j@techhelplist.com>", "filetype": "memory", "maltype1": "Botnet", "reference1": "https://researchcenter.paloaltonetworks.com/2018/02/threat-brief-hancitor-actors/", "reference2": "https://www.virustotal.com/#/file/43e17f30b78c085e9bda8cadf5063cd5cec9edaa7441594ba1fe51391cc1c486/", "reference3": "https://www.virustotal.com/#/file/d135f03b9fdc709651ac9d0264e155c5580b072577a8ff24c90183b126b5e12a/", "description": "Memory string yara for Hancitor"}', '2020-12-04 20:51:02.665507', '

rule hancitor {
	meta:
		description = "Memory string yara for Hancitor"
		author = "J from THL <j@techhelplist.com>"
		reference1 = "https://researchcenter.paloaltonetworks.com/2018/02/threat-brief-hancitor-actors/"
		reference2 = "https://www.virustotal.com/#/file/43e17f30b78c085e9bda8cadf5063cd5cec9edaa7441594ba1fe51391cc1c486/"
		reference3 = "https://www.virustotal.com/#/file/d135f03b9fdc709651ac9d0264e155c5580b072577a8ff24c90183b126b5e12a/"
		date = "2018-09-18"
		maltype1 = "Botnet"
		filetype = "memory"

	strings:
		$a = "GUID="	ascii
                $b = "&BUILD="	ascii
                $c = "&INFO="	ascii
                $d = "&IP="	ascii
                $e = "&TYPE=" 	ascii
                $f = "php|http"	ascii
		$g = "GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d" ascii fullword


	condition:
		5 of ($a,$b,$c,$d,$e,$f) or $g

}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (140, 'Madness', '{DoS}', '{"date": "2014-01-15", "author": "Jason Jones <jasonjones@arbor.net>", "source": "https://github.com/arbor/yara/blob/master/madness.yara", "description": "Identify Madness Pro DDoS Malware"}', '2020-12-04 20:51:03.19473', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule Madness : DoS {
    meta:
        author = "Jason Jones <jasonjones@arbor.net>"
        date = "2014-01-15"
        description = "Identify Madness Pro DDoS Malware"
        source = "https://github.com/arbor/yara/blob/master/madness.yara"
    strings:
        $ua1 = "TW96aWxsYS81LjAgKFdpbmRvd3M7IFU7IFdpbmRvd3MgTlQgNS4xOyBlbi1VUzsgcnY6MS44LjAuNSkgR2Vja28vMjAwNjA3MzEgRmlyZWZveC8xLjUuMC41IEZsb2NrLzAuNy40LjE"
        $ua2 = "TW96aWxsYS81LjAgKFgxMTsgVTsgTGludXggMi40LjItMiBpNTg2OyBlbi1VUzsgbTE4KSBHZWNrby8yMDAxMDEzMSBOZXRzY2FwZTYvNi4wMQ=="
        $str1= "document.cookie=" fullword
        $str2 = "[\"cookie\",\"" fullword
        $str3 = "\"realauth=" fullword
        $str4 = "\"location\"];" fullword
        $str5 = "d3Rm" fullword
        $str6 = "ZXhl" fullword
    condition:
        all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (141, 'QuarksPwDump_Gen', '{Toolkit}', '{"date": "2015-09-29", "hash1": "2b86e6aea37c324ce686bd2b49cf5b871d90f51cec24476daa01dd69543b54fa", "hash2": "87e4c76cd194568e65287f894b4afcef26d498386de181f568879dde124ff48f", "hash3": "a59be92bf4cce04335bd1a1fcf08c1a94d5820b80c068b3efe13e2ca83d857c9", "hash4": "c5cbb06caa5067fdf916e2f56572435dd40439d8e8554d3354b44f0fd45814ab", "hash5": "677c06db064ee8d8777a56a641f773266a4d8e0e48fbf0331da696bea16df6aa", "hash6": "d3a1eb1f47588e953b9759a76dfa3f07a3b95fab8d8aa59000fd98251d499674", "hash7": "8a81b3a75e783765fe4335a2a6d1e126b12e09380edc4da8319efd9288d88819", "score": 80, "author": "Florian Roth", "description": "Detects all QuarksPWDump versions"}', '2020-12-04 20:51:03.413325', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule QuarksPwDump_Gen : Toolkit  {
	meta:
		description = "Detects all QuarksPWDump versions"
		author = "Florian Roth"
		date = "2015-09-29"
		score = 80
		hash1 = "2b86e6aea37c324ce686bd2b49cf5b871d90f51cec24476daa01dd69543b54fa"
		hash2 = "87e4c76cd194568e65287f894b4afcef26d498386de181f568879dde124ff48f"
		hash3 = "a59be92bf4cce04335bd1a1fcf08c1a94d5820b80c068b3efe13e2ca83d857c9"
		hash4 = "c5cbb06caa5067fdf916e2f56572435dd40439d8e8554d3354b44f0fd45814ab"
		hash5 = "677c06db064ee8d8777a56a641f773266a4d8e0e48fbf0331da696bea16df6aa"
		hash6 = "d3a1eb1f47588e953b9759a76dfa3f07a3b95fab8d8aa59000fd98251d499674"
		hash7 = "8a81b3a75e783765fe4335a2a6d1e126b12e09380edc4da8319efd9288d88819"
	strings:
		$s1 = "OpenProcessToken() error: 0x%08X" fullword ascii
		$s2 = "%d dumped" fullword ascii
		$s3 = "AdjustTokenPrivileges() error: 0x%08X" fullword ascii
		$s4 = "\\SAM-%u.dmp" fullword ascii
	condition:
		all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (181, 'with_sqlite', '{sqlite}', '{"author": "Julian J. Gonzalez <info@seguridadparatodos.es>", "reference": "http://www.st2labs.com", "description": "Rule to detect the presence of SQLite data in raw image"}', '2020-12-04 20:51:14.394327', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule with_sqlite : sqlite
{
	meta:
		author = "Julian J. Gonzalez <info@seguridadparatodos.es>"
		reference = "http://www.st2labs.com"
		description = "Rule to detect the presence of SQLite data in raw image"
	strings:
		$hex_string = {53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00}
	condition:
		all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (144, 'APT17_Sample_FXSST_DLL', NULL, '{"date": "2015-05-14", "hash": "52f1add5ad28dc30f68afda5d41b354533d8bce3", "author": "Florian Roth", "reference": "https://goo.gl/ZiJyQv", "description": "Detects Samples related to APT17 activity - file FXSST.DLL"}', '2020-12-04 20:51:04.305373', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule APT17_Sample_FXSST_DLL
{

    meta:
        description = "Detects Samples related to APT17 activity - file FXSST.DLL"
        author = "Florian Roth"
        reference = "https://goo.gl/ZiJyQv"
        date = "2015-05-14"
        hash = "52f1add5ad28dc30f68afda5d41b354533d8bce3"

    strings:
        $x1 = "Microsoft? Windows? Operating System" fullword wide
        $x2 = "fxsst.dll" fullword ascii
        $y1 = "DllRegisterServer" fullword ascii
        $y2 = ".cSV" fullword ascii
        $s1 = "GetLastActivePopup"
        $s2 = "Sleep"
        $s3 = "GetModuleFileName"
        $s4 = "VirtualProtect"
        $s5 = "HeapAlloc"
        $s6 = "GetProcessHeap"
        $s7 = "GetCommandLine"

   condition:
        uint16(0) == 0x5a4d and filesize < 800KB and ( 1 of ($x*) or all of ($y*) ) and all of ($s*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (145, 'termite_ransomware', NULL, '{"author": "Marc Rivero | @seifreed", "reference": "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/", "description": "Rule to detect Termite Ransomware"}', '2020-12-04 20:51:05.363948', 'rule termite_ransomware {

   meta:

      description = "Rule to detect Termite Ransomware"
      author = "Marc Rivero | @seifreed"
      reference = "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/"

   strings:

      $s1 = "C:\\Windows\\SysNative\\mswsock.dll" fullword ascii
      $s2 = "C:\\Windows\\SysWOW64\\mswsock.dll" fullword ascii
      $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Termite.exe" fullword ascii
      $s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Payment.exe" fullword ascii
      $s5 = "C:\\Windows\\Termite.exe" fullword ascii
      $s6 = "\\Shell\\Open\\Command\\" fullword ascii
      $s7 = "t314.520@qq.com" fullword ascii
      $s8 = "(*.JPG;*.PNG;*.BMP;*.GIF;*.ICO;*.CUR)|*.JPG;*.PNG;*.BMP;*.GIF;*.ICO;*.CUR|JPG" fullword ascii

   condition:

      ( uint16(0) == 0x5a4d and filesize < 6000KB ) and all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (146, 'CrossRAT', '{RAT}', '{"ref": "https://objective-see.com/blog/blog_0x28.html", "date": "26/01/2018", "author": "Simon Sigre (simon.sigre@gmail.com)", "description": "Detects CrossRAT known hash"}', '2020-12-04 20:51:05.490013', 'import "hash"

rule CrossRAT: RAT
{
    meta:
        description = "Detects CrossRAT known hash"
        author = "Simon Sigre (simon.sigre@gmail.com)"
        date = "26/01/2018"
        ref = "https://simonsigre.com"
        ref= "https://objective-see.com/blog/blog_0x28.html"
    strings:
        $magic = { 50 4b 03 04 ( 14 | 0a ) 00 }
        $string_1 = "META-INF/"
        $string_2 = ".class" nocase

    condition:
        filesize < 400KB and
        $magic at 0 and 1 of ($string_*) and
        hash.md5(0, filesize) == "85b794e080d83a91e904b97769e1e770"
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (147, 'CyberGate', '{RAT}', '{"ref": "http://malwareconfig.com/stats/CyberGate", "date": "2014/04", "author": " Kevin Breen <kevin@techanarchy.net>", "maltype": "Remote Access Trojan", "filetype": "exe"}', '2020-12-04 20:51:06.123593', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
rule CyberGate : RAT
{

	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/CyberGate"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$string1 = {23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}
		$string2 = {23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}
		$string3 = "EditSvr"
		$string4 = "TLoader"
		$string5 = "Stroks"
		$string6 = "####@####"
		$res1 = "XX-XX-XX-XX"
		$res2 = "CG-CG-CG-CG"

	condition:
		all of ($string*) and any of ($res*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (148, 'Upatre_Hazgurut', NULL, '{"date": "2015-10-13", "hash1": "7ee0d20b15e24b7fe72154d9521e1959752b4e9c20d2992500df9ac096450a50", "hash2": "79ffc620ddb143525fa32bc6a83c636168501a4a589a38cdb0a74afac1ee8b92", "hash3": "62d8a6880c594fe9529158b94a9336179fa7a3d3bf1aa9d0baaf07d03b281bd3", "hash4": "c64282aca980d558821bec8b3dfeae562d9620139dc43d02ee4d1745cd989f2a", "hash5": "a35f9870f9d4b993eb094460b05ee1f657199412807abe6264121dd7cc12aa70", "hash6": "f8cb2730ebc8fac1c58da1346ad1208585fe730c4f03d976eb1e13a1f5d81ef9", "hash7": "b65ad7e2d299d6955d95b7ae9b62233c34bc5f6aa9f87dc482914f8ad2cba5d2", "hash8": "6b857ef314938d37997c178ea50687a281d8ff9925f0c4e70940754643e2c0e3", "hash9": "33a288cef0ae7192b34bd2ef3f523dfb7c6cbc2735ba07edf988400df1713041", "score": 70, "author": "Florian Roth", "hash10": "2a8e50afbc376cb2a9700d2d83c1be0c21ef942309676ecac897ba4646aba273", "hash11": "3d0f2c7e07b7d64b1bad049b804ff1aae8c1fc945a42ad555eca3e1698c7f7d3", "hash12": "951360b32a78173a1f81da0ded8b4400e230125d05970d41621830efc5337274", "hash13": "bd90faebfd7663ef89b120fe69809532cada3eb94bb94094e8bc615f70670295", "hash14": "8c5823f67f9625e4be39a67958f0f614ece49c18596eacc5620524bc9b6bad3d", "reference": "https://weankor.vxstream-sandbox.com/sample/6b857ef314938d37997c178ea50687a281d8ff9925f0c4e70940754643e2c0e3?environmentId=7", "description": "Detects Upatre malware - file hazgurut.exe"}', '2020-12-04 20:51:06.474137', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-10-13
	Identifier: Upatre Campaign October 2015
*/

rule Upatre_Hazgurut {
	meta:
		description = "Detects Upatre malware - file hazgurut.exe"
		author = "Florian Roth"
		reference = "https://weankor.vxstream-sandbox.com/sample/6b857ef314938d37997c178ea50687a281d8ff9925f0c4e70940754643e2c0e3?environmentId=7"
		date = "2015-10-13"
		score = 70
		hash1 = "7ee0d20b15e24b7fe72154d9521e1959752b4e9c20d2992500df9ac096450a50"
		hash2 = "79ffc620ddb143525fa32bc6a83c636168501a4a589a38cdb0a74afac1ee8b92"
		hash3 = "62d8a6880c594fe9529158b94a9336179fa7a3d3bf1aa9d0baaf07d03b281bd3"
		hash4 = "c64282aca980d558821bec8b3dfeae562d9620139dc43d02ee4d1745cd989f2a"
		hash5 = "a35f9870f9d4b993eb094460b05ee1f657199412807abe6264121dd7cc12aa70"
		hash6 = "f8cb2730ebc8fac1c58da1346ad1208585fe730c4f03d976eb1e13a1f5d81ef9"
		hash7 = "b65ad7e2d299d6955d95b7ae9b62233c34bc5f6aa9f87dc482914f8ad2cba5d2"
		hash8 = "6b857ef314938d37997c178ea50687a281d8ff9925f0c4e70940754643e2c0e3"
		hash9 = "33a288cef0ae7192b34bd2ef3f523dfb7c6cbc2735ba07edf988400df1713041"
		hash10 = "2a8e50afbc376cb2a9700d2d83c1be0c21ef942309676ecac897ba4646aba273"
		hash11 = "3d0f2c7e07b7d64b1bad049b804ff1aae8c1fc945a42ad555eca3e1698c7f7d3"
		hash12 = "951360b32a78173a1f81da0ded8b4400e230125d05970d41621830efc5337274"
		hash13 = "bd90faebfd7663ef89b120fe69809532cada3eb94bb94094e8bc615f70670295"
		hash14 = "8c5823f67f9625e4be39a67958f0f614ece49c18596eacc5620524bc9b6bad3d"
	strings:
		$a1 = "barcod" fullword ascii

		$s0 = "msports.dll" fullword ascii
		$s1 = "nddeapi.dll" fullword ascii
		$s2 = "glmf32.dll" fullword ascii
		$s3 = "<requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\">" fullword ascii
		$s4 = "cmutil.dll" fullword ascii
		$s5 = "mprapi.dll" fullword ascii
		$s6 = "glmf32.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1500KB
		and $a1 in (0..4000)
		and all of ($s*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (149, 'win_asyncrat_j1', NULL, '{"tlp": "white", "date": "2020-04-26", "author": "Johannes Bader @viql", "references": "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp", "description": "detects AsyncRAT"}', '2020-12-04 20:51:06.589442', '/*
   This Yara ruleset is under the GNU-GPLv2 license
   (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or
   organization, as long as you use it under this license.
*/

rule win_asyncrat_j1 {

    meta:
        author      = "Johannes Bader @viql"
        date        = "2020-04-26"
        description = "detects AsyncRAT"
        references  = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"
        tlp         = "white"

    strings:
        $str_anti_1 = "VIRTUAL" wide
        $str_anti_2 = "vmware" wide
        $str_anti_3 = "VirtualBox" wide
        $str_anti_4 = "SbieDll.dll" wide

        $str_miner_1 = "--donate-level=" wide

        $str_b_rev_run    = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
        $str_b_msg_pack_1 = "(ext8,ext16,ex32) type $c7,$c8,$c9" wide
        $str_b_msg_pack_2 = "(never used) type $c1" wide
        $str_b_schtask_1  = "/create /f /sc ONLOGON /RL HIGHEST /tn \"''" wide
        $str_b_schtask_2  = "\"'' /tr \"''" wide

        $str_config_1 = "Antivirus" wide
        $str_config_2 = "Pastebin" wide
        $str_config_3 = "HWID" wide
        $str_config_4 = "Installed" wide
        $str_config_5 = "Pong" wide
        $str_config_6 = "Performance" wide

    condition:
        all of ($str_anti_*)  and
        4 of ($str_config_*) and (
            all of ($str_miner_*) or
            3 of ($str_b_*)
        )

}

');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (150, 'Powerstager', NULL, '{"date": "02JAN2018", "hash1": "758097319d61e2744fb6b297f0bff957c6aab299278c1f56a90fba197795a0fa", "hash2": "83e714e72d9f3c500cad610c4772eae6152a232965191f0125c1c6f97004b7b5", "author": "Jeff White - jwhite@paloaltonetworks.com @noottrak", "reference": "https://researchcenter.paloaltonetworks.com/2018/01/unit42-powerstager-analysis/", "reference2": "https://github.com/z0noxz/powerstager", "description": "Detects PowerStager Windows executable, both x86 and x64"}', '2020-12-04 20:51:06.980753', 'rule Powerstager
{
    meta:
      author = "Jeff White - jwhite@paloaltonetworks.com @noottrak"
      date = "02JAN2018"
      hash1 = "758097319d61e2744fb6b297f0bff957c6aab299278c1f56a90fba197795a0fa" //x86
      hash2 = "83e714e72d9f3c500cad610c4772eae6152a232965191f0125c1c6f97004b7b5" //x64
      description = "Detects PowerStager Windows executable, both x86 and x64"
      reference = "https://researchcenter.paloaltonetworks.com/2018/01/unit42-powerstager-analysis/"
      reference2 = "https://github.com/z0noxz/powerstager"

    strings:
      $filename = /%s\\[a-zA-Z0-9]{12}/
      $pathname = "TEMP" wide ascii
//    $errormsg = "The version of this file is not compatible with the version of Windows you''re running." wide ascii
      $filedesc = "Lorem ipsum dolor sit amet, consecteteur adipiscing elit" wide ascii
      $apicall_01 = "memset"
      $apicall_02 = "getenv"
      $apicall_03 = "fopen"
      $apicall_04 = "memcpy"
      $apicall_05 = "fwrite"
      $apicall_06 = "fclose"
      $apicall_07 = "CreateProcessA"
      $decoder_x86_01 = { 8D 95 [4] 8B 45 ?? 01 D0 0F B6 18 8B 4D ?? }
      $decoder_x86_02 = { 89 C8 0F B6 84 05 [4] 31 C3 89 D9 8D 95 [4] 8B 45 ?? 01 D0 88 08 83 45 [2] 8B 45 ?? 3D }
      $decoder_x64_01 = { 8B 85 [4] 48 98 44 0F [7] 8B 85 [4] 48 63 C8 48 }
      $decoder_x64_02 = { 48 89 ?? 0F B6 [3-6] 44 89 C2 31 C2 8B 85 [4] 48 98 }

    condition:
      uint16be(0) == 0x4D5A
        and
      all of ($apicall_*)
        and
      $filename
        and
      $pathname
        and
      $filedesc
        and
      (2 of ($decoder_x86*) or 2 of ($decoder_x64*))
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (151, 'NetWiredRC_B', '{RAT}', '{"date": "2014-12-23", "author": "Jean-Philippe Teissier / @Jipe_", "version": "1.1", "filetype": "memory", "description": "NetWiredRC"}', '2020-12-04 20:51:07.101485', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"
rule NetWiredRC_B : RAT
{
	meta:
		description = "NetWiredRC"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2014-12-23"
		filetype = "memory"
		version = "1.1"

	strings:
		$mutex = "LmddnIkX"

		$str1 = "%s.Identifier"
		$str2 = "%d:%I64u:%s%s;"
		$str3 = "%s%.2d-%.2d-%.4d"
		$str4 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"
		$str5 = "%.2d/%.2d/%d %.2d:%.2d:%.2d"

		$klg1 = "[Backspace]"
		$klg2 = "[Enter]"
		$klg3 = "[Tab]"
		$klg4 = "[Arrow Left]"
		$klg5 = "[Arrow Up]"
		$klg6 = "[Arrow Right]"
		$klg7 = "[Arrow Down]"
		$klg8 = "[Home]"
		$klg9 = "[Page Up]"
		$klg10 = "[Page Down]"
		$klg11 = "[End]"
		$klg12 = "[Break]"
		$klg13 = "[Delete]"
		$klg14 = "[Insert]"
		$klg15 = "[Print Screen]"
		$klg16 = "[Scroll Lock]"
		$klg17 = "[Caps Lock]"
		$klg18 = "[Alt]"
		$klg19 = "[Esc]"
		$klg20 = "[Ctrl+%c]"

	condition:
		$mutex or (1 of ($str*) and 1 of ($klg*))
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (152, 'MedussaHTTP_2019', NULL, '{"date": "2019-08-12", "author": "J from THL <j@techhelplist.com>", "maltype": "Bot", "version": 1, "filetype": "memory", "reference1": "https://app.any.run/tasks/68c8f400-eba5-4d6c-b1f1-8b07d4c014a4/", "reference2": "https://www.netscout.com/blog/asert/medusahttp-ddos-slithers-back-spotlight", "reference3": "https://twitter.com/malware_traffic/status/1161034462983008261", "description": "MedussaHTTP v20190812"}', '2020-12-04 20:51:07.22914', '
rule MedussaHTTP_2019
{

    meta:
        author = "J from THL <j@techhelplist.com>"
        date = "2019-08-12"
        reference1 = "https://app.any.run/tasks/68c8f400-eba5-4d6c-b1f1-8b07d4c014a4/"
        reference2 = "https://www.netscout.com/blog/asert/medusahttp-ddos-slithers-back-spotlight"
        reference3 = "https://twitter.com/malware_traffic/status/1161034462983008261"
        version = 1
        maltype = "Bot"
        filetype = "memory"
        description = "MedussaHTTP v20190812"

    strings:
        $text01 = "|check|" ascii
        $text02 = "POST!" ascii
        $text03 = "httpactive" ascii
        $text04 = "httpstrong" ascii
        $text05 = "httppost" ascii
        $text06 = "slavicdragon" ascii
        $text07 = "slavicnodragon" ascii
        $text08 = "smartflood" ascii
        $text09 = "stop-all" ascii
        $text10 = "botkill" ascii
        $text11 = "updatehash" ascii
        $text12 = "xyz=" ascii
        $text13 = "abc=" ascii



    condition:
        9 of them
}

');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (153, 'PoetRat_Python', NULL, '{"Data": "6th May 2020", "Author": "Nishan Maharjan", "Description": "A yara rule to catch PoetRat python scripts"}', '2020-12-04 20:51:07.728868', 'rule PoetRat_Python
{
    meta:
        Author = "Nishan Maharjan"
        Description = "A yara rule to catch PoetRat python scripts"
        Data = "6th May 2020"
    strings:

        // Any of the strings that stand out in the files, these are for the multiple python files, not just for a single file
        $encrptionFunction = "Affine"
        $commands = /version|ls|cd|sysinfo|download|upload|shot|cp|mv|link|register|hid|compress|jobs|exit|tasklist|taskkill/
        $domain = "dellgenius.hopto.org"
        $grammer_massacre = /BADD|Bad Error Happened|/
        $mayBePresent = /self\.DIE|THE_GUID_KEY/
        $pipe_out = "Abibliophobia23"
        $shot = "shot_{0}_{1}.png"
    condition:
        3 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (154, 'TRITON_ICS_FRAMEWORK', NULL, '{"md5": "0face841f7b2953e7c29c064d6886523", "author": "nicholas.carr @itsreallynick", "description": "TRITON framework recovered during Mandiant ICS incident response"}', '2020-12-04 20:51:07.959784', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule TRITON_ICS_FRAMEWORK
{
      meta:
          author = "nicholas.carr @itsreallynick"
          md5 = "0face841f7b2953e7c29c064d6886523"
          description = "TRITON framework recovered during Mandiant ICS incident response"
      strings:
          $python_compiled = ".pyc" nocase ascii wide
          $python_module_01 = "__module__" nocase ascii wide
          $python_module_02 = "<module>" nocase ascii wide
          $python_script_01 = "import Ts" nocase ascii wide
          $python_script_02 = "def ts_" nocase ascii wide

          $py_cnames_01 = "TS_cnames.py" nocase ascii wide
          $py_cnames_02 = "TRICON" nocase ascii wide
          $py_cnames_03 = "TriStation " nocase ascii wide
          $py_cnames_04 = " chassis " nocase ascii wide

          $py_tslibs_01 = "GetCpStatus" nocase ascii wide
          $py_tslibs_02 = "ts_" ascii wide
          $py_tslibs_03 = " sequence" nocase ascii wide
          $py_tslibs_04 = /import Ts(Hi|Low|Base)[^:alpha:]/ nocase ascii wide
          $py_tslibs_05 = /module\s?version/ nocase ascii wide
          $py_tslibs_06 = "bad " nocase ascii wide
          $py_tslibs_07 = "prog_cnt" nocase ascii wide

          $py_tsbase_01 = "TsBase.py" nocase ascii wide
          $py_tsbase_02 = ".TsBase(" nocase ascii wide

          $py_tshi_01 = "TsHi.py" nocase ascii wide
          $py_tshi_02 = "keystate" nocase ascii wide
          $py_tshi_03 = "GetProjectInfo" nocase ascii wide
          $py_tshi_04 = "GetProgramTable" nocase ascii wide
          $py_tshi_05 = "SafeAppendProgramMod" nocase ascii wide
          $py_tshi_06 = ".TsHi(" ascii nocase wide

          $py_tslow_01 = "TsLow.py" nocase ascii wide
          $py_tslow_02 = "print_last_error" ascii nocase wide
          $py_tslow_03 = ".TsLow(" ascii nocase wide
          $py_tslow_04 = "tcm_" ascii wide
          $py_tslow_05 = " TCM found" nocase ascii wide

          $py_crc_01 = "crc.pyc" nocase ascii wide
          $py_crc_02 = "CRC16_MODBUS" ascii wide
          $py_crc_03 = "Kotov Alaxander" nocase ascii wide
          $py_crc_04 = "CRC_CCITT_XMODEM" ascii wide
          $py_crc_05 = "crc16ret" ascii wide
          $py_crc_06 = "CRC16_CCITT_x1D0F" ascii wide
          $py_crc_07 = /CRC16_CCITT[^_]/ ascii wide

          $py_sh_01 = "sh.pyc" nocase ascii wide

          $py_keyword_01 = " FAILURE" ascii wide
          $py_keyword_02 = "symbol table" nocase ascii wide

          $py_TRIDENT_01 = "inject.bin" ascii nocase wide
          $py_TRIDENT_02 = "imain.bin" ascii nocase wide

      condition:
          2 of ($python_*) and 7 of ($py_*) and filesize < 3MB
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (155, 'Batel_export_function', NULL, '{"date": "2016/10/15", "author": "@j0sm1", "filetype": "binary", "reference": "https://www.symantec.com/security_response/writeup.jsp?docid=2016-091923-4146-99", "description": "Batel backdoor"}', '2020-12-04 20:51:08.062373', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.

*/

import "pe"

rule Batel_export_function
{

    meta:
        author = "@j0sm1"
        date = "2016/10/15"
        description = "Batel backdoor"
        reference = "https://www.symantec.com/security_response/writeup.jsp?docid=2016-091923-4146-99"
        filetype = "binary"

    condition:
        pe.exports("run_shell") and pe.imports("kernel32.dll","GetTickCount") and pe.imports("kernel32.dll","IsDebuggerPresent") and pe.imports("msvcr100.dll","_crt_debugger_hook") and pe.imports("kernel32.dll","TerminateProcess") and pe.imports("kernel32.dll","UnhandledExceptionFilter")
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (156, 'unpacked_shiva_ransomware', NULL, '{"author": "Marc Rivero | @seifreed", "reference": "https://twitter.com/malwrhunterteam/status/1037424962569732096", "description": "Rule to detect an unpacked sample of Shiva ransopmw"}', '2020-12-04 20:51:08.172096', 'rule unpacked_shiva_ransomware {

   meta:

      description = "Rule to detect an unpacked sample of Shiva ransopmw"
      author = "Marc Rivero | @seifreed"
      reference = "https://twitter.com/malwrhunterteam/status/1037424962569732096"

   strings:

      $s1 = "c:\\Users\\sys\\Desktop\\v 0.5\\Shiva\\Shiva\\obj\\Debug\\shiva.pdb" fullword ascii
      $s2 = "This email will be as confirmation you are ready to pay for decryption key." fullword wide
      $s3 = "Your important files are now encrypted due to a security problem with your PC!" fullword wide
      $s4 = "write.php?info=" fullword wide
      $s5 = " * Do not try to decrypt your data using third party software, it may cause permanent data loss." fullword wide
      $s6 = " * Do not rename encrypted files." fullword wide
      $s7 = ".compositiontemplate" fullword wide
      $s8 = "You have to pay for decryption in Bitcoins. The price depends on how fast you write to us." fullword wide
      $s9 = "\\READ_IT.txt" fullword wide
      $s10 = ".lastlogin" fullword wide
      $s11 = ".logonxp" fullword wide
      $s12 = " * Decryption of your files with the help of third parties may cause increased price" fullword wide
      $s13 = "After payment we will send you the decryption tool that will decrypt all your files." fullword wide

   condition:

      ( uint16(0) == 0x5a4d and filesize < 800KB ) and all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (157, 'APT_Hikit_msrv', NULL, '{"author": "ThreatConnect Intelligence Research Team"}', '2020-12-04 20:51:08.401004', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule APT_Hikit_msrv
{

meta:
    author = "ThreatConnect Intelligence Research Team"

strings:
    $m = {6D 73 72 76 2E 64 6C 6C 00 44 6C 6C}

condition:
    any of them
}

');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (158, 'Mozart', NULL, '{"author": "Nick Hoffman - Morphick Inc", "reference": "http://securitykitten.github.io/the-mozart-ram-scraper/", "description": "Detects samples of the Mozart POS RAM scraping utility"}', '2020-12-04 20:51:08.512208', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule Mozart
{
   meta:
       author = "Nick Hoffman - Morphick Inc"
       description = "Detects samples of the Mozart POS RAM scraping utility"
       reference = "http://securitykitten.github.io/the-mozart-ram-scraper/"
   strings:
       $pdb = "z:\\Slender\\mozart\\mozart\\Release\\mozart.pdb" nocase wide ascii
       $output = {67 61 72 62 61 67 65 2E 74 6D 70 00}
       $service_name = "NCR SelfServ Platform Remote Monitor" nocase wide ascii
       $service_name_short = "NCR_RemoteMonitor"
       $encode_data = {B8 08 10 00 00 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 53 55 8B AC 24 14 10 00 00 89 84 24 0C 10 00 00 56 8B C5 33 F6 33 DB 8D 50 01 8D A4 24 00 00 00 00 8A 08 40 84 C9 ?? ?? 2B C2 89 44 24 0C ?? ?? 8B 94 24 1C 10 00 00 57 8B FD 2B FA 89 7C 24 10 ?? ?? 8B 7C 24 10 8A 04 17 02 86 E0 BA 40 00 88 02 B8 ?? ?? ?? ?? 46 8D 78 01 8D A4 24 00 00 00 00 8A 08 40 84 C9 ?? ?? 2B C7 3B F0 ?? ?? 33 F6 8B C5 43 42 8D 78 01 8A 08 40 84 C9 ?? ?? 2B C7 3B D8 ?? ?? 5F 8B B4 24 1C 10 00 00 8B C5 C6 04 33 00 8D 50 01 8A 08 40 84 C9 ?? ?? 8B 8C 24 20 10 00 00 2B C2 51 8D 54 24 14 52 50 56 E8 ?? ?? ?? ?? 83 C4 10 8B D6 5E 8D 44 24 0C 8B C8 5D 2B D1 5B 8A 08 88 0C 02 40 84 C9 ?? ?? 8B 8C 24 04 10 00 00 E8 ?? ?? ?? ?? 81 C4 08 10 00 00}
   condition:
      any of ($pdb, $output, $encode_data) or
      all of ($service*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (159, 'Emissary_APT_Malware_1', NULL, '{"date": "2016-01-02", "hash1": "9420017390c598ee535c24f7bcbd39f40eca699d6c94dc35bcf59ddf918c59ab", "hash2": "70561f58c9e5868f44169854bcc906001947d98d15e9b4d2fbabd1262d938629", "hash3": "0e64e68f6f88b25530699a1cd12f6f2790ea98e6e8fa3b4bc279f8e5c09d7290", "hash4": "69caa2a4070559d4cafdf79020c4356c721088eb22398a8740dea8d21ae6e664", "hash5": "675869fac21a94c8f470765bc6dd15b17cc4492dd639b878f241a45b2c3890fc", "hash6": "e817610b62ccd00bdfc9129f947ac7d078d97525e9628a3aa61027396dba419b", "hash7": "a8b0d084949c4f289beb4950f801bf99588d1b05f68587b245a31e8e82f7a1b8", "hash8": "acf7dc5a10b00f0aac102ecd9d87cd94f08a37b2726cb1e16948875751d04cc9", "hash9": "e21b47dfa9e250f49a3ab327b7444902e545bed3c4dcfa5e2e990af20593af6d", "score": 75, "author": "Florian Roth", "hash10": "e369417a7623d73346f6dff729e68f7e057f7f6dae7bb03d56a7510cb3bfe538", "hash11": "29d8dc863427c8e37b75eb738069c2172e79607acc7b65de6f8086ba36abf051", "hash12": "98fb1d2975babc18624e3922406545458642e01360746870deee397df93f50e0", "hash13": "fbcb401cf06326ab4bb53fb9f01f1ca647f16f926811ea66984f1a1b8cf2f7bb", "reference": "http://goo.gl/V0epcf", "description": "Detect Emissary Malware - from samples A08E81B411.DAT, ishelp.dll"}', '2020-12-04 20:51:08.62339', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-01-02
	Identifier: Emissary Malware
*/

rule Emissary_APT_Malware_1
{

    meta:
        description = "Detect Emissary Malware - from samples A08E81B411.DAT, ishelp.dll"
        author = "Florian Roth"
        reference = "http://goo.gl/V0epcf"
        date = "2016-01-02"
        score = 75
        hash1 = "9420017390c598ee535c24f7bcbd39f40eca699d6c94dc35bcf59ddf918c59ab"
        hash2 = "70561f58c9e5868f44169854bcc906001947d98d15e9b4d2fbabd1262d938629"
        hash3 = "0e64e68f6f88b25530699a1cd12f6f2790ea98e6e8fa3b4bc279f8e5c09d7290"
        hash4 = "69caa2a4070559d4cafdf79020c4356c721088eb22398a8740dea8d21ae6e664"
        hash5 = "675869fac21a94c8f470765bc6dd15b17cc4492dd639b878f241a45b2c3890fc"
        hash6 = "e817610b62ccd00bdfc9129f947ac7d078d97525e9628a3aa61027396dba419b"
        hash7 = "a8b0d084949c4f289beb4950f801bf99588d1b05f68587b245a31e8e82f7a1b8"
        hash8 = "acf7dc5a10b00f0aac102ecd9d87cd94f08a37b2726cb1e16948875751d04cc9"
        hash9 = "e21b47dfa9e250f49a3ab327b7444902e545bed3c4dcfa5e2e990af20593af6d"
        hash10 = "e369417a7623d73346f6dff729e68f7e057f7f6dae7bb03d56a7510cb3bfe538"
        hash11 = "29d8dc863427c8e37b75eb738069c2172e79607acc7b65de6f8086ba36abf051"
        hash12 = "98fb1d2975babc18624e3922406545458642e01360746870deee397df93f50e0"
        hash13 = "fbcb401cf06326ab4bb53fb9f01f1ca647f16f926811ea66984f1a1b8cf2f7bb"

    strings:
        $s1 = "cmd.exe /c %s > %s" fullword ascii
        $s2 = "execute cmd timeout." fullword ascii
        $s3 = "rundll32.exe \"%s\",Setting" fullword ascii
        $s4 = "DownloadFile - exception:%s." fullword ascii
        $s5 = "CDllApp::InitInstance() - Evnet create successful." fullword ascii
        $s6 = "UploadFile - EncryptBuffer Error" fullword ascii
        $s7 = "WinDLL.dll" fullword wide
        $s8 = "DownloadFile - exception:%s,code:0x%08x." fullword ascii
        $s9 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)" fullword ascii
        $s10 = "CDllApp::InitInstance() - Evnet already exists." fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 250KB and 3 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (160, 'rtf_Kaba_jDoe', NULL, '{"date": "2013-12-10", "author": "@patrickrolsen", "maltype": "APT.Kaba", "version": "0.1", "filetype": "RTF", "description": "fe439af268cd3de3a99c21ea40cf493f, d0e0e68a88dce443b24453cc951cf55f, b563af92f144dea7327c9597d9de574e, and def0c9a4c732c3a1e8910db3f9451620"}', '2020-12-04 20:51:08.951863', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule rtf_Kaba_jDoe
{

meta:
    author = "@patrickrolsen"
    maltype = "APT.Kaba"
    filetype = "RTF"
    version = "0.1"
    description = "fe439af268cd3de3a99c21ea40cf493f, d0e0e68a88dce443b24453cc951cf55f, b563af92f144dea7327c9597d9de574e, and def0c9a4c732c3a1e8910db3f9451620"
    date = "2013-12-10"

strings:
    $magic1 = { 7b 5c 72 74 30 31 } // {\rt01
    $magic2 = { 7b 5c 72 74 66 31 } // {\rtf1
    $magic3 = { 7b 5c 72 74 78 61 33 } // {\rtxa3
    $author1 = { 4A 6F 68 6E 20 44 6F 65 } // "John Doe"
    $author2 = { 61 75 74 68 6f 72 20 53 74 6f 6e 65 } // "author Stone"
    $string1 = { 44 30 [16] 43 46 [23] 31 31 45 }

condition:
    ($magic1 or $magic2 or $magic3 at 0) and all of ($author*) and $string1
}

');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (161, 'POS_bruteforcing_bot', NULL, '{"ref": "https://github.com/reed1713", "date": "3/11/2014", "maltype": "botnet", "reference": "http://www.alienvault.com/open-threat-exchange/blog/botnet-bruteforcing-point-of-sale-via-remote-desktop", "description": "botnet bruteforcing POS terms via RDP"}', '2020-12-04 20:51:09.057154', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule POS_bruteforcing_bot
{
	meta:
		maltype = "botnet"
    ref = "https://github.com/reed1713"
		reference = "http://www.alienvault.com/open-threat-exchange/blog/botnet-bruteforcing-point-of-sale-via-remote-desktop"
		date = "3/11/2014"
		description = "botnet bruteforcing POS terms via RDP"
	strings:
		$type="Microsoft-Windows-Security-Auditing"
		$eventid="4688"
		$data="\\AppData\\Roaming\\lsacs.exe"

	condition:
		all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (162, 'diamond_fox', NULL, '{"date": "2015-08-22", "author": "Brian Wallace @botnet_hunter", "description": "Identify DiamondFox", "author_email": "bwall@ballastsecurity.net"}', '2020-12-04 20:51:09.646451', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule diamond_fox
{

    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-08-22"
        description = "Identify DiamondFox"

    strings:
        $s1 = "UPDATE_B"
        $s2 = "UNISTALL_B"
        $s3 = "S_PROTECT"
        $s4 = "P_WALLET"
        $s5 = "GR_COMMAND"
        $s6 = "FTPUPLOAD"

    condition:
        all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (163, 'cryptonar_ransomware', NULL, '{"author": "Marc Rivero | @seifreed", "reference": "https://www.bleepingcomputer.com/news/security/cryptonar-ransomware-discovered-and-quickly-decrypted/", "description": "Rule to detect CryptoNar Ransomware"}', '2020-12-04 20:51:09.75914', 'rule cryptonar_ransomware {

   meta:

      description = "Rule to detect CryptoNar Ransomware"
      author = "Marc Rivero | @seifreed"
      reference = "https://www.bleepingcomputer.com/news/security/cryptonar-ransomware-discovered-and-quickly-decrypted/"

   strings:

      $s1 = "C:\\narnar\\CryptoNar\\CryptoNarDecryptor\\obj\\Debug\\CryptoNar.pdb" fullword ascii
      $s2 = "CryptoNarDecryptor.exe" fullword wide
      $s3 = "server will eliminate the key after 72 hours since its generation (since the moment your computer was infected). Once this has " fullword ascii
      $s4 = "Do not delete this file, else the decryption process will be broken" fullword wide
      $s5 = "key you received, and wait until the decryption process is done." fullword ascii
      $s6 = "In order to receive your decryption key, you will have to pay $200 in bitcoins to this bitcoin address: [bitcoin address]" fullword ascii
      $s7 = "Decryption process failed" fullword wide
      $s8 = "CryptoNarDecryptor.KeyValidationWindow.resources" fullword ascii
      $s9 = "Important note: Removing CryptoNar will not restore access to your encrypted files." fullword ascii
      $s10 = "johnsmith987654@tutanota.com" fullword wide
      $s11 = "Decryption process will start soon" fullword wide
      $s12 = "CryptoNarDecryptor.DecryptionProgressBarForm.resources" fullword ascii
      $s13 = "DecryptionProcessProgressBar" fullword wide
      $s14 = "CryptoNarDecryptor.Properties.Resources.resources" fullword ascii

   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB) and all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (164, 'Windows_Malware_Zeus', '{Zeus_1134}', '{"date": "2014-03-03", "author": "Xylitol xylitol@malwareint.com", "reference": "http://www.xylibox.com/2014/03/zeus-1134.html", "description": "Match first two bytes, protocol and string present in Zeus 1.1.3.4"}', '2020-12-04 20:51:09.865969', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Windows_Malware_Zeus : Zeus_1134
    {
            meta:
                    author = "Xylitol xylitol@malwareint.com"
                    date = "2014-03-03"
                    description = "Match first two bytes, protocol and string present in Zeus 1.1.3.4"
                    reference = "http://www.xylibox.com/2014/03/zeus-1134.html"

            strings:
                    $mz = {4D 5A}
                    $protocol1 = "X_ID: "
                    $protocol2 = "X_OS: "
                    $protocol3 = "X_BV: "
                    $stringR1 = "InitializeSecurityDescriptor"
                    $stringR2 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1)"
            condition:
                    ($mz at 0 and all of ($protocol*) and ($stringR1 or $stringR2))
    }
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (165, 'apt_win32_dll_rat_1a53b0cp32e46g0qio7', NULL, '{"info": "Indicators for FTA-1020", "hash1": "75d3d1f23628122a64a2f1b7ef33f5cf", "hash2": "d9821468315ccd3b9ea03161566ef18e", "hash3": "b9af5f5fd434a65d7aa1b55f5441c90a", "author": "https://www.fidelissecurity.com/", "reference": "https://github.com/fideliscyber"}', '2020-12-04 20:51:09.977464', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule apt_win32_dll_rat_1a53b0cp32e46g0qio7
{
	meta:
		author = "https://www.fidelissecurity.com/"
        	info = "Indicators for FTA-1020"
		hash1 = "75d3d1f23628122a64a2f1b7ef33f5cf"
		hash2 = "d9821468315ccd3b9ea03161566ef18e"
		hash3 = "b9af5f5fd434a65d7aa1b55f5441c90a"
		reference = "https://github.com/fideliscyber"
	strings:
    	// Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0;rv:11.0) like Gecko
		$ = { c7 [2] 64 00 63 00 c7 [2] 69 00 62 00 c7 [2] 7a 00 7e 00 c7 [2] 2d 00 43 00 c7 [2] 59 00 2d 00 c7 [2] 3b 00 23 00 c7 [2] 3e 00 36 00 c7 [2] 2d 00 5a 00 c7 [2] 42 00 5a 00 c7 [2] 3b 00 39 00 c7 [2] 36 00 2d 00 c7 [2] 59 00 7f 00 c7 [2] 64 00 69 00 c7 [2] 68 00 63 00 c7 [2] 79 00 22 00 c7 [2] 3a 00 23 00 c7 [2] 3d 00 36 00 c7 [2] 2d 00 7f 00 c7 [2] 7b 00 37 00 c7 [2] 3c 00 3c 00 c7 [2] 23 00 3d 00 c7 [2] 24 00 2d 00 c7 [2] 61 00 64 00 c7 [2] 66 00 68 00 c7 [2] 2d 00 4a 00 c7 [2] 68 00 6e 00 c7 [2] 66 00 62 00 } // offset 10001566
	// Software\Microsoft\Windows\CurrentVersion\Run
       $ = { c7 [2] 23 00 24 00 c7 [2] 24 00 33 00 c7 [2] 38 00 22 00 c7 [2] 00 00 33 00 c7 [2] 24 00 25 00 c7 [2] 3f 00 39 00 c7 [2] 38 00 0a 00 c7 [2] 04 00 23 00 c7 [2] 38 00 00 00 c7 [2] 43 00 66 00 c7 [2] 6d 00 60 00 c7 [2] 67 00 52 00 c7 [2] 6e 00 63 00 c7 [2] 7b 00 67 00 c7 [2] 70 00 00 00 c7 [2] 43 00 4d 00 c7 [2] 44 00 00 00 c7 [2] 0f 00 43 00 c7 [2] 00 00 50 00 c7 [2] 49 00 4e 00 c7 [2] 47 00 00 00 c7 [2] 11 00 12 00 c7 [2] 17 00 0e 00 c7 [2] 10 00 0e 00 c7 [2] 10 00 0e 00 c7 [2] 11 00 06 00 c7 [2] 44 00 45 00 c7 [2] 4c 00 00 00 } // 10003D09
	$ = { 66 [4-7] 0d 40 83 f8 44 7c ?? }
       // xor		word ptr [ebp+eax*2+var_5C], 14h
	// inc		eax
	// cmp     	eax, 14h
       // Loop to decode a static string. It reveals the "1a53b0cp32e46g0qio9" static string sent in the beacon
	$ = { 66 [4-7] 14 40 83 f8 14 7c ?? } // 100017F0
	$ = { 66 [4-7] 56 40 83 f8 2d 7c ?? } // 10003621
	$ = { 66 [4-7] 20 40 83 f8 1a 7c ?? } // 10003640
	$ = { 80 [2-7] 2e 40 3d 50 02 00 00 72 ?? } //  10003930
	$ = "%08x%08x%08x%08x" wide ascii
	$ = "WinHttpGetIEProxyConfigForCurrentUser" wide ascii

	condition:
	(uint16(0) == 0x5A4D or uint32(0) == 0x4464c457f) and (all of them)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (166, 'ransomware_PetrWrap', NULL, '{"hash": "71B6A493388E7D0B40C83CE903BC6B04", "author": "Kaspersky Lab", "version": "1.0", "copyright": "Kaspersky Lab", "reference": "https://securelist.com/schroedingers-petya/78870/", "description": "Rule to detect PetrWrap ransomware samples", "last_modified": "2017-06-27"}', '2020-12-04 20:51:10.199467', 'rule ransomware_PetrWrap
{
meta:
	copyright= "Kaspersky Lab"
	description = "Rule to detect PetrWrap ransomware samples"
    reference = "https://securelist.com/schroedingers-petya/78870/"
	last_modified = "2017-06-27"
	author = "Kaspersky Lab"
	hash = "71B6A493388E7D0B40C83CE903BC6B04"
	version = "1.0"
strings:
	$a1 = "MIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2n2JmURWV/uHB0ZrlQ/wcYJBwLhQ9EqJ3iDqmN19Oo7NtyEUmbYmopcqYLIBZzQ2ZTK0A2DtX4GRKxEEFLCy7vP12EYOPXknVy/mf0JFWixz29QiTf5oLu15wVLONCuEibGaNNpgqCXsPwfITDbDDmdrRIiUEUw6o3pt5pNOskfOJbMan2TZu" fullword wide
	$a2 = ".3ds.7z.accdb.ai.asp.aspx.avhd.back.bak.c.cfg.conf.cpp.cs.ctl.dbf.disk.djvu.doc.docx.dwg.eml.fdb.gz.h.hdd.kdbx.mail.mdb.msg.nrg.ora.ost.ova.ovf.pdf.php.pmf.ppt.pptx.pst.pvi.py.pyc.rar.rtf.sln.sql.tar.vbox.vbs.vcb.vdi.vfd.vmc.vmdk.vmsd.vmx.vsdx.vsv.work.xls" fullword wide
	$a3 = "DESTROY ALL OF YOUR DATA PLEASE ENSURE THAT YOUR POWER CABLE IS PLUGGED" fullword ascii
	$a4 = "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX" fullword ascii
	$a5 = "wowsmith123456posteo.net." fullword wide
condition:
	uint16(0) == 0x5A4D and filesize < 1000000 and any of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (167, 'easterjackpos', NULL, '{"date": "2014-09-02", "author": "Brian Wallace @botnet_hunter", "description": "Identify JackPOS", "author_email": "bwall@ballastsecurity.net"}', '2020-12-04 20:51:10.428216', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
rule easterjackpos {
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-09-02"
        description = "Identify JackPOS"
	strings:
	    $s1 = "updateinterval="
        $s2 = "cardinterval="
        $s3 = "{[!17!]}{[!18!]}"
    condition:
        all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (168, 'elknot_xor', '{malware}', '{"date": "2016-04-25", "author": "liuya@360.cn", "sample": "474429d9da170e733213940acc9a2b1c, 2579aa65a28c32778790ec1c673abc49", "reference": "http://liuya0904.blogspot.tw/2016/04/new-elknotbillgates-variant-with-xor.html", "description": "elknot/Billgates variants with XOR like C2 encryption scheme"}', '2020-12-04 20:51:11.025067', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule elknot_xor : malware
{
meta:
    author = "liuya@360.cn"
    date = "2016-04-25"
    description = "elknot/Billgates variants with XOR like C2 encryption scheme"
    reference = "http://liuya0904.blogspot.tw/2016/04/new-elknotbillgates-variant-with-xor.html"
    sample = "474429d9da170e733213940acc9a2b1c, 2579aa65a28c32778790ec1c673abc49"

strings:
   //md5=474429d9da170e733213940acc9a2b1c
   /*
   seg000:08130801 68 00 09 13 08                          push    offset dword_8130900
    seg000:08130806 83 3D 30 17 13 08 02                    cmp     ds:dword_8131730, 2
    seg000:0813080D 75 07                                   jnz     short loc_8130816
    seg000:0813080F 81 04 24 00 01 00 00                    add     dword ptr [esp], 100h
    seg000:08130816                         loc_8130816:
    seg000:08130816 50                                      push    eax
    seg000:08130817 E8 15 00 00 00                          call    sub_8130831
    seg000:0813081C E9 C8 F6 F5 FF                          jmp     near ptr 808FEE9h
   */
    $decrypt_c2_func_1 = {08 83 [5] 02 75 07 81 04 24 00 01 00 00 50 e8 [4] e9}

    // md5=2579aa65a28c32778790ec1c673abc49
    /*
    .rodata:08104D20 E8 00 00 00 00                          call    $+5
    .rodata:08104D25 87 1C 24                                xchg    ebx, [esp+4+var_4] ;
    .rodata:08104D28 83 EB 05                                sub     ebx, 5
    .rodata:08104D2B 8D 83 00 FD FF FF                       lea     eax, [ebx-300h]
    .rodata:08104D31 83 BB 10 CA 02 00 02                    cmp     dword ptr [ebx+2CA10h], 2
    .rodata:08104D38 75 05                                   jnz     short loc_8104D3F
    .rodata:08104D3A 05 00 01 00 00                          add     eax, 100h
    .rodata:08104D3F                         loc_8104D3F:
    .rodata:08104D3F 50                                      push    eax
    .rodata:08104D40 FF 74 24 10                             push    [esp+8+strsVector]
*/
$decrypt_c2_func_2 = {e8 00 00 00 00 87 [2] 83 eb 05 8d 83 [4] 83 bb [4] 02 75 05}

condition:
    1 of ($decrypt_c2_func_*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (169, 'universal_1337_stealer_serveur', '{Stealer}', '{"date": "24/02/2013", "author": "Kevin Falcoz", "description": "Universal 1337 Stealer Serveur"}', '2020-12-04 20:51:11.138883', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule universal_1337_stealer_serveur : Stealer
{
	meta:
		author="Kevin Falcoz"
		date="24/02/2013"
		description="Universal 1337 Stealer Serveur"

	strings:
		$signature1={2A 5B 53 2D 50 2D 4C 2D 49 2D 54 5D 2A} /*[S-P-L-I-T]*/
		$signature2={2A 5B 48 2D 45 2D 52 2D 45 5D 2A} /*[H-E-R-E]*/
		$signature3={46 54 50 7E} /*FTP~*/
		$signature4={7E 31 7E 31 7E 30 7E 30} /*~1~1~0~0*/

	condition:
		$signature1 and $signature2 or $signature3 and $signature4
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (170, 'Kovter', NULL, '{"date": "9-19-2016", "maltype": "Kovter", "reference": "http://blog.airbuscybersecurity.com/post/2016/03/FILELESS-MALWARE-%E2%80%93-A-BEHAVIOURAL-ANALYSIS-OF-KOVTER-PERSISTENCE", "description": "fileless malware"}', '2020-12-04 20:51:11.759475', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule Kovter
{
	meta:
		maltype = "Kovter"
    reference = "http://blog.airbuscybersecurity.com/post/2016/03/FILELESS-MALWARE-%E2%80%93-A-BEHAVIOURAL-ANALYSIS-OF-KOVTER-PERSISTENCE"
		date = "9-19-2016"
		description = "fileless malware"
	strings:
		$type="Microsoft-Windows-Security-Auditing" wide ascii
		$eventid="4688" wide ascii
		$data="Windows\\System32\\regsvr32.exe" wide ascii

		$type1="Microsoft-Windows-Security-Auditing" wide ascii
		$eventid1="4689" wide ascii
		$data1="Windows\\System32\\mshta.exe" wide ascii

		$type2="Microsoft-Windows-Security-Auditing" wide ascii
		$eventid2="4689" wide ascii
		$data2="Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" wide ascii

		$type3="Microsoft-Windows-Security-Auditing" wide ascii
		$eventid3="4689" wide ascii
		$data3="Windows\\System32\\wbem\\WmiPrvSE.exe" wide ascii


	condition:
		all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (171, 'Adwind', NULL, '{"author": "Asaf Aprozper, asafa AT minerva-labs.com", "reference": "https://minerva-labs.com/post/adwind-and-other-evasive-java-rats", "description": "Adwind RAT", "last_modified": "2017-06-25"}', '2020-12-04 20:51:11.866006', 'rule Adwind
{
meta:
        author="Asaf Aprozper, asafa AT minerva-labs.com"
        description = "Adwind RAT"
        reference = "https://minerva-labs.com/post/adwind-and-other-evasive-java-rats"
        last_modified = "2017-06-25"
strings:
        $a0 = "META-INF/MANIFEST.MF"
        $a1 = /Main(\$)Q[0-9][0-9][0-9][0-9]/
        $PK = "PK"
condition:
        $PK at 0 and $a0 and $a1
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (172, 'genome', NULL, '{"date": "2014-09-07", "author": "Brian Wallace @botnet_hunter", "description": "Identify Genome", "author_email": "bwall@ballastsecurity.net"}', '2020-12-04 20:51:12.723128', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
rule genome {
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-09-07"
        description = "Identify Genome"
	strings:
	    $s1 = "Attempting to create more than one keyboard::Monitor instance"
        $s2 = "{Right windows}"
        $s3 = "Access violation - no RTTI data!"
    condition:
        all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (173, 'urausy_skype_dat', '{memory}', '{"author": "AlienVault Labs", "description": "Yara rule to match against memory of processes infected by Urausy skype.dat"}', '2020-12-04 20:51:12.831714', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule urausy_skype_dat : memory {
	meta:
		author = "AlienVault Labs"
		description = "Yara rule to match against memory of processes infected by Urausy skype.dat"
	strings:
		$a = "skype.dat" ascii wide
		$b = "skype.ini" ascii wide
		$win1 = "CreateWindow"
		$win2 = "YIWEFHIWQ" ascii wide
		$desk1 = "CreateDesktop"
		$desk2 = "MyDesktop" ascii wide
	condition:
		$a and $b and (all of ($win*) or all of ($desk*))
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (174, 'Payload_Exe2Hex', '{toolkit}', '{"date": "2016-01-15", "score": 70, "author": "Florian Roth", "reference": "https://github.com/g0tmi1k/exe2hex", "description": "Detects payload generated by exe2hex"}', '2020-12-04 20:51:12.936912', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-01-15
	Identifier: Exe2hex
*/

rule Payload_Exe2Hex : toolkit {
	meta:
		description = "Detects payload generated by exe2hex"
		author = "Florian Roth"
		reference = "https://github.com/g0tmi1k/exe2hex"
		date = "2016-01-15"
		score = 70
	strings:
		$a1 = "set /p \"=4d5a" ascii
		$a2 = "powershell -Command \"$hex=" ascii
		$b1 = "set+%2Fp+%22%3D4d5" ascii
		$b2 = "powershell+-Command+%22%24hex" ascii
		$c1 = "echo 4d 5a " ascii
		$c2 = "echo r cx >>" ascii
		$d1 = "echo+4d+5a+" ascii
		$d2 = "echo+r+cx+%3E%3E" ascii
	condition:
		all of ($a*) or all of ($b*) or all of ($c*) or all of ($d*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (182, 'backoff', NULL, '{"date": "2014-08-21", "author": "Brian Wallace @botnet_hunter", "description": "Identify Backoff", "author_email": "bwall@ballastsecurity.net"}', '2020-12-04 20:51:15.170193', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule backoff
{

    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2014-08-21"
        description = "Identify Backoff"

    strings:
        $s1 = "&op=%d&id=%s&ui=%s&wv=%d&gr=%s&bv=%s"
        $s2 = "%s @ %s"
        $s3 = "Upload KeyLogs"

    condition:
        all of them
}

');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (175, 'shrug2_ransomware', NULL, '{"author": "Marc Rivero | @seifreed", "reference": "https://blogs.quickheal.com/new-net-ransomware-shrug2/", "description": "Rule to detect Shrug2 ransomware"}', '2020-12-04 20:51:13.049004', 'rule shrug2_ransomware {

   meta:

      description = "Rule to detect Shrug2 ransomware"
      author = "Marc Rivero | @seifreed"
      reference = "https://blogs.quickheal.com/new-net-ransomware-shrug2/"

   strings:

      $s1 = "C:\\Users\\Gamer\\Desktop\\Shrug2\\ShrugTwo\\ShrugTwo\\obj\\Debug\\ShrugTwo.pdb" fullword ascii
      $s2 = "http://tempacc11vl.000webhostapp.com/" fullword wide
      $s4 = "Shortcut for @ShrugDecryptor@.exe" fullword wide
      $s5 = "C:\\Users\\" fullword wide
      $s6 = "http://clients3.google.com/generate_204" fullword wide
      $s7 = "\\Desktop\\@ShrugDecryptor@.lnk" fullword wide

   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB ) and all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (176, 'Zegost', '{Trojan}', '{"date": "10/06/2013", "author": "Kevin Falcoz", "description": "Zegost Trojan"}', '2020-12-04 20:51:13.713311', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Zegost : Trojan
{
	meta:
		author="Kevin Falcoz"
		date="10/06/2013"
		description="Zegost Trojan"

	strings:
		$signature1={39 2F 66 33 30 4C 69 35 75 62 4F 35 44 4E 41 44 44 78 47 38 73 37 36 32 74 71 59 3D}
		$signature2={00 BA DA 22 51 42 6F 6D 65 00}

	condition:
		$signature1 and $signature2
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (177, 'apt_backspace', NULL, '{"date": "2015-05-14", "hash": "6cbfeb7526de65eb2e3c848acac05da1e885636d17c1c45c62ad37e44cd84f99", "author": "Bit Byte Bitten", "description": "Detects APT backspace"}', '2020-12-04 20:51:13.823547', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule apt_backspace
{

    meta:
        description = "Detects APT backspace"
        author = "Bit Byte Bitten"
        date = "2015-05-14"
        hash = "6cbfeb7526de65eb2e3c848acac05da1e885636d17c1c45c62ad37e44cd84f99"

    strings:
        $s1 = "!! Use Splice Socket !!"
        $s2 = "User-Agent: SJZJ (compatible; MSIE 6.0; Win32)"
        $s3 = "g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d"

    condition:
        uint16(0) == 0x5a4d and all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (178, 'shifu_shiz', NULL, '{"date": "2018-03-16", "author": "J from THL <j@techhelplist.com>", "filetype": "memory", "maltype1": "Banker", "maltype2": "Keylogger", "maltype3": "Stealer", "reference1": "https://researchcenter.paloaltonetworks.com/2017/01/unit42-2016-updates-shifu-banking-trojan/", "reference2": "https://beta.virusbay.io/sample/browse/24a6dfaa98012a839658c143475a1e46", "reference3": "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/crime_shifu_trojan.yar", "description": "Memory string yara for Shifu/Shiz"}', '2020-12-04 20:51:13.940477', '

rule shifu_shiz {
	meta:
		description = "Memory string yara for Shifu/Shiz"
		author = "J from THL <j@techhelplist.com>"
		reference1 = "https://researchcenter.paloaltonetworks.com/2017/01/unit42-2016-updates-shifu-banking-trojan/"
		reference2 = "https://beta.virusbay.io/sample/browse/24a6dfaa98012a839658c143475a1e46"
    reference3 = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/crime_shifu_trojan.yar"
		date = "2018-03-16"
		maltype1 = "Banker"
		maltype2 = "Keylogger"
		maltype3 = "Stealer"
		filetype = "memory"

	strings:
		$aa = "auth_loginByPassword"	fullword ascii
		$ab = "back_command"	fullword ascii
		$ac = "back_custom1"	fullword ascii
		$ad = "GetClipboardData"	fullword ascii
		$ae = "iexplore.exe|opera.exe|java.exe|javaw.exe|explorer.exe|isclient.exe|intpro.exe|ipc_full.exe"	fullword ascii
		$af = "mnp.exe|cbsmain.dll|firefox.exe|clmain.exe|core.exe|maxthon.exe|avant.exe|safari.exe"	fullword ascii
		$ag = "svchost.exe|chrome.exe|notepad.exe|rundll32.exe|netscape.exe|tbb-firefox.exe|frd.exe"	fullword ascii
		$ah = "!inject"	fullword ascii
		$ai = "!deactivebc"	fullword ascii
		$aj = "!kill_os"	fullword ascii
		$ak = "!load"	fullword ascii
		$al = "!new_config"	fullword ascii
		$am = "!activebc"	fullword ascii
		$an = "keylog.txt"	fullword ascii
		$ao = "keys_path.txt"	fullword ascii
		$ap = "pass.log"	fullword ascii
		$aq = "passwords.txt"	fullword ascii
		$ar = "Content-Disposition: form-data; name=\"file\"; filename=\"report\""	fullword ascii
		$as = "Content-Disposition: form-data; name=\"pcname\""	fullword ascii
		$at = "botid=%s&ver="	fullword ascii
		$au = "action=auth&np=&login="	fullword ascii
		$av = "&ctl00%24MainMenu%24Login1%24UserName="	fullword ascii
		$aw = "&cvv="	fullword ascii
		$ax = "&cvv2="	fullword ascii
		$ay = "&domain="	fullword ascii
		$az = "LOGIN_AUTHORIZATION_CODE="	fullword ascii
		$ba = "name=%s&port=%u"	fullword ascii
		$bb = "PeekNamedPipe"	fullword ascii
		$bc = "[pst]"	fullword ascii
		$bd = "[ret]"	fullword ascii
		$be = "[tab]"	fullword ascii
		$bf = "[bks]"	fullword ascii
		$bg = "[del]"	fullword ascii
		$bh = "[ins]"	fullword ascii
		$bi = "&up=%u&os=%03u&rights=%s&ltime=%s%d&token=%d&cn="	fullword ascii

	condition:
		18 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (179, 'APT_bestia', NULL, '{"date": "2014-03-19", "hash0": "9bb03bb5af40d1202378f95a6485fba8", "hash1": "7d9a806e0da0b869b10870dd6c7692c5", "author": "Adam Ziaja <adam@adamziaja.com> http://adamziaja.com", "maltype": "apt", "filetype": "exe", "references": "http://zaufanatrzeciastrona.pl/post/ukierunkowany-atak-na-pracownikow-polskich-samorzadow/", "description": "Bestia.3.02.012.07 malware used in APT attacks on Polish government"}', '2020-12-04 20:51:14.15977', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
rule APT_bestia
{
meta:
    author = "Adam Ziaja <adam@adamziaja.com> http://adamziaja.com"
    date = "2014-03-19"
    description = "Bestia.3.02.012.07 malware used in APT attacks on Polish government"
    references = "http://zaufanatrzeciastrona.pl/post/ukierunkowany-atak-na-pracownikow-polskich-samorzadow/" /* PL */
    hash0 = "9bb03bb5af40d1202378f95a6485fba8"
    hash1 = "7d9a806e0da0b869b10870dd6c7692c5"
    maltype = "apt"
    filetype = "exe"
strings:
    /* generated with https://github.com/Xen0ph0n/YaraGenerator */
    $string0 = "u4(UeK"
    $string1 = "nMiq/''p"
    $string2 = "_9pJMf"
    $string3 = "ICMP.DLL"
    $string4 = "EG}QAp"
    $string5 = "tsjWj:U"
    $string6 = "FileVersion" wide
    $string7 = "O2nQpp"
    $string8 = "2}W8we"
    $string9 = "ILqkC:l"
    $string10 = "f1yzMk"
    $string11 = "AutoIt v3 Script: 3, 3, 8, 1" wide
    $string12 = "wj<1uH"
    $string13 = "6fL-uD"
    $string14 = "B9Iavo<"
    $string15 = "rUS)sO"
    $string16 = "FJH{_/f"
    $string17 = "3e 03V"
condition:
    17 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (180, 'screenlocker_acroware', NULL, '{"author": "Marc Rivero | @seifreed", "reference": "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/", "description": "Rule to detect Acroware ScreenLocker"}', '2020-12-04 20:51:14.27155', 'rule screenlocker_acroware {

   meta:

      description = "Rule to detect Acroware ScreenLocker"
      author = "Marc Rivero | @seifreed"
      reference = "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/"

   strings:

      $s1 = "C:\\Users\\patri\\Documents\\Visual Studio 2015\\Projects\\Advanced Ransi\\Advanced Ransi\\obj\\Debug\\Advanced Ransi.pdb" fullword ascii
      $s2 = "All your Personal Data got encrypted and the decryption key is stored on a hidden" fullword ascii
      $s3 = "alphaoil@mail2tor.com any try of removing this Ransomware will result in an instantly " fullword ascii
      $s4 = "HKEY_CURRENT_USER\\SoftwareE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword wide
      $s5 = "webserver, after 72 hours the decryption key will get removed and your personal" fullword ascii

   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB ) and all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (183, 'XMRIG_Miner', NULL, '{"ref": "https://gist.github.com/GelosSnake/c2d4d6ef6f93ccb7d3afb5b1e26c7b4e"}', '2020-12-04 20:51:15.519378', 'rule XMRIG_Miner
{
	meta:
  ref = "https://gist.github.com/GelosSnake/c2d4d6ef6f93ccb7d3afb5b1e26c7b4e"
  strings:
    $a1 = "stratum+tcp"
    condition:
    $a1
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (184, 'apt_all_JavaScript_ScanboxFramework_obfuscated', NULL, '{"ref": "https://www.fidelissecurity.com/TradeSecret"}', '2020-12-04 20:51:15.750018', '
/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule apt_all_JavaScript_ScanboxFramework_obfuscated

{
              meta:

                    ref = "https://www.fidelissecurity.com/TradeSecret"

                  strings:

              $sa1 = /(var|new|return)\s[_\$]+\s?/

                  $sa2 = "function"

                  $sa3 = "toString"

                  $sa4 = "toUpperCase"

                  $sa5 = "arguments.length"

                  $sa6 = "return"

                  $sa7 = "while"

                  $sa8 = "unescape("

                  $sa9 = "365*10*24*60*60*1000"

                  $sa10 = ">> 2"

                  $sa11 = "& 3) << 4"

                  $sa12 = "& 15) << 2"

                  $sa13 = ">> 6) | 192"

                  $sa14 = "& 63) | 128"

                  $sa15 = ">> 12) | 224"

                  condition:

                  all of them

}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (185, 'APT_Win_Pipcreat', NULL, '{"MD5": "f09d832bea93cf320986b53fce4b8397", "date": "2013-03", "author": "chort (@chort0)", "version": "1.0", "filetype": "pe,dll", "Reference": "http://www.cyberengineeringservices.com/login-exe-analysis-trojan-pipcreat/", "description": "APT backdoor Pipcreat"}', '2020-12-04 20:51:15.967721', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule APT_Win_Pipcreat
{

  meta:
    author = "chort (@chort0)"
    description = "APT backdoor Pipcreat"
    filetype = "pe,dll"
    date = "2013-03"
    MD5 = "f09d832bea93cf320986b53fce4b8397" // (incorrectly?) identified as Hupigon by many AV on VT
    Reference = "http://www.cyberengineeringservices.com/login-exe-analysis-trojan-pipcreat/"
    version = "1.0"

  strings:
    $strA = "pip creat failed" wide fullword
    $strB = "CraatePipe" ascii fullword
    $strC = "are you there? " wide fullword
    $strD = "success kill process ok" wide fullword
    $strE = "Vista|08|Win7" wide fullword
    $rut = "are you there!@#$%^&*()_+" ascii fullword

  condition:
    $rut or (2 of ($str*))
  }
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (186, 'korlia', NULL, '{"author": "Nick Hoffman", "company": "Morphick", "reference": "http://www.morphick.com/resources/lab-blog/curious-korlia", "information": "korlia malware found in apt dump"}', '2020-12-04 20:51:16.080034', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule korlia
{
meta:
author = "Nick Hoffman"
company = "Morphick"
reference = "http://www.morphick.com/resources/lab-blog/curious-korlia"
information = "korlia malware found in apt dump"

//case a
//b2 1f mov dl, 0x1f ; mov key (wildcard)
// -----------------
//8A 86 98 40 00 71 mov al, byte ptr url[esi]
//BF 98 40 00 71 mov edi, offset url
//32 C2 xor al, dl
//83 C9 FF or ecx, 0FFFFFFFFh
//88 86 98 40 00 71 mov byte ptr url[esi], al
//33 C0 xor eax, eax
//46 inc esi
//F2 AE repne scasb
//F7 D1 not ecx
//49 dec ecx
//3B F1 cmp esi, ecx
//72 DE jb short loc_71001DE0

//case b (variant of loop a)
//8A 8A 28 50 40 00 mov cl, byte_405028[edx]
//BF 28 50 40 00 mov edi, offset byte_405028
//32 CB xor cl, bl
//33 C0 xor eax, eax
//88 8A 28 50 40 00 mov byte_405028[edx], cl
//83 C9 FF or ecx, 0FFFFFFFFh
//42 inc edx
//F2 AE repne scasb
//F7 D1 not ecx
//49 dec ecx
//3B D1 cmp edx, ecx
//72 DE jb short loc_4047F2

//case c (not a variant of the above loop)
//8A 0C 28 mov cl, [eax+ebp]
//80 F1 28 xor cl, 28h
//88 0C 28 mov [eax+ebp], cl
//8B 4C 24 14 mov ecx, [esp+0D78h+var_D64]
//40 inc eax
//3B C1 cmp eax, ecx
//7C EE jl short loc_404F1C

strings:
$a = {b2 ?? 8A 86 98 40 00 71 BF 98 40 00 71 32 c2 83 C9 FF 88 86 98 40 00 71 33 C0 46 F2 AE F7 D1 49 3B F1}
$b = {B3 ?? ?? ?? 8A 8A 28 50 40 00 BF 28 50 40 00 32 CB 33 C0 88 8A 28 50 40 00 83 C9 FF 42 F2 AE F7 D1 49 3B D1}
$c = {8A 0C 28 80 F1 ?? 88 0C 28 8B 4C 24 14 40 3B C1}
$d = {00 62 69 73 6F 6E 61 6C 00} //config marker "\x00bisonal\x00"
condition:
any of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (187, 'Grozlex', '{Stealer}', '{"date": "20/08/2013", "author": "Kevin Falcoz", "description": "Grozlex Stealer - Possible HCStealer"}', '2020-12-04 20:51:16.19358', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Grozlex : Stealer
{
	meta:
		author="Kevin Falcoz"
		date="20/08/2013"
		description="Grozlex Stealer - Possible HCStealer"

	strings:
		$signature={4C 00 6F 00 67 00 73 00 20 00 61 00 74 00 74 00 61 00 63 00 68 00 65 00 64 00 20 00 62 00 79 00 20 00 69 00 43 00 6F 00 7A 00 65 00 6E}

	condition:
		$signature
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (188, 'Cythosia', NULL, '{"date": "2015-03-21", "author": "Brian Wallace @botnet_hunter", "description": "Identify Cythosia", "author_email": "bwall@ballastsecurity.net"}', '2020-12-04 20:51:16.41959', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule Cythosia
{

    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-03-21"
        description = "Identify Cythosia"

    strings:
        $str1 = "HarvesterSocksBot.Properties.Resources" wide

    condition:
        all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (189, 'apt_win32_dll_rat_hiZor_RAT', '{RAT}', '{"ref1": "http://www.threatgeek.com/2016/01/introducing-hi-zor-rat.html", "ref2": "https://github.com/Neo23x0/Loki/blob/b187ed063d73d0defc6958100ca7ad04aa77fc12/signatures/apt_hizor_rat.yar", "hash1": "75d3d1f23628122a64a2f1b7ef33f5cf", "hash2": "d9821468315ccd3b9ea03161566ef18e", "hash3": "b9af5f5fd434a65d7aa1b55f5441c90a", "reference": "https://www.fidelissecurity.com/sites/default/files/FTA_1020_Fidelis_Inocnation_FINAL.pdf", "description": "Detects hiZor RAT"}', '2020-12-04 20:51:16.649704', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/
rule apt_win32_dll_rat_hiZor_RAT: RAT
{
	meta:
    description = "Detects hiZor RAT"
		hash1 = "75d3d1f23628122a64a2f1b7ef33f5cf"
		hash2 = "d9821468315ccd3b9ea03161566ef18e"
		hash3 = "b9af5f5fd434a65d7aa1b55f5441c90a"
    ref1 = "http://www.threatgeek.com/2016/01/introducing-hi-zor-rat.html"
    ref2 = "https://github.com/Neo23x0/Loki/blob/b187ed063d73d0defc6958100ca7ad04aa77fc12/signatures/apt_hizor_rat.yar"
    reference = "https://www.fidelissecurity.com/sites/default/files/FTA_1020_Fidelis_Inocnation_FINAL.pdf"
	strings:
		// Part of the encoded User-Agent = Mozilla
		$s1 = { c7 [5] 40 00 62 00 c7 [5] 77 00 64 00 c7 [5] 61 00 61 00 c7 [5] 6c 00 }

		// XOR to decode User-Agent after string stacking 0x10001630
		$s2 = { 66 [7] 0d 40 83 ?? ?? 7c ?? }

		// XOR with 0x2E - 0x10002EF6
		$s3 = { 80 [2] 2e 40 3b ?? 72 ?? }

		$s4 = "CmdProcessExited" wide ascii
		$s5 = "rootDir" wide ascii
		$s6 = "DllRegisterServer" wide ascii
		$s7 = "GetNativeSystemInfo" wide ascii
		$s8 = "%08x%08x%08x%08x" wide ascii
	condition:
		(uint16(0) == 0x5A4D or uint32(0) == 0x4464c457f) and (all of them)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (191, 'IceID_Bank_trojan', NULL, '{"org": "MalwareMustDie", "date": "2018-01-14", "author": "unixfreaxjp", "description": "Detects IcedID..adjusted several times"}', '2020-12-04 20:51:17.109521', '/* Yara rule to detect IcedID banking trojan generic
   This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html)
   and  open to any user or organization, as long as you use it under this license.
*/

import "pe"

rule IceID_Bank_trojan {

	meta:
		description = "Detects IcedID..adjusted several times"
		author = "unixfreaxjp"
		org = "MalwareMustDie"
		date = "2018-01-14"

	strings:
		$header = { 4D 5A }
		$magic1 = { E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A ?? 68 ?? ?? }
		$st01 = "CCmdTarget" fullword nocase wide ascii
		$st02 = "CUserException" fullword nocase wide ascii
		$st03 = "FileType" fullword nocase wide ascii
		$st04 = "FlsGetValue" fullword nocase wide ascii
		$st05 = "AVCShellWrapper@@" fullword nocase wide ascii
		$st06 = "AVCCmdTarget@@" fullword nocase wide ascii
		$st07 = "AUCThreadData@@" fullword nocase wide ascii
		$st08 = "AVCUserException@@" fullword nocase wide ascii

	condition:
		$header at 0 and all of ($magic*) and 6 of ($st0*)
		and pe.sections[0].name contains ".text"
		and pe.sections[1].name contains ".rdata"
		and pe.sections[2].name contains ".data"
		and pe.sections[3].name contains ".rsrc"
		and pe.characteristics & pe.EXECUTABLE_IMAGE
		and pe.characteristics & pe.RELOCS_STRIPPED
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (192, 'Bublik', NULL, '{"date": "29/09/2013", "author": "Kevin Falcoz", "description": "Bublik Trojan Downloader"}', '2020-12-04 20:51:17.329089', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Bublik
{

    meta:
        author="Kevin Falcoz"
        date="29/09/2013"
        description="Bublik Trojan Downloader"

    strings:
        $signature1={63 6F 6E 73 6F 6C 61 73}
        $signature2={63 6C 55 6E 00 69 6E 66 6F 2E 69 6E 69}

    condition:
        $signature1 and $signature2
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (193, 'LuckyCatCode', '{LuckyCat,Family}', '{"author": "Seth Hardy", "description": "LuckyCat code tricks", "last_modified": "2014-06-19"}', '2020-12-04 20:51:17.931426', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule LuckyCatCode : LuckyCat Family
{
    meta:
        description = "LuckyCat code tricks"
        author = "Seth Hardy"
        last_modified = "2014-06-19"

    strings:
        $xordecrypt = { BF 0F 00 00 00 F7 F7 ?? ?? ?? ?? 32 14 39 80 F2 7B }
        $dll = { C6 ?? ?? ?? 64 C6 ?? ?? ?? 6C C6 ?? ?? ?? 6C }
        $commonletters = { B? 63 B? 61 B? 73 B? 65 }

    condition:
        $xordecrypt or ($dll and $commonletters)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (194, 'custom_ssh_backdoor_server', NULL, '{"date": "2015-05-14", "hash": "0953b6c2181249b94282ca5736471f85d80d41c9", "author": "Florian Roth", "reference": "https://goo.gl/S46L3o", "description": "Custome SSH backdoor based on python and paramiko - file server.py"}', '2020-12-04 20:51:18.037562', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule custom_ssh_backdoor_server
{

    meta:
        description = "Custome SSH backdoor based on python and paramiko - file server.py"
        author = "Florian Roth"
        reference = "https://goo.gl/S46L3o"
        date = "2015-05-14"
        hash = "0953b6c2181249b94282ca5736471f85d80d41c9"

    strings:
        $s0 = "command= raw_input(\"Enter command: \").strip(''n'')" fullword ascii
        $s1 = "print ''[-] (Failed to load moduli -- gex will be unsupported.)''" fullword ascii
        $s2 = "print ''[-] Listen/bind/accept failed: '' + str(e)" fullword ascii
        $s3 = "chan.send(command)" fullword ascii
        $s4 = "print ''[-] SSH negotiation failed.''" fullword ascii
        $s5 = "except paramiko.SSHException, x:" fullword ascii

    condition:
        filesize < 10KB and 5 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (195, 'marap', NULL, '{"date": "2018-08-19", "author": " J from THL <j@techhelplist.com>", "maltype": "Downloader", "version": 1, "filetype": "memory", "reference1": "https://www.virustotal.com/#/file/61dfc4d535d86359c2f09dbdd8f14c0a2e6367e5bb7377812f323a94d32341ba/detection", "reference2": "https://www.virustotal.com/#/file/c0c85f93a4f425a23c2659dce11e3b1c8b9353b566751b32fcb76b3d8b723b94/detection", "reference3": "https://threatpost.com/highly-flexible-marap-malware-enters-the-financial-scene/136623/", "reference4": "https://www.bleepingcomputer.com/news/security/necurs-botnet-pushing-new-marap-malware/"}', '2020-12-04 20:51:18.3498', 'rule marap
{

    meta:
        author = " J from THL <j@techhelplist.com>"
        date = "2018-08-19"
        reference1 = "https://www.virustotal.com/#/file/61dfc4d535d86359c2f09dbdd8f14c0a2e6367e5bb7377812f323a94d32341ba/detection"
        reference2 = "https://www.virustotal.com/#/file/c0c85f93a4f425a23c2659dce11e3b1c8b9353b566751b32fcb76b3d8b723b94/detection"
        reference3 = "https://threatpost.com/highly-flexible-marap-malware-enters-the-financial-scene/136623/"
        reference4 = "https://www.bleepingcomputer.com/news/security/necurs-botnet-pushing-new-marap-malware/"
        version = 1
        maltype = "Downloader"
        filetype = "memory"

    strings:
        $text01 = "%02X-%02X-%02X-%02X-%02X-%02X" wide
        $text02 = "%s, base=0x%p" wide
        $text03 = "pid=%d" wide
        $text04 = "%s %s" wide
        $text05 = "%d|%d|%s|%s|%s" wide
        $text06 = "%s|1|%d|%d|%d|%d|%d|%s" wide
        $text07 = "%d#%s#%s#%s#%d#%s#%s#%d#%s#%s#%s#%s#%d" wide
        $text08 = "%s|1|%d|%d|%d|%d|%d|%s#%s#%s#%s#%d#%d#%d" wide
        $text09 = "%s|0|%d" wide
        $text10 = "%llx" wide
        $text11 = "%s -a" wide

    condition:
        7 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (196, 'Bolonyokte', '{rat}', '{"date": "2013-02-01", "author": "Jean-Philippe Teissier / @Jipe_", "version": "1.0", "filetype": "memory", "description": "UnknownDotNet RAT - Bolonyokte"}', '2020-12-04 20:51:18.582006', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule Bolonyokte : rat
{
	meta:
		description = "UnknownDotNet RAT - Bolonyokte"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-02-01"
		filetype = "memory"
		version = "1.0"

	strings:
		$campaign1 = "Bolonyokte" ascii wide
		$campaign2 = "donadoni" ascii wide

		$decoy1 = "nyse.com" ascii wide
		$decoy2 = "NYSEArca_Listing_Fees.pdf" ascii wide
		$decoy3 = "bf13-5d45cb40" ascii wide

		$artifact1 = "Backup.zip"  ascii wide
		$artifact2 = "updates.txt" ascii wide
		$artifact3 = "vdirs.dat" ascii wide
		$artifact4 = "default.dat"
		$artifact5 = "index.html"
		$artifact6 = "mime.dat"

		$func1 = "FtpUrl"
		$func2 = "ScreenCapture"
		$func3 = "CaptureMouse"
		$func4 = "UploadFile"

		$ebanking1 = "Internet Banking" wide
		$ebanking2 = "(Online Banking)|(Online banking)"
		$ebanking3 = "(e-banking)|(e-Banking)" nocase
		$ebanking4 = "login"
		$ebanking5 = "en ligne" wide
		$ebanking6 = "bancaires" wide
		$ebanking7 = "(eBanking)|(Ebanking)" wide
		$ebanking8 = "Anmeldung" wide
		$ebanking9 = "internet banking" nocase wide
		$ebanking10 = "Banking Online" nocase wide
		$ebanking11 = "Web Banking" wide
		$ebanking12 = "Power"

	condition:
		any of ($campaign*) or 2 of ($decoy*) or 2 of ($artifact*) or all of ($func*) or 3 of ($ebanking*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (197, 'Bozok', '{RAT}', '{"ref": "http://malwareconfig.com/stats/Bozok", "date": "2014/04", "author": " Kevin Breen <kevin@techanarchy.net>", "maltype": "Remote Access Trojan", "filetype": "exe"}', '2020-12-04 20:51:18.790145', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/
rule Bozok : RAT
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Bozok"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "getVer" nocase
		$b = "StartVNC" nocase
		$c = "SendCamList" nocase
		$d = "untPlugin" nocase
		$e = "gethostbyname" nocase

	condition:
		all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (198, 'VisualDiscovery_Lonovo_Superfish_SSL_Hijack', NULL, '{"date": "2015/02/19", "hash1": "99af9cfc7ab47f847103b5497b746407dc566963", "hash2": "f0b0cd0227ba302ac9ab4f30d837422c7ae66c46", "hash3": "f12edf2598d8f0732009c5cd1df5d2c559455a0b", "hash4": "343af97d47582c8150d63cbced601113b14fcca6", "author": "Florian Roth / improved by kbandla", "reference": "https://twitter.com/4nc4p/status/568325493558272000", "description": "Lenovo Superfish SSL Interceptor - file VisualDiscovery.exe"}', '2020-12-04 20:51:19.016332', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

/* LENOVO Superfish -------------------------------------------------------- */

rule VisualDiscovery_Lonovo_Superfish_SSL_Hijack {
	meta:
		description = "Lenovo Superfish SSL Interceptor - file VisualDiscovery.exe"
		author = "Florian Roth / improved by kbandla"
		reference = "https://twitter.com/4nc4p/status/568325493558272000"
		date = "2015/02/19"
		hash1 = "99af9cfc7ab47f847103b5497b746407dc566963"
		hash2 = "f0b0cd0227ba302ac9ab4f30d837422c7ae66c46"
		hash3 = "f12edf2598d8f0732009c5cd1df5d2c559455a0b"
		hash4 = "343af97d47582c8150d63cbced601113b14fcca6"
	strings:
		$mz = { 4d 5a }
		//$s1 = "VisualDiscovery.exe" fullword wide
		$s2 = "Invalid key length used to initialize BlowFish." fullword ascii
		$s3 = "GetPCProxyHandler" fullword ascii
		$s4 = "StartPCProxy" fullword ascii
		$s5 = "SetPCProxyHandler" fullword ascii
	condition:
		( $mz at 0 ) and filesize < 2MB and all of ($s*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (199, 'PoS_Malware_MalumPOS', NULL, '{"date": "2015-05-25", "author": "Trend Micro, Inc.", "description": "Used to detect MalumPOS memory dumper", "sample_filtype": "exe"}', '2020-12-04 20:51:19.123511', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"

rule PoS_Malware_MalumPOS
{
    meta:
        author = "Trend Micro, Inc."
        date = "2015-05-25"
        description = "Used to detect MalumPOS memory dumper"
        sample_filtype = "exe"
    strings:
        $string1 = "SOFTWARE\\Borland\\Delphi\\RTL"
        $string2 = "B)[0-9]{13,19}\\"
        $string3 = "[A-Za-z\\s]{0,30}\\/[A-Za-z\\s]{0,30}\\"
        $string4 = "TRegExpr(exec): ExecNext Without Exec[Pos]"
        $string5 = /Y:\\PROGRAMS\\.{20,300}\.pas/
    condition:
        all of ($string*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (200, 'Trojan_W32_Gh0stMiancha_1_0_0', NULL, '{"Date": "2014/01/27", "Author": "Context Threat Intelligence", "Reference": "http://www.contextis.com/documents/30/TA10009_20140127_-_CTI_Threat_Advisory_-_The_Monju_Incident1.pdf", "Description": "Bytes inside"}', '2020-12-04 20:51:19.349796', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "pe"


rule Trojan_W32_Gh0stMiancha_1_0_0
{
    meta:
        Author      = "Context Threat Intelligence"
        Date        = "2014/01/27"
        Description = "Bytes inside"
        Reference   = "http://www.contextis.com/documents/30/TA10009_20140127_-_CTI_Threat_Advisory_-_The_Monju_Incident1.pdf"

    strings:
        $0x = { 57 5b 5a 5a 51 57 40 34 31 67 2e 31 70 34 5c 40 40 44 3b 25 3a 19 1e 5c 7b 67 60 2e 34 31 67 2e 31 70 19 1e 55 77 77 71 64 60 2e 34 3e 3b 3e 19 1e 57 7b 7a 60 71 7a 60 39 40 6d 64 71 2e 34 60 71 6c 60 3b 7c 60 79 78 19 1e 44 66 7b 6c 6d 39 57 7b 7a 7a 71 77 60 7d 7b 7a 2e 34 5f 71 71 64 39 55 78 7d 62 71 19 1e 57 7b 7a 60 71 7a 60 39 78 71 7a 73 60 7c 2e 34 24 19 1e 19 1e }
        $1 = { 5c e7 99 bd e5 8a a0 e9 bb 91 5c }
        $1x = { 48 f3 8d a9 f1 9e b4 fd af 85 48 }
        $2 = "DllCanLoadNow"
        $2x = { 50 78 78 57 75 7a 58 7b 75 70 5a 7b 63 }
        $3x = { 5a 61 79 76 71 66 34 7b 72 34 67 61 76 7f 71 6d 67 2e 34 31 70 }
        $4 = "JXNcc2hlbGxcb3Blblxjb21tYW5k"
        $4x = { 5e 4c 5a 77 77 26 7c 78 76 53 6c 77 76 27 56 78 76 78 6c 7e 76 26 25 60 4d 43 21 7f }
        $5 = "SEFSRFdBUkVcREVTQ1JJUFRJT05cU3lzdGVtXENlbnRyYWxQcm9jZXNzb3JcMA=="
        $5x = { 47 51 52 47 46 52 70 56 41 7f 42 77 46 51 42 40 45 25 5e 5e 41 52 46 5e 40 24 21 77 41 27 78 6e 70 53 42 60 4c 51 5a 78 76 7a 46 6d 4d 43 6c 45 77 79 2d 7e 4e 4c 5a 6e 76 27 5e 77 59 55 29 29 }
        $6 = "C:\\Users\\why\\"
        $6x = { 57 2e 48 41 67 71 66 67 48 63 7c 6d 48 }
        $7 = "g:\\ykcx\\"
        $7x = { 73 2E 48 6D 7F 77 6C 48 }
        $8 = "(miansha)"
        $8x = { 3C 79 7D 75 7A 67 7C 75 3D }
        $9 = "server(\xE5\xA3\xB3)"
        $9x = { 7C 2E 48 26 24 25 27 3A 25 25 3A 26 21 48 67 71 66 62 71 66 3C F1 B7 A7 3D 48 46 71 78 71 75 67 71 48 67 71 66 62 71 66 3A 64 70 76 }
        $cfgDecode = { 8a ?? ?? 80 c2 7a 80 f2 19 88 ?? ?? 41 3b ce 7c ??}

   condition:
       any of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (201, 'TrumpBot', '{MALW}', '{"MD5": "77122e0e6fcf18df9572d80c4eedd88d", "SHA1": "108ee460d4c11ea373b7bba92086dd8023c0654f", "date": "2017-04-16", "author": "Joan Soriano / @joanbtl", "version": "1.0", "description": "TrumpBot"}', '2020-12-04 20:51:19.582422', 'rule TrumpBot : MALW
{
	meta:
		description = "TrumpBot"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "77122e0e6fcf18df9572d80c4eedd88d"
		SHA1 = "108ee460d4c11ea373b7bba92086dd8023c0654f"

	strings:
		$string = "trumpisdaddy"
		$ip = "198.50.154.188"
	condition:
		 all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (202, 'nkminer_monero', NULL, '{"tlp": "white", "author": "cdoman@alienvault.com", "license": "MIT License", "reference": "https://www.alienvault.com/blogs/labs-research/a-north-korean-monero-cryptocurrency-miner", "description": "Detects installer of Monero miner that points to a NK domain"}', '2020-12-04 20:51:19.686345', 'rule nkminer_monero {

 meta:

 description = "Detects installer of Monero miner that points to a NK domain"

 author = "cdoman@alienvault.com"

 reference = "https://www.alienvault.com/blogs/labs-research/a-north-korean-monero-cryptocurrency-miner"

 tlp = "white"

 license = "MIT License"

 strings:

 $a = "82e999fb-a6e0-4094-aa1f-1a306069d1a5" nocase wide ascii

 $b = "4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRy5YeFCqgoUMnzumvS" nocase wide ascii

 $c = "barjuok.ryongnamsan.edu.kp" nocase wide ascii

 $d = "C:\\SoftwaresInstall\\soft" nocase wide ascii

 $e = "C:\\Windows\\Sys64\\intelservice.exe" nocase wide ascii

 $f = "C:\\Windows\\Sys64\\updater.exe" nocase wide ascii

 $g = "C:\\Users\\Jawhar\\documents\\" nocase wide ascii

 condition:

 any of them

}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (203, 'ATM_HelloWorld', '{malware}', '{"date": "2019-01-13", "author": "xylitol@temari.fr", "description": "Search strings and procedure in HelloWorld ATM Malware"}', '2020-12-04 20:51:20.004262', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule ATM_HelloWorld : malware
{
    meta:
        description = "Search strings and procedure in HelloWorld ATM Malware"
        author = "xylitol@temari.fr"
        date = "2019-01-13"

    strings:
        $api1 = "CscCngOpen" ascii wide
        $api2 = "CscCngClose" ascii wide
        $string1 = "%d,%02d;" ascii wide
        $string2 = "MAX_NOTES" ascii wide
        $hex_var1 = { FF 15 ?? ?? ?? ?? BF 00 80 00 00 85 C7 }

    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them
}

');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (204, 'BlackWorm', NULL, '{"date": "2015-05-20", "author": "Brian Wallace @botnet_hunter", "description": "Identify BlackWorm", "author_email": "bwall@ballastsecurity.net"}', '2020-12-04 20:51:20.108307', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule BlackWorm
{

    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-05-20"
        description = "Identify BlackWorm"

    strings:
        $str1 = "m_ComputerObjectProvider"
        $str2 = "MyWebServices"
        $str3 = "get_ExecutablePath"
        $str4 = "get_WebServices"
        $str5 = "My.WebServices"
        $str6 = "My.User"
        $str7 = "m_UserObjectProvider"
        $str8 = "DelegateCallback"
        $str9 = "TargetMethod"
        $str10 = "000004b0" wide
        $str11 = "Microsoft Corporation" wide

    condition:
        all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (205, 'SeaDuke_Sample', NULL, '{"date": "2015-07-14", "hash": "d2e570129a12a47231a1ecb8176fa88a1bf415c51dabd885c513d98b15f75d4e", "score": 70, "author": "Florian Roth", "reference": "http://goo.gl/MJ0c2M", "description": "SeaDuke Malware - file 3eb86b7b067c296ef53e4857a74e09f12c2b84b666fc130d1f58aec18bc74b0d"}', '2020-12-04 20:51:20.233252', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule SeaDuke_Sample
{

    meta:
        description = "SeaDuke Malware - file 3eb86b7b067c296ef53e4857a74e09f12c2b84b666fc130d1f58aec18bc74b0d"
        author = "Florian Roth"
        reference = "http://goo.gl/MJ0c2M"
        date = "2015-07-14"
        score = 70
        hash = "d2e570129a12a47231a1ecb8176fa88a1bf415c51dabd885c513d98b15f75d4e"

    strings:
        $s0 = "bpython27.dll" fullword ascii
        $s1 = "email.header(" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "LogonUI.exe" fullword wide /* PEStudio Blacklist: strings */
        $s3 = "Crypto.Cipher.AES(" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "mod is NULL - %s" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 4000KB and all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (206, 'SnakeRansomware', NULL, '{"Data": "15th May 2020", "Author": "Nishan Maharjan", "Reference": "https://medium.com/@nishanmaharjan17/malware-analysis-snake-ransomware-a0e66f487017", "Description": "A yara rule to catch snake ransomware"}', '2020-12-04 20:51:20.34165', 'rule SnakeRansomware
{
    meta:
        Author = "Nishan Maharjan"
        Description = "A yara rule to catch snake ransomware"
        Reference = "https://medium.com/@nishanmaharjan17/malware-analysis-snake-ransomware-a0e66f487017"
        Data = "15th May 2020"
    strings:
        $go_build_id = "Go build ID: \"X6lNEpDhc_qgQl56x4du/fgVJOqLlPCCIekQhFnHL/rkxe6tXCg56Ez88otHrz/Y-lXW-OhiIbzg3-ioGRz\""
        $math_rand_seed_calling = { 89 C8 BB 00 CA 9A 3B 89 D1 F7 E3 81 E1 FF FF FF 3F 89 C3 01 C8 89 C6 05 00 00 1A 3D 89 04 24 69 ED 00 CA 9A 3B 01 EA 89 CD C1 F9 1F 01 EB 11 CA 81 C6 00 00 1A 3D 81 D2 EB 03 B2 A1 89 54 24 04 E8 10 62 F6 FF }
        $encryption_function = {64 8B 0D 14 00 00 00 8B 89 00 00 00 00 3B 61 08 0F 86 38 01 00 00 83 EC 3C E8 32 1A F3 FF 8D 7C 24 28 89 E6 E8 25 EA F0 FF 8B 44 24 2C 8B 4C 24 28 89 C2 C1 E8 1F C1 E0 1F 85 C0 0F 84 FC 00 00 00 D1 E2 89 CB C1 E9 1F 09 D1 89 DA D1 E3 C1 EB 1F 89 CD D1 E1 09 D9 89 CB 81 C1 80 7F B1 D7 C1 ED 1F 81 C3 80 7F B1 D7 83 D5 0D 89 C8 BB 00 CA 9A 3B 89 D1 F7 E3 81 E1 FF FF FF 3F 89 C3 01 C8 89 C6 05 00 00 1A 3D 89 04 24 69 ED 00 CA 9A 3B 01 EA 89 CD C1 F9 1F 01 EB 11 CA 81 C6 00 00 1A 3D 81 D2 EB 03 B2 A1 89 54 24 04 E8 10 62 F6 FF 31 C0 EB 79 89 44 24 20 8B 4C 24 40 8D 14 C1 8B 1A 89 5C 24 24 8B 52 04 89 54 24 1C C7 04 24 05 00 00 00 E8 48 FE FF FF 8B 44 24 08 8B 4C 24 04 C7 04 24 00 00 00 00 8B 54 24 24 89 54 24 04 8B 5C 24 1C 89 5C 24 08 89 4C 24 0C 89 44 24 10 E8 EC DD EF FF 8B 44 24 18 8B 4C 24 14 89 4C 24 08 89 44 24 0C 8B 44 24 24 89 04 24 8B 44 24 1C 89 44 24 04 E8 68 BB F3 FF 8B 44 24 20 40}
    condition:
        all of them
}


');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (207, 'sendsafe', NULL, '{"date": "2016/09", "author": " J from THL <j@techhelplist.com>", "maltype": "Spammer", "version": 2, "filetype": "memory", "reference": "http://pastebin.com/WPWWs406"}', '2020-12-04 20:51:20.464418', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/



rule sendsafe {

    meta:
        author = " J from THL <j@techhelplist.com>"
        date = "2016/09"
        reference = "http://pastebin.com/WPWWs406"
		version = 2
        maltype = "Spammer"
        filetype = "memory"

    strings:
        $a = "Enterprise Mailing Service"
        $b = "Blacklisted by rule: %s:%s"
        $c = "/SuccessMails?CampaignNum=%ld"
        $d = "/TimedOutMails?CampaignNum=%ld"
        $e = "/InvalidMails?CampaignNum=%ld"
        $f = "Failed to download maillist, retrying"
        $g = "No maillist loaded"
        $h = "Successfully sent using SMTP account %s (%d of %ld messages to %s)"
        $i = "Successfully sent %d of %ld messages to %s"
        $j = "Sending to %s in the same connection"
        $k = "New connection required, will send to %s"
		$l = "Mail transaction for %s is over."
		$m = "Domain %s is bad (found in cache)"
		$n = "Domain %s found in cache"
		$o = "Domain %s isn''t found in cache, resolving it"
		$p = "All tries to resolve %s failed."
		$q = "Failed to receive response for %s from DNS server"
		$r = "Got DNS server response: domain %s is bad"
		$s = "Got error %d in response for %s from DNS server"
		$t = "MX''s IP for domain %s found in cache:"
		$u = "Timeout waiting for domain %s to be resolved"
		$v = "No valid MXes for domain %s. Marking it as bad"
		$w = "Resolving MX %s using existing connection to DNS server"
		$x = "All tries to resolve MX for %s are failed"
		$y = "Resolving MX %s using DNS server"
		$z = "Failed to receive response for MX %s from DNS server"

    condition:
        13 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (208, 'fire2013', '{webshell}', '{"date": "2016/07/18", "author": "Vlad https://github.com/vlad-s", "description": "Catches a webshell"}', '2020-12-04 20:51:21.635496', '/*
    Webshell "fire2013.php" - shell apended to PHP!Anuna code,
    found in the wild both appended and single.

    Shell prints a fake "404 not found" Apache message, while
    the user has to post "pass=Fuck1950xx=" to enable it.

    As written in the original (decoded PHP) file,
    @define(''VERSION'', ''v4 by Sp4nksta'');

    Shell is also backdoored, it mails the shell location and
    info on "h4x4rwow@yahoo.com" as written in the "system32()"
    function.
*/
rule fire2013 : webshell
{
    meta:
        author      = "Vlad https://github.com/vlad-s"
        date        = "2016/07/18"
        description = "Catches a webshell"
    strings:
        $a = "eval(\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61"
        $b = "yc0CJYb+O//Xgj9/y+U/dd//vkf''\\x29\\x29\\x29\\x3B\")"
    condition:
        all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (209, 'Backdoor_WebShell_asp', '{ASPXSpy}', '{"date": "2019-02-26", "author": "xylitol@temari.fr", "description": "Detect ASPXSpy"}', '2020-12-04 20:51:21.748124', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule Backdoor_WebShell_asp : ASPXSpy
{
    meta:
    description= "Detect ASPXSpy"
    author = "xylitol@temari.fr"
    date = "2019-02-26"
    // May only the challenge guide you
    strings:
    $string1 = "CmdShell" wide ascii
    $string2 = "ADSViewer" wide ascii
    $string3 = "ASPXSpy.Bin" wide ascii
    $string4 = "PortScan" wide ascii
    $plugin = "Test.AspxSpyPlugins" wide ascii

    condition:
    3 of ($string*) or $plugin
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (210, 'php_anuna', NULL, '{"date": "2016/07/18", "author": "Vlad https://github.com/vlad-s", "description": "Catches a PHP Trojan"}', '2020-12-04 20:51:22.106894', '/*
    I first found this in May 2016, appeared in every PHP file on the
    server, cleaned it with `sed` and regex magic. Second time was
    in June 2016, same decoded content, different encoding/naming.

    https://www.symantec.com/security_response/writeup.jsp?docid=2015-111911-4342-99
*/
rule php_anuna
{
    meta:
        author      = "Vlad https://github.com/vlad-s"
        date        = "2016/07/18"
        description = "Catches a PHP Trojan"
    strings:
        $a = /<\?php \$[a-z]+ = ''/
        $b = /\$[a-z]+=explode\(chr\(\([0-9]+[-+][0-9]+\)\)/
        $c = /\$[a-z]+=\([0-9]+[-+][0-9]+\)/
        $d = /if \(!function_exists\(''[a-z]+''\)\)/
    condition:
        all of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (211, 'Dotico_PHP_webshell', '{webshell}', '{"date": "2019/12/04", "author": "Luis Fueris", "reference": "https://rankinstudio.com/Drupal_ico_index_hack", "description": ".ico PHP webshell - file <eight-num-letter-chars>.ico"}', '2020-12-04 20:51:22.230071', '/*
This Yara ruleset is under the GNU-GPLv2 license
(http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or
organization, as long as you use it under this license.
*/

/*
Author: Luis Fueris
Date: 4 october, 2019
Description: Drupalgeddon 2 - Web Shells Extract. This rules matchs with
webshells that inserts the Drupal core vulnerability SA-CORE-2018-002
(https://www.drupal.org/sa-core-2018-002)
*/

rule Dotico_PHP_webshell : webshell {
    meta:
        description = ".ico PHP webshell - file <eight-num-letter-chars>.ico"
        author = "Luis Fueris"
        reference = "https://rankinstudio.com/Drupal_ico_index_hack"
        date = "2019/12/04"
    strings:
        $php = "<?php" ascii
        $regexp = /basename\/\*[a-z0-9]{,6}\*\/\(\/\*[a-z0-9]{,5}\*\/trim\/\*[a-z0-9]{,5}\*\/\(\/\*[a-z0-9]{,5}\*\//
    condition:
        $php at 0 and $regexp and filesize > 70KB and filesize < 110KB
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (212, 'php_in_image', NULL, '{"date": "2016/07/18", "author": "Vlad https://github.com/vlad-s", "description": "Finds image files w/ PHP code in images"}', '2020-12-04 20:51:22.334659', '/*
    Finds PHP code in JP(E)Gs, GIFs, PNGs.
    Magic numbers via Wikipedia.
*/
rule php_in_image
{
    meta:
        author      = "Vlad https://github.com/vlad-s"
        date        = "2016/07/18"
        description = "Finds image files w/ PHP code in images"
    strings:
        $gif = /^GIF8[79]a/
        $jfif = { ff d8 ff e? 00 10 4a 46 49 46 }
        $png = { 89 50 4e 47 0d 0a 1a 0a }

        $php_tag = "<?php"
    condition:
        (($gif at 0) or
        ($jfif at 0) or
        ($png at 0)) and

        $php_tag
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (213, 'Android_Dogspectus', NULL, '{"date": "20-July-2016", "author": "Jacob Soo Lead Re", "source": "https://www.bluecoat.com/security-blog/2016-04-25/android-exploit-delivers-dogspectus-ransomware", "description": "This rule try to detects Dogspectus"}', '2020-12-04 20:51:22.971781', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "androguard"

rule Android_Dogspectus
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "20-July-2016"
		description = "This rule try to detects Dogspectus"
		source = "https://www.bluecoat.com/security-blog/2016-04-25/android-exploit-delivers-dogspectus-ransomware"

	condition:
		androguard.activity(/PanickedActivity/i) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/i) and
		androguard.permission(/android.permission.INTERNET/i) and
		androguard.permission(/android.permission.WAKE_LOCK/i)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (214, 'andr_tordow', NULL, '{"author": "https://twitter.com/5h1vang", "source": "https://securelist.com/blog/mobile/76101/the-banker-that-can-steal-anything/", "description": "Yara for variants of Trojan-Banker.AndroidOS.Tordow. Test rule"}', '2020-12-04 20:51:23.08368', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/
import "androguard"


rule andr_tordow
{
	meta:
		description = "Yara for variants of Trojan-Banker.AndroidOS.Tordow. Test rule"
		source = "https://securelist.com/blog/mobile/76101/the-banker-that-can-steal-anything/"
		author = "https://twitter.com/5h1vang"

	condition:
		androguard.package_name("com.di2.two") or
		(androguard.activity(/API2Service/i) and
		androguard.activity(/CryptoUtil/i) and
		androguard.activity(/Loader/i) and
		androguard.activity(/Logger/i) and
		androguard.permission(/android.permission.INTERNET/)) or

		//Certificate check based on @stevenchan''s comment
		androguard.certificate.sha1("78F162D2CC7366754649A806CF17080682FE538C") or
		androguard.certificate.sha1("BBA26351CE41ACBE5FA84C9CF331D768CEDD768F") or
		androguard.certificate.sha1("0B7C3BC97B6D7C228F456304F5E1B75797B7265E")
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (215, 'Banker_Acecard', NULL, '{"author": "https://twitter.com/SadFud75", "samples_sha1": "ad9fff7fd019cf2a2684db650ea542fdeaaeaebb 53cca0a642d2f120dea289d4c7bd0d644a121252", "more_information": "https://threats.kaspersky.com/en/threat/Trojan-Banker.AndroidOS.Acecard/"}', '2020-12-04 20:51:23.198449', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/
import "androguard"

rule Banker_Acecard
{
meta:
author = "https://twitter.com/SadFud75"
more_information = "https://threats.kaspersky.com/en/threat/Trojan-Banker.AndroidOS.Acecard/"
samples_sha1 = "ad9fff7fd019cf2a2684db650ea542fdeaaeaebb 53cca0a642d2f120dea289d4c7bd0d644a121252"
strings:
$str_1 = "Cardholder name"
$str_2 = "instagram.php"
condition:
((androguard.package_name("starter.fl") and androguard.service("starter.CosmetiqFlServicesCallHeadlessSmsSendService")) or androguard.package_name("cosmetiq.fl") or all of ($str_*)) and androguard.permissions_number > 19
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (216, 'android_tempting_cedar_spyware', NULL, '{"Date": "2018-03-06", "Author": "@X0RC1SM", "Reference": "https://blog.avast.com/avast-tracks-down-tempting-cedar-spyware"}', '2020-12-04 20:51:23.308086', 'rule android_tempting_cedar_spyware
{
	meta:
    	Author = "@X0RC1SM"
        Date = "2018-03-06"
        Reference = "https://blog.avast.com/avast-tracks-down-tempting-cedar-spyware"
	strings:
		$PK_HEADER = {50 4B 03 04}
		$MANIFEST = "META-INF/MANIFEST.MF"
		$DEX_FILE = "classes.dex"
		$string = "rsdroid.crt"

	condition:
    	$PK_HEADER in (0..4) and $MANIFEST and $DEX_FILE and any of ($string*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (218, 'backdoor', '{dropper}', '{"author": "Antonio Sanchez <asanchez@koodous.com>", "sample": "0c3bc51952c71e5bb05c35346005da3baa098faf3911b9b45c3487844de9f539", "source": "https://koodous.com/rulesets/1765", "description": "This rule detects fake samples with a backdoor/dropper"}', '2020-12-04 20:51:23.700292', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and
    open to any user or organization, as long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.
	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule backdoor: dropper
{
	meta:
		author = "Antonio Sanchez <asanchez@koodous.com>"
		description = "This rule detects fake samples with a backdoor/dropper"
		sample = "0c3bc51952c71e5bb05c35346005da3baa098faf3911b9b45c3487844de9f539"
		source = "https://koodous.com/rulesets/1765"

	condition:
		androguard.url("http://sys.wksnkys7.com")
		or androguard.url("http://sys.hdyfhpoi.com")
		or androguard.url("http://sys.syllyq1n.com")
		or androguard.url("http://sys.aedxdrcb.com")
		or androguard.url("http://sys.aedxdrcb.com")
}');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (219, 'finspy', '{cdshide,android}', '{"date": "2020/01/07", "author": "Thorsten Schröder - ths @ ccc.de (https://twitter.com/__ths__)", "sample": "c2ce202e6e08c41e8f7a0b15e7d0781704e17f8ed52d1b2ad7212ac29926436e", "reference1": "https://github.com/devio/FinSpy-Tools", "reference2": "https://github.com/Linuzifer/FinSpy-Dokumentation", "reference3": "https://www.ccc.de/de/updates/2019/finspy", "description": "Detect Gamma/FinFisher FinSpy for Android #GovWare"}', '2020-12-04 20:51:23.803182', '// Published under the GNU-GPLv2 license. It’s open to any user or organization,
//    as long as you use it under this license.

rule finspy : cdshide android
{

	meta:
		description = "Detect Gamma/FinFisher FinSpy for Android #GovWare"
		date = "2020/01/07"
		author = "Thorsten Schröder - ths @ ccc.de (https://twitter.com/__ths__)"
		reference1 = "https://github.com/devio/FinSpy-Tools"
		reference2 = "https://github.com/Linuzifer/FinSpy-Dokumentation"
		reference3 = "https://www.ccc.de/de/updates/2019/finspy"
		sample = "c2ce202e6e08c41e8f7a0b15e7d0781704e17f8ed52d1b2ad7212ac29926436e"

	strings:
		$re = /\x50\x4B\x01\x02[\x00-\xff]{32}[A-Za-z0-9+\/]{6}/

	condition:
		$re and (#re > 50)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (220, 'adware', '{ads,android}', '{"author": "Fernando Denis Ramirez https://twitter.com/fdrg21", "sample": "5a331231f997decca388ba2d73b7dec1554e966a0795b0cb8447a336bdafd71b", "reference": "https://koodous.com/", "description": "Adware"}', '2020-12-04 20:51:23.914772', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule adware : ads android
{
	meta:
		author = "Fernando Denis Ramirez https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "Adware"
		sample = "5a331231f997decca388ba2d73b7dec1554e966a0795b0cb8447a336bdafd71b"

	strings:
		$string_a = "banner_layout"
		$string_b = "activity_adpath_sms"
		$string_c = "adpath_title_one"
		$string_d = "7291-2ec9362bd699d0cd6f53a5ca6cd"

	condition:
		all of ($string_*)

}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (221, 'Android_pinkLocker', '{android}', '{"ref1": "https://www.virustotal.com/es/file/388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d/analysis/", "ref2": "https://analyst.koodous.com/rulesets/1186", "author": "@5h1vang", "sample": "388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d", "description": "Yara detection for Android Locker app named Pink Club"}', '2020-12-04 20:51:24.026126', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/
/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule Android_pinkLocker : android
{
	meta:
		description = "Yara detection for Android Locker app named Pink Club"
		author = "@5h1vang"
		ref1 = "https://www.virustotal.com/es/file/388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d/analysis/"
		ref2 = "https://analyst.koodous.com/rulesets/1186"
		sample = "388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d"

	strings:
		$str_1 = "arnrsiec sisani"
		$str_2 = "rhguecisoijng ts"
		$str_3 = "assets/data.db"
		$str_4 = "res/xml/device_admin_sample.xmlPK"

	condition:
		androguard.url(/lineout\.pw/) or
		androguard.certificate.sha1("D88B53449F6CAC93E65CA5E224A5EAD3E990921E") or
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.DISABLE_KEYGUARD/) and
		all of ($str_*)

}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (222, 'android_overlayer', NULL, '{"author": "https://twitter.com/5h1vang", "source": "https://www.zscaler.com/blogs/research/android-banker-malware-goes-social", "description": "This rule detects the banker trojan with overlaying functionality"}', '2020-12-04 20:51:24.344704', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "androguard"

rule android_overlayer
{
	meta:
		description = "This rule detects the banker trojan with overlaying functionality"
		source =  "https://www.zscaler.com/blogs/research/android-banker-malware-goes-social"
		author = "https://twitter.com/5h1vang"

	strings:
		$str_1 = "tel:"
		$str_2 = "lockNow" nocase
		$str_3 = "android.app.action.ADD_DEVICE_ADMIN"
		$str_4 = "Cmd_conf" nocase
		$str_5 = "Sms_conf" nocase
		$str_6 = "filter2"

	condition:
		androguard.certificate.sha1("6994ED892E7F0019BCA74B5847C6D5113391D127") or

		(androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_SMS/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		all of ($str_*))
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (223, 'SlemBunk', '{android}', '{"author": "@plutec_net", "sample": "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b", "source": "https://www.fireeye.com/blog/threat-research/2015/12/slembunk_an_evolvin.html", "description": "Rule to detect trojans imitating banks of North America, Eurpope and Asia"}', '2020-12-04 20:51:24.470666', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/


rule SlemBunk : android
{
	meta:
		description = "Rule to detect trojans imitating banks of North America, Eurpope and Asia"
		author = "@plutec_net"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
		source = "https://www.fireeye.com/blog/threat-research/2015/12/slembunk_an_evolvin.html"

	strings:
		$a = "#intercept_sms_start"
		$b = "#intercept_sms_stop"
		$c = "#block_numbers"
		$d = "#wipe_data"
		$e = "Visa Electron"

	condition:
		all of them

}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (224, 'Android_Switcher', NULL, '{"author": "https://twitter.com/5h1vang", "sample": "d3aee0e8fa264a33f77bdd59d95759de8f6d4ed6790726e191e39bcfd7b5e150", "source": "https://securelist.com/blog/mobile/76969/switcher-android-joins-the-attack-the-router-club/", "source2": "https://koodous.com/rulesets/2049", "description": "This rule detects Android wifi Switcher variants"}', '2020-12-04 20:51:24.576894', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"


rule Android_Switcher
{
	meta:
		description = "This rule detects Android wifi Switcher variants"
		sample = "d3aee0e8fa264a33f77bdd59d95759de8f6d4ed6790726e191e39bcfd7b5e150"
		source = "https://securelist.com/blog/mobile/76969/switcher-android-joins-the-attack-the-router-club/"
    source2 = "https://koodous.com/rulesets/2049"
    author = "https://twitter.com/5h1vang"

	strings:
		$str_1 = "javascript:scrollTo"
		$str_5 = "javascript:document.getElementById(''dns1'')"
		$str_6 = "admin:"

		$dns_2 = "101.200.147.153"
		$dns_3 = "112.33.13.11"
		$dns_4 = "120.76.249.59"


	condition:
		androguard.certificate.sha1("2421686AE7D976D19AB72DA1BDE273C537D2D4F9") or
		(androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.ACCESS_WIFI_STATE/) and
		($dns_2 or $dns_3 or $dns_4) and all of ($str_*))
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (225, 'Android_AliPay_smsStealer', '{android}', '{"ref": "https://analyst.koodous.com/rulesets/1192", "author": "https://twitter.com/5h1vang", "sample": "f4794dd02d35d4ea95c51d23ba182675cc3528f42f4fa9f50e2d245c08ecf06b", "source": "http://research.zscaler.com/2016/02/fake-security-app-for-alipay-customers.html", "description": "Yara rule for detection of Fake AliPay Sms Stealer"}', '2020-12-04 20:51:24.688785', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule Android_AliPay_smsStealer : android
{
	meta:
		description = "Yara rule for detection of Fake AliPay Sms Stealer"
		sample = "f4794dd02d35d4ea95c51d23ba182675cc3528f42f4fa9f50e2d245c08ecf06b"
		source = "http://research.zscaler.com/2016/02/fake-security-app-for-alipay-customers.html"
		ref = "https://analyst.koodous.com/rulesets/1192"
		author = "https://twitter.com/5h1vang"

	strings:
		$str_1 = "START_SERVICE"
		$str_2 = "extra_key_sms"
		$str_3 = "android.provider.Telephony.SMS_RECEIVED"
		$str_4 = "mPhoneNumber"

	condition:
		androguard.certificate.sha1("0CDFC700D0BDDC3EA50D71B54594BF3711D0F5B2") or
		androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		all of ($str_*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (226, 'Trojan_Droidjack', NULL, '{"author": "https://twitter.com/SadFud75"}', '2020-12-04 20:51:25.014245', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule Trojan_Droidjack
{
meta:
author = "https://twitter.com/SadFud75"
condition:
androguard.package_name("net.droidjack.server") or androguard.activity(/net.droidjack.server/i)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (227, 'Android_DeathRing', NULL, '{"date": "06-June-2016", "author": "Jacob Soo Lead Re", "source": "https://blog.lookout.com/blog/2014/12/04/deathring/", "description": "DeathRing is a Chinese Trojan that is pre-installed on a number of smartphones most popular in Asian and African countries. Detection volumes are moderate, though we consider this a concerning threat given its pre-loaded nature and the fact that we are actively seeing detections of it around the world."}', '2020-12-04 20:51:25.127807', 'import "androguard"

rule Android_DeathRing
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "06-June-2016"
		description = "DeathRing is a Chinese Trojan that is pre-installed on a number of smartphones most popular in Asian and African countries. Detection volumes are moderate, though we consider this a concerning threat given its pre-loaded nature and the fact that we are actively seeing detections of it around the world."
		source = "https://blog.lookout.com/blog/2014/12/04/deathring/"

	condition:
		androguard.service(/MainOsService/i) and
        androguard.receiver(/ApkUninstallReceiver/i)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (228, 'SpyNet', '{malware}', '{"sample": "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b", "description": "Ruleset to detect SpyNetV2 samples. "}', '2020-12-04 20:51:25.34606', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

rule SpyNet : malware
{
	meta:
		description = "Ruleset to detect SpyNetV2 samples. "
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	strings:
	$a = "odNotice.txt"
	$b = "camera This device has camera!"
	$c = "camera This device has Nooo camera!"
	$d = "send|1sBdBBbbBBF|K|"
	$e = "send|372|ScreamSMS|senssd"
	$f = "send|5ms5gs5annc"
	$g = "send|45CLCLCa01"
	$h = "send|999SAnd|TimeStart"
	$i = "!s!c!r!e!a!m!"
	condition:
		4 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (229, 'hacking_team', '{stcert,android}', '{"author": "Fernando Denis https://twitter.com/fdrg21", "samples": "c605df5dbb9d9fb1d687d59e4d90eba55b3201f8dd4fa51ec80aa3780d6e3e6e", "reference": "https://koodous.com/", "description": "This rule detects the apk related to hackingteam - These certificates are presents in mailboxes od hackingteam"}', '2020-12-04 20:51:25.686043', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule hacking_team : stcert android
{
	meta:
		author = "Fernando Denis https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "This rule detects the apk related to hackingteam - These certificates are presents in mailboxes od hackingteam"
		samples = "c605df5dbb9d9fb1d687d59e4d90eba55b3201f8dd4fa51ec80aa3780d6e3e6e"

	strings:
		$string_a_1 = "280128120000Z0W1"
		$string_a_2 = "E6FFF4C5062FBDC9"
		$string_a_3 = "886FEC93A75D2AC1"
		$string_a_4 = "121120104150Z"

		$string_b_1 = "&inbox_timestamp > 0 and is_permanent=1"
		$string_b_2 = "contact_id = ? AND mimetype = ?"

		$string_c = "863d9effe70187254d3c5e9c76613a99"

		$string_d = "nv-sa1"

	condition:
		(any of ($string_a_*) and any of ($string_b_*) and $string_c and $string_d) or
		androguard.certificate.sha1("B1BC968BD4F49D622AA89A81F2150152A41D829C") or
		androguard.certificate.sha1("3FEC88BA49773680E2A3040483806F56E6E8502E") or
		androguard.certificate.sha1("B0A4A4880FA5345D6B3B00C0C588A39815D3872E") or
		androguard.certificate.sha1("EC2184676D4AE153E63987326666BA0C554A4A60") or
		androguard.certificate.sha1("A7394CBAB09D35C69DA7FABB1A7870BE987A5F77")	or
		androguard.certificate.sha1("A1131C7F816D65670567D6C7041F30E380754022") or
		androguard.certificate.sha1("4E40663CC29C1FE7A436810C79CAB8F52474133B") or
		androguard.certificate.sha1("159B4F6C03D43F27339E06ABFD2DE8D8D65516BC") or
		androguard.certificate.sha1("3EEE4E45B174405D64F877EFC7E5905DCCD73816") or
		androguard.certificate.sha1("9CE815802A672B75C078D920A5D506BBBAC0D5C9") or
		androguard.certificate.sha1("C4CF31DBEF79393FD2AD617E79C27BFCF19EFBB3") or
		androguard.certificate.sha1("2125821BC97CF4B7591E5C771C06C9C96D24DF8F")
		//97257C6D8F6DA60EA27D2388D9AE252657FF3304 this certification could be stolen
		//03EA873D5D13707B0C278A0055E452416054E27B this certification could be stolen
		//B8D5E3F0BCAD2EB03BB34AEE2B3F63FC5162C56B this certification could be stolen
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (241, 'tinhvan', '{android}', '{"author": "https://twitter.com/plutec_net", "sample": "0f7e995ff7075af2d0f8d60322975d610e888884922a89fda9a61c228374c5c5", "reference": "https://koodous.com/"}', '2020-12-04 20:51:27.358391', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule tinhvan : android
{
	meta:
	  author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
		sample = "0f7e995ff7075af2d0f8d60322975d610e888884922a89fda9a61c228374c5c5"

	condition:
		androguard.certificate.sha1("0DFBBDB7735517748C3DEF3B6DEC2A800182D1D5")

}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (230, 'spyAgent', NULL, '{"author": "@koodous_project", "sample": "7cbf61fbb31c26530cafb46282f5c90bc10fe5c724442b8d1a0b87a8125204cb", "reference": "https://blogs.mcafee.com/mcafee-labs/android-spyware-targets-security-job-seekers-in-saudi-arabia/", "description": "This rule detects arabian spyware which records call and gathers user information which is later sent to a remote c&c"}', '2020-12-04 20:51:25.79828', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "androguard"


rule spyAgent
{
	meta:
		description = "This rule detects arabian spyware which records call and gathers user information which is later sent to a remote c&c"
		sample = "7cbf61fbb31c26530cafb46282f5c90bc10fe5c724442b8d1a0b87a8125204cb"
		reference = "https://blogs.mcafee.com/mcafee-labs/android-spyware-targets-security-job-seekers-in-saudi-arabia/"
		author = "@koodous_project"

	strings:
		$phone = "0597794205"
		$caption = "New victim arrived"
		$cc = "http://ksa-sef.com/Hack%20Mobaile/ADDNewSMS.php"
		$cc_alt = "http://ksa-sef.com/Hack%20Mobaile/AddAllLogCall.php"
		$cc_alt2= "http://ksa-sef.com/Hack%20Mobaile/addScreenShot.php"
		$cc_alt3= "http://ksa-sef.com/Hack%20Mobaile/ADDSMS.php"
		$cc_alt4 = "http://ksa-sef.com/Hack%20Mobaile/ADDVCF.php"
		$cc_alt5 = "http://ksa-sef.com/Hack%20Mobaile/ADDIMSI.php"
		$cc_alt6 = "http://ksa-sef.com/Hack%20Mobaile/ADDHISTORYINTERNET.php"
		$cc_alt7 = "http://ksa-sef.com/Hack%20Mobaile/addInconingLogs.php"

	condition:
		androguard.url(/ksa-sef\.com/) or ($phone and $caption) or ($cc and $cc_alt and $cc_alt2 and $cc_alt3 and $cc_alt4 and $cc_alt5 and $cc_alt6 and $cc_alt7)

}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (231, 'moscow_fake', '{banker,androoid}', '{"author": "Fernando Denis", "reference": "https://koodous.com/ https://twitter.com/fdrg21", "description": "Moskow Droid Development", "in_the_wild": true, "thread_level": 3}', '2020-12-04 20:51:25.908885', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/


//41dce59ace9cce668e893c9d2c35d6859dc1c86d631a0567bfde7d34dd5cae0b
//61f7909512c5caf6dd125659428cf764631d5a52c59c6b50112af4a02047774c
//2c89d0d37257c90311436115c1cf06295c39cd0a8c117730e07be029bd8121a0
rule moscow_fake : banker androoid
{
	meta:
	  author = "Fernando Denis"
		reference = "https://koodous.com/ https://twitter.com/fdrg21"
		description = "Moskow Droid Development"
		thread_level = 3
		in_the_wild = true

	strings:
		$string_a = "%ioperator%"
		$string_b = "%imodel%"
		$string_c = "%ideviceid%"
		$string_d = "%ipackname%"
		$string_e = "VILLLLLL"

	condition:
		all of ($string_*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (232, 'assd_developer', '{official,android}', '{"author": "Fernando Denis Ramirez https://twitter.com/fdrg21", "sample": "cb9721c524f155478e9402d213e240b9f99eaba86fcbce0571cd7da4e258a79e", "reference": "https://koodous.com/", "description": "This rule detects apks fom ASSD developer"}', '2020-12-04 20:51:26.014276', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule assd_developer : official android
{
	meta:
		author = "Fernando Denis Ramirez https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "This rule detects apks fom ASSD developer"
		sample = "cb9721c524f155478e9402d213e240b9f99eaba86fcbce0571cd7da4e258a79e"

	condition:
		androguard.certificate.sha1("ED9A1CE1F18A1097DCCC5C0CB005E3861DA9C34A")

}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (233, 'spynote_variants', NULL, '{"author": "5h1vang https://analyst.koodous.com/analysts/5h1vang", "source": " http://researchcenter.paloaltonetworks.com/2016/07/unit42-spynote-android-trojan-builder-leaked/", "description": "Yara rule for detection of different Spynote Variants", "rule_source": "https://analyst.koodous.com/rulesets/1710"}', '2020-12-04 20:51:26.118873', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and
    open to any user or organization, as long as you use it under this license.
*/

/*
    Androguard module used in this rule file is under development by people at https://koodous.com/.
    You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/


import "androguard"

rule spynote_variants
{
    meta:
        author = "5h1vang https://analyst.koodous.com/analysts/5h1vang"
        description = "Yara rule for detection of different Spynote Variants"
        source = " http://researchcenter.paloaltonetworks.com/2016/07/unit42-spynote-android-trojan-builder-leaked/"
        rule_source = "https://analyst.koodous.com/rulesets/1710"

    strings:
        $str_1 = "SERVER_IP" nocase
        $str_2 = "SERVER_NAME" nocase
        $str_3 = "content://sms/inbox"
        $str_4 = "screamHacker"
        $str_5 = "screamon"
    condition:
        androguard.package_name("dell.scream.application") or
        androguard.certificate.sha1("219D542F901D8DB85C729B0F7AE32410096077CB") or
        all of ($str_*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (234, 'android_spywaller', '{android}', '{"sample": "7b31656b9722f288339cb2416557241cfdf69298a749e49f07f912aeb1e5931b", "source": "http://blog.fortinet.com/post/android-spywaller-firewall-style-antivirus-blocking", "description": "Rule for detection of Android Spywaller samples"}', '2020-12-04 20:51:26.247083', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/
import "androguard"


rule android_spywaller : android
{
	meta:
		description = "Rule for detection of Android Spywaller samples"
		sample = "7b31656b9722f288339cb2416557241cfdf69298a749e49f07f912aeb1e5931b"
		source = "http://blog.fortinet.com/post/android-spywaller-firewall-style-antivirus-blocking"

	strings:
		$str_1 = "droid.png"
		$str_2 = "getSrvAddr"
		$str_3 = "getSrvPort"
		$str_4 = "android.intent.action.START_GOOGLE_SERVICE"

	condition:
		androguard.certificate.sha1("165F84B05BD33DA1BA0A8E027CEF6026B7005978") or
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.READ_PHONE_STATE/) and
		all of ($str_*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (242, 'Trojan_Dendroid', NULL, '{"author": "https://www.twitter.com/SadFud75", "description": "Detection of dendroid trojan"}', '2020-12-04 20:51:27.472783', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

rule Trojan_Dendroid
{
meta:
author = "https://www.twitter.com/SadFud75"
description = "Detection of dendroid trojan"
strings:
$s1 = "/upload-pictures.php?"
$s2 = "/get-functions.php?"
$s3 = "/new-upload.php?"
$s4 = "/message.php?"
$s5 = "/get.php?"
condition:
3 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (235, 'Android_Dogspectus_rswm', NULL, '{"author": "https://twitter.com/5h1vang", "sample": "197588be3e8ba5c779696d864121aff188901720dcda796759906c17473d46fe", "source": "https://www.bluecoat.com/security-blog/2016-04-25/android-exploit-delivers-dogspectus-ransomware", "description": "Yara rule for Dogspectus intial ransomware apk"}', '2020-12-04 20:51:26.583388', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule Android_Dogspectus_rswm
{
	meta:
		author = "https://twitter.com/5h1vang"
		description = "Yara rule for Dogspectus intial ransomware apk"
		sample = "197588be3e8ba5c779696d864121aff188901720dcda796759906c17473d46fe"
		source = "https://www.bluecoat.com/security-blog/2016-04-25/android-exploit-delivers-dogspectus-ransomware"

	strings:
		$str_1 = "android.app.action.ADD_DEVICE_ADMIN"
		$str_2 = "Tap ACTIVATE to continue with software update"


	condition:
		(androguard.package_name("net.prospectus") and
		 androguard.app_name("System update")) or

		androguard.certificate.sha1("180ADFC5DE49C0D7F643BD896E9AAC4B8941E44E") or

		(androguard.activity(/Loganberry/i) or
		androguard.activity("net.prospectus.pu") or
		androguard.activity("PanickedActivity")) or

		(androguard.permission(/android.permission.INTERNET/) and
		 androguard.permission(/android.permission.WAKE_LOCK/) and
		 androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		 all of ($str_*))


}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (236, 'BaDoink', '{official,android}', '{"author": "Fernando Denis https://twitter.com/fdrg21", "sample": "9bc0fb0f05bbf25507104a4eb74e8066b194a8e6a57670957c0ad1af92189921", "reference": "https://koodous.com/", "description": "Virus de la Policia - android"}', '2020-12-04 20:51:26.698289', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule BaDoink : official android
{
		meta:
		author = "Fernando Denis https://twitter.com/fdrg21"
		reference = "https://koodous.com/"
		description = "Virus de la Policia - android"
		sample = "9bc0fb0f05bbf25507104a4eb74e8066b194a8e6a57670957c0ad1af92189921"

	strings:

		//$url_string_1 = "http://police-mobile-stop.com"
		//$url_string_2 = "http://mobile-policeblock.com"

		$type_a_1 ="6589y459gj4058rt"

		$type_b_1 = "Q,hu4P#hT;U!XO7T,uD"
		$type_b_2 = "+Gkwg#M!lf>Laq&+J{lg"

//		$type_c_1 = "ANIM_STYLE_CLOSE_ENTER"
//		$type_c_2 = "TYPE_VIEW_ACCESSIBILITY_FOCUSED"
//		$type_c_3 = "TYPE_VIEW_TEXT_SELECTION_CHANGED"
//		$type_c_4 = "FLAG_REQUEST_ENHANCED_WEB_ACCESSIBILITY"

	condition:
		androguard.app_name("BaDoink") or
		//all of ($url_string_*) or
		$type_a_1 or
		all of ($type_b*)
//		all of ($type_c_*)

}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (237, 'koodous', '{official}', '{"Reference": "https://github.com/dana-at-cp/backdoor-apk", "description": "Detects samples repackaged by backdoor-apk shell script"}', '2020-12-04 20:51:26.811473', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/
import "androguard"


rule koodous : official
{
	meta:
		description = "Detects samples repackaged by backdoor-apk shell script"
		Reference = "https://github.com/dana-at-cp/backdoor-apk"

	strings:
		$str_1 = "cnlybnq.qrk" // encrypted string "payload.dex"

	condition:
		$str_1 and
		androguard.receiver(/\.AppBoot$/)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (238, 'Metasploit_Payload', NULL, '{"author": "https://www.twitter.com/SadFud75", "information": "Detection of payloads generated with metasploit"}', '2020-12-04 20:51:26.917814', 'import "androguard"

rule Metasploit_Payload
{
meta:
author = "https://www.twitter.com/SadFud75"
information = "Detection of payloads generated with metasploit"
strings:
$s1 = "-com.metasploit.meterpreter.AndroidMeterpreter"
$s2 = ",Lcom/metasploit/stage/MainBroadcastReceiver;"
$s3 = "#Lcom/metasploit/stage/MainActivity;"
$s4 = "Lcom/metasploit/stage/Payload;"
$s5 = "Lcom/metasploit/stage/a;"
$s6 = "Lcom/metasploit/stage/c;"
$s7 = "Lcom/metasploit/stage/b;"
condition:
androguard.package_name("com.metasploit.stage") or any of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (239, 'trojan', '{pornClicker}', '{"author": "Koodous Project", "sample": "5a863fe4b141e14ba3d9d0de3a9864c1339b2358386e10ba3b4caec73b5d06ca", "reference": "https://blog.malwarebytes.org/cybercrime/2016/06/trojan-clickers-gaze-cast-upon-google-play-store/?utm_source=facebook&utm_medium=social", "description": "Ruleset to detect android pornclicker trojan, connects to a remote host and obtains javascript and a list from urls generated, leading to porn in the end."}', '2020-12-04 20:51:27.029611', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "androguard"



rule trojan: pornClicker
{
	meta:
		description = "Ruleset to detect android pornclicker trojan, connects to a remote host and obtains javascript and a list from urls generated, leading to porn in the end."
		sample = "5a863fe4b141e14ba3d9d0de3a9864c1339b2358386e10ba3b4caec73b5d06ca"
 		reference = "https://blog.malwarebytes.org/cybercrime/2016/06/trojan-clickers-gaze-cast-upon-google-play-store/?utm_source=facebook&utm_medium=social"
    author = "Koodous Project"

	strings:
		$a = "SELEN3333"
		$b = "SELEN33"
		$c = "SELEN333"
		$api = "http://mayis24.4tubetv.xyz/dmr/ya"

	condition:
		($a and $b and $c and $api) or androguard.url(/mayis24\.4tubetv\.xyz/)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (240, 'Android_Triada', '{android}', '{"date": "2016/03/04", "author": "reverseShell - https://twitter.com/JReyCastro", "sample": "4656aa68ad30a5cf9bcd2b63f21fba7cfa0b70533840e771bd7d6680ef44794b", "source": "https://securelist.com/analysis/publications/74032/attack-on-zygote-a-new-twist-in-the-evolution-of-mobile-threats/", "description": "This rule try to detects Android.Triada.Malware"}', '2020-12-04 20:51:27.136945', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule Android_Triada : android
{
	meta:
		author = "reverseShell - https://twitter.com/JReyCastro"
		date = "2016/03/04"
		description = "This rule try to detects Android.Triada.Malware"
		sample = "4656aa68ad30a5cf9bcd2b63f21fba7cfa0b70533840e771bd7d6680ef44794b"
		source = "https://securelist.com/analysis/publications/74032/attack-on-zygote-a-new-twist-in-the-evolution-of-mobile-threats/"

	strings:
		$string_1 = "android/system/PopReceiver"
	condition:
		all of ($string_*) and
		androguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and
		androguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and
		androguard.permission(/android.permission.GET_TASKS/)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (243, 'bankbot_polish_banks', '{banker}', '{"hash0": "86aaed9017e3af5d1d9c8460f2d8164f14e14db01b1a278b4b93859d3cf982f5", "author": "Eternal", "reference": "https://www.cert.pl/en/news/single/analysis-of-a-polish-bankbot/", "description": "BankBot/Mazain attacking polish banks"}', '2020-12-04 20:51:27.585391', 'import "androguard"

rule bankbot_polish_banks : banker
{
    meta:
        author = "Eternal"
        hash0 = "86aaed9017e3af5d1d9c8460f2d8164f14e14db01b1a278b4b93859d3cf982f5"
        description = "BankBot/Mazain attacking polish banks"
        reference = "https://www.cert.pl/en/news/single/analysis-of-a-polish-bankbot/"
    strings:
        $bank1 = "com.comarch.mobile"
        $bank2 = "eu.eleader.mobilebanking.pekao"
        $bank3 = "eu.eleader.mobilebanking.raiffeisen"
        $bank4 = "pl.fmbank.smart"
        $bank5 = "pl.mbank"
        $bank6 = "wit.android.bcpBankingApp.millenniumPL"
        $bank7 = "pl.pkobp.iko"
        $bank8 = "pl.plus.plusonline"
        $bank9 = "pl.ing.mojeing"
        $bank10 = "pl.bzwbk.bzwbk24"
        $bank11 = "com.getingroup.mobilebanking"
        $bank12 = "eu.eleader.mobilebanking.invest"
        $bank13 = "pl.bph"
        $bank14 = "com.konylabs.cbplpat"
        $bank15 = "eu.eleader.mobilebanking.pekao.firm"

        $s1 = "IMEI"
        $s2 = "/:/"
        $s3 = "p="
        $s4 = "SMS From:"

    condition:
        all of ($s*) and 1 of ($bank*) and
        androguard.permission(/android.permission.INTERNET/) and
        androguard.permission(/android.permission.WAKE_LOCK/) and
        androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/) and
        androguard.permission(/android.permission.RECEIVE_MMS/) and
        androguard.permission(/android.permission.READ_SMS/) and
        androguard.permission(/android.permission.RECEIVE_SMS/)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (244, 'SandroRat', NULL, '{"date": "21-May-2016", "author": "Jacob Soo Lead Re", "source": "https://blogs.mcafee.com/mcafee-labs/sandrorat-android-rat-targeting-polish-banking-users-via-e-mail-phishing/", "description": "This rule detects SandroRat"}', '2020-12-04 20:51:27.696474', 'import "androguard"


rule SandroRat
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "21-May-2016"
		description = "This rule detects SandroRat"
		source = "https://blogs.mcafee.com/mcafee-labs/sandrorat-android-rat-targeting-polish-banking-users-via-e-mail-phishing/"

	condition:
		androguard.activity(/net.droidjack.server/i)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (245, 'dropper', '{realshell,android}', '{"author": "https://twitter.com/plutec_net", "source": "https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/", "reference": "https://koodous.com/"}', '2020-12-04 20:51:27.800126', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as
    long as you use it under this license.
*/

rule dropper:realshell android {
    meta:
        author = "https://twitter.com/plutec_net"
        reference = "https://koodous.com/"
        source = "https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/"
    strings:
        $b = "Decrypt.malloc.memset.free.pluginSMS_encrypt.Java_com_skymobi_pay_common_util_LocalDataDecrpty_Encrypt.strcpy"

    condition:
        $b
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (246, 'Android_FakeBank_Fanta', NULL, '{"date": "14-July-2016", "author": "Jacob Soo Lead Re", "source": "https://blog.trendmicro.com/trendlabs-security-intelligence/fake-bank-app-phishes-credentials-locks-users-out/", "description": "This rule try to detects Android FakeBank_Fanta"}', '2020-12-04 20:51:27.908964', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "androguard"

rule Android_FakeBank_Fanta
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "14-July-2016"
		description = "This rule try to detects Android FakeBank_Fanta"
		source = "https://blog.trendmicro.com/trendlabs-security-intelligence/fake-bank-app-phishes-credentials-locks-users-out/"

	condition:
		androguard.service(/SocketService/i) and
		androguard.receiver(/MyAdmin/i) and
		androguard.receiver(/Receiver/i) and
		androguard.receiver(/NetworkChangeReceiver/i)

}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (247, 'VikingBotnet', NULL, '{"author": "https://twitter.com/koodous_project", "sample": "85e6d5b3569e5b22a16245215a2f31df1ea3a1eb4d53b4c286a6ad2a46517b0c", "description": "Rule to detect Viking Order Botnet."}', '2020-12-04 20:51:28.022247', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

import "androguard"
import "cuckoo"


rule VikingBotnet
{
	meta:
	  author = "https://twitter.com/koodous_project"
		description = "Rule to detect Viking Order Botnet."
		sample = "85e6d5b3569e5b22a16245215a2f31df1ea3a1eb4d53b4c286a6ad2a46517b0c"

	strings:
		$a = "cv7obBkPVC2pvJmWSfHzXh"
		$b = "http://joyappstech.biz:11111/knock/"
		$c = "I HATE TESTERS onGlobalLayout"
		$d = "http://144.76.70.213:7777/ecspectapatronum/"

	condition:
		($a and $c) or ($b and $d)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (248, 'andr_sk_bank', NULL, '{"author": "https://twitter.com/5h1vang", "sample": "0af5c4c2f39aba06f6793f26d6caae134564441b2134e0b72536e65a62bcbfad", "source": "https://www.zscaler.com/blogs/research/android-malware-targeting-south-korean-mobile-users", "description": "Yara rule for Banking trojan targeting South Korean banks"}', '2020-12-04 20:51:28.132021', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/
import "androguard"


rule andr_sk_bank
{
	meta:
		description = "Yara rule for Banking trojan targeting South Korean banks"
		sample = "0af5c4c2f39aba06f6793f26d6caae134564441b2134e0b72536e65a62bcbfad"
		source = "https://www.zscaler.com/blogs/research/android-malware-targeting-south-korean-mobile-users"
		author = "https://twitter.com/5h1vang"

	strings:
		$str_1 = "NPKI"
		$str_2 = "portraitCallBack("
		$str_3 = "android.app.extra.DEVICE_ADMIN"
		$str_4 = "SMSReceiver&imsi="
		$str_5 = "com.ahnlab.v3mobileplus"

	condition:
		androguard.package_name("com.qbjkyd.rhsxa") or
		androguard.certificate.sha1("543382EDDAFC05B435F13BBE97037BB335C2948B") or
		(androguard.permission(/android.permission.RECEIVE_SMS/) and
		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and
		all of ($str_*))
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (249, 'tachi', '{android}', '{"author": "https://twitter.com/plutec_net", "sample": "10acdf7db989c3acf36be814df4a95f00d370fe5b5fda142f9fd94acf46149ec", "source": "https://analyst.koodous.com/rulesets/1332", "description": "This rule detects tachi apps (not all malware)"}', '2020-12-04 20:51:28.235518', 'rule tachi : android
{
	meta:
		author = "https://twitter.com/plutec_net"
		source = "https://analyst.koodous.com/rulesets/1332"
		description = "This rule detects tachi apps (not all malware)"
		sample = "10acdf7db989c3acf36be814df4a95f00d370fe5b5fda142f9fd94acf46149ec"

	strings:
		$a = "svcdownload"
		$xml_1 = "<config>"
		$xml_2 = "<apptitle>"
		$xml_3 = "<txinicio>"
		$xml_4 = "<txiniciotitulo>"
		$xml_5 = "<txnored>"
		$xml_6 = "<txnoredtitulo>"
		$xml_7 = "<txnoredretry>"
		$xml_8 = "<txnoredsalir>"
		$xml_9 = "<laurl>"
		$xml_10 = "<txquieresalir>"
		$xml_11 = "<txquieresalirtitulo>"
		$xml_12 = "<txquieresalirsi>"
		$xml_13 = "<txquieresalirno>"
		$xml_14 = "<txfiltro>"
		$xml_15 = "<txfiltrourl>"
		$xml_16 = "<posicion>"


	condition:
		$a and 4 of ($xml_*)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (250, 'Android_Clicker_G', NULL, '{"date": "01-July-2016", "author": "Jacob Soo Lead Re", "reference": "https://blogs.mcafee.com/mcafee-labs/android-malware-clicker-dgen-found-google-play/", "description": "This rule try to detects Clicker.G samples"}', '2020-12-04 20:51:28.350812', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "androguard"

rule Android_Clicker_G
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "This rule try to detects Clicker.G samples"
		reference = "https://blogs.mcafee.com/mcafee-labs/android-malware-clicker-dgen-found-google-play/"
	strings:
		$a = "upd.php?text="
	condition:
		androguard.receiver(/MyBroadCastReceiver/i) and $a
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (251, 'dowgin', '{adware,android}', '{"author": "https://twitter.com/plutec_net", "sample": "4d7f2d6ff4ed8ced6f8f7f96e9899273cc3090ea108f2cc3b32dd1a06e63cf70", "sample2": "cde8160d09c486bdd6d96b2ed81bd52390d77094d13ff9cfbc6949ed00206a83", "sample3": "d2e81e6db5f4964246d10241588e0e97cde524815c4de7c0ea1c34a48da1bcaf", "sample4": "cc2d0b3d8f00690298b0e5813f6ace8f4d4b04c9704292407c2b83a12c69617b", "reference": "https://koodous.com/"}', '2020-12-04 20:51:28.470865', 'rule dowgin:adware android
{
    meta:
        author = "https://twitter.com/plutec_net"
        reference = "https://koodous.com/"
        sample = "4d7f2d6ff4ed8ced6f8f7f96e9899273cc3090ea108f2cc3b32dd1a06e63cf70"
        sample2 = "cde8160d09c486bdd6d96b2ed81bd52390d77094d13ff9cfbc6949ed00206a83"
        sample3 = "d2e81e6db5f4964246d10241588e0e97cde524815c4de7c0ea1c34a48da1bcaf"
        sample4 = "cc2d0b3d8f00690298b0e5813f6ace8f4d4b04c9704292407c2b83a12c69617b"

    strings:
        $a = "http://112.74.111.42:8000"
        $b = "SHA1-Digest: oIx4iYWeTtKib4fBH7hcONeHuaE="
        $c = "ONLINEGAMEPROCEDURE_WHICH_WAP_ID"
        $d = "http://da.mmarket.com/mmsdk/mmsdk?func=mmsdk:posteventlog"

    condition:
        all of them

}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (252, 'fraudulents_2', '{certificates,android}', '{"author": "https://twitter.com/fdrg21", "description": "This rule automatically adds certificates present in malware"}', '2020-12-04 20:51:28.577573', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule fraudulents_2 : certificates android
{
	meta:
		description = "This rule automatically adds certificates present in malware"
		author = "https://twitter.com/fdrg21"

	condition:
		androguard.certificate.sha1("A5D9C9A40A3786D631210E8FCB9CF7A1BC5B3062") or
		androguard.certificate.sha1("B4142B617997345809736842147F97F46059FDE3") or
		androguard.certificate.sha1("950A545EA156A0E44B3BAB5F432DCD35005A9B70") or
		androguard.certificate.sha1("DE18FA0C68E6C9E167262F1F4ED984A5F00FD78C") or
		androguard.certificate.sha1("81E8E202C539F7AEDF6138804BE870338F81B356") or
		androguard.certificate.sha1("5A051047F2434DDB2CAA65898D9B19ED9665F759")

}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (253, 'Android_BadMirror', NULL, '{"date": "06-June-2016", "author": "Jacob Soo Lead Re", "source": "https://blog.fortinet.com/post/badmirror-new-android-malware-family-spotted-by-sherlockdroid", "description": "BadMirror is Android malware. The malware sends information to its remote CnC (phone number, MAC adddress, list of installed applications...) but it also has the capability to execute a few commands such as \\\"app\\\" (download an APK) or \\\"page\\\" (display a given URL)."}', '2020-12-04 20:51:28.789357', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "androguard"

rule Android_BadMirror
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "06-June-2016"
		description = "BadMirror is Android malware. The malware sends information to its remote CnC (phone number, MAC adddress, list of installed applications...) but it also has the capability to execute a few commands such as \"app\" (download an APK) or \"page\" (display a given URL)."
		source = "https://blog.fortinet.com/post/badmirror-new-android-malware-family-spotted-by-sherlockdroid"

	condition:
		androguard.service(/SimInsService/i) and
        androguard.permission(/android.permission.READ_PHONE_STATE/i)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (254, 'HackingTeam_Android', '{Android,Implant}', '{"date": "2016-11-14", "author": "Tim ''diff'' Strazzere <strazz@gmail.com>", "version": "1.0", "reference": "http://rednaga.io/2016/11/14/hackingteam_back_for_your_androids/", "description": "HackingTeam Android implant, known to detect version v4 - v7"}', '2020-12-04 20:51:28.898076', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule HackingTeam_Android : Android Implant
{
	meta:
		description = "HackingTeam Android implant, known to detect version v4 - v7"
		author = "Tim ''diff'' Strazzere <strazz@gmail.com>"
                reference = "http://rednaga.io/2016/11/14/hackingteam_back_for_your_androids/"
		date = "2016-11-14"
		version = "1.0"
        strings:
        $decryptor = {  12 01               // const/4 v1, 0x0
                        D8 00 ?? ??         // add-int/lit8 ??, ??, ??
                        6E 10 ?? ?? ?? 00   // invoke-virtual {??} -> String.toCharArray()
                        0C 04               // move-result-object v4
                        21 45               // array-length v5, v4
                        01 02               // move v2, v0
                        01 10               // move v0, v1
                        32 50 11 00         // if-eq v0, v5, 0xb
                        49 03 04 00         // aget-char v3, v4, v0
                        DD 06 02 5F         // and-int/lit8 v6, v2, 0x5f <- potentially change the hardcoded xor bit to ??
                        B7 36               // xor-int/2addr v6, v3
                        D8 03 02 ??         // and-int/lit8 v3, v2, ??
                        D8 02 00 01         // and-int/lit8 v2, v0, 0x1
                        8E 66               // int-to-char v6, v6
                        50 06 04 00         // aput-char v6, v4, v0
                        01 20               // move v0, v2
                        01 32               // move v2, v3
                        28 F0               // goto 0xa
                        71 30 ?? ?? 14 05   // invoke-static {v4, v1, v5}, ?? -> String.valueOf()
                        0C 00               // move-result-object v0
                        6E 10 ?? ?? 00 00   // invoke-virtual {v0} ?? -> String.intern()
                        0C 00               // move-result-object v0
                        11 00               // return-object v0
                     }
        // Below is the following string, however encoded as it would appear in the string table (length encoded, null byte padded)
        // Lcom/google/android/global/Settings;
        $settings = {
                        00 24 4C 63 6F 6D 2F 67 6F 6F 67 6C 65 2F 61 6E
                        64 72 6F 69 64 2F 67 6C 6F 62 61 6C 2F 53 65 74
                        74 69 6E 67 73 3B 00
                    }
        // getSmsInputNumbers (Same encoded described above)
        $getSmsInputNumbers = {
                                00 12 67 65 74 53 6D 73 49 6E 70 75 74 4E 75 6D
                                62 65 72 73 00
                              }
      condition:
        $decryptor and ($settings and $getSmsInputNumbers)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (261, 'zeus_js', '{EK}', '{"date": "2016-06-26", "hash0": "c87ac7a25168df49a64564afb04dc961", "author": "Josh Berry", "description": "Zeus Exploit Kit Detection", "yaragenerator": "https://github.com/Xen0ph0n/YaraGenerator", "sample_filetype": "js-html"}', '2020-12-04 20:51:30.105898', 'rule zeus_js : EK
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "Zeus Exploit Kit Detection"
	hash0 = "c87ac7a25168df49a64564afb04dc961"
	sample_filetype = "js-html"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "var jsmLastMenu "
	$string1 = "position:absolute; z-index:99'' "
	$string2 = " -1)jsmSetDisplayStyle(''popupmenu'' "
	$string3 = " ''<tr><td><a href"
	$string4 = "  jsmLastMenu "
	$string5 = "  var ids "
	$string6 = "this.target"
	$string7 = " jsmPrevMenu, ''none'');"
	$string8 = "  if(jsmPrevMenu "
	$string9 = ")if(MenuData[i])"
	$string10 = " ''<div style"
	$string11 = "popupmenu"
	$string12 = "  jsmSetDisplayStyle(''popupmenu'' "
	$string13 = "function jsmHideLastMenu()"
	$string14 = " MenuData.length; i"
condition:
	14 of them
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (255, 'libyan_scorpions', NULL, '{"sample": "9d8e5ccd4cf543b4b41e4c6a1caae1409076a26ee74c61c148dffd3ce87d7787", "source": "https://cyberkov.com/wp-content/uploads/2016/09/Hunting-Libyan-Scorpions-EN.pdf"}', '2020-12-04 20:51:29.106425', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"
import "cuckoo"


rule libyan_scorpions
{
	meta:
		source = "https://cyberkov.com/wp-content/uploads/2016/09/Hunting-Libyan-Scorpions-EN.pdf"
		sample = "9d8e5ccd4cf543b4b41e4c6a1caae1409076a26ee74c61c148dffd3ce87d7787"

	strings:
		$ip_1 = "41.208.110.46" ascii wide
		$domain_1 = "winmeif.myq-see.com" ascii wide nocase
		$domain_2 = "wininit.myq-see.com" ascii wide nocase
		$domain_3 = "samsung.ddns.me" ascii wide nocase
		$domain_4 = "collge.myq-see.com" ascii wide nocase
		$domain_5 = "sara2011.no-ip.biz" ascii wide nocase

	condition:
		androguard.url(/41\.208\.110\.46/) or cuckoo.network.http_request(/41\.208\.110\.46/) or
		androguard.url(/winmeif.myq-see.com/i) or cuckoo.network.dns_lookup(/winmeif.myq-see.com/i) or
		androguard.url(/wininit.myq-see.com/i) or cuckoo.network.dns_lookup(/wininit.myq-see.com/i) or
		androguard.url(/samsung.ddns.me/i) or cuckoo.network.dns_lookup(/samsung.ddns.me/i) or
		androguard.url(/collge.myq-see.com/i) or cuckoo.network.dns_lookup(/collge.myq-see.com/i) or
		androguard.url(/sara2011.no-ip.biz/i) or cuckoo.network.dns_lookup(/sara2011.no-ip.biz/i) or
		any of ($domain_*) or any of ($ip_*) or
		androguard.certificate.sha1("DFFDD3C42FA06BCEA9D65B8A2E980851383BD1E3")

}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (256, 'batterybotpro', '{ClickFraud,AdFraud,SMS,Downloader_Trojan,android}', '{"author": "https://twitter.com/fdrg21", "sample": "cc4e024db858d7fa9b03d7422e760996de6a4674161efbba22d05f8b826e69d5", "description": "http://research.zscaler.com/2015/07/fake-batterybotpro-clickfraud-adfruad.html"}', '2020-12-04 20:51:29.457793', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule batterybotpro : ClickFraud AdFraud SMS Downloader_Trojan android
{
	meta:
		description = "http://research.zscaler.com/2015/07/fake-batterybotpro-clickfraud-adfruad.html"
		sample = "cc4e024db858d7fa9b03d7422e760996de6a4674161efbba22d05f8b826e69d5"
		author = "https://twitter.com/fdrg21"

	condition:

		androguard.activity(/com\.polaris\.BatteryIndicatorPro\.BatteryInfoActivity/i) and
		androguard.permission(/android\.permission\.SEND_SMS/)

}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (257, 'Android_Copy9', NULL, '{"date": "06-June-2016", "author": "Jacob Soo Lead Re", "source": "http://copy9.com/", "description": "This rule try to detect commercial spyware from Copy9"}', '2020-12-04 20:51:29.570674', 'import "androguard"

rule Android_Copy9
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "06-June-2016"
		description = "This rule try to detect commercial spyware from Copy9"
		source = "http://copy9.com/"

	condition:
		androguard.service(/com.ispyoo/i) and
        androguard.receiver(/com.ispyoo/i)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (258, 'leadbolt', '{advertising,android}', '{"author": "https://twitter.com/plutec_net", "reference": "https://koodous.com/", "description": "Leadbolt"}', '2020-12-04 20:51:29.675895', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"

rule leadbolt : advertising android
{
	meta:
	  author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
		description = "Leadbolt"

	condition:
		androguard.url(/http:\/\/ad.leadbolt.net/)
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (259, 'Android_OmniRat', NULL, '{"date": "01-July-2016", "author": "Jacob Soo Lead Re", "source": "https://blog.avast.com/2015/11/05/droidjack-isnt-the-only-spying-software-out-there-avast-discovers-that-omnirat-is-currently-being-used-and-spread-by-criminals-to-gain-full-remote-co", "description": "This rule try to detects OmniRat"}', '2020-12-04 20:51:29.78909', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.

*/

import "androguard"

rule Android_OmniRat
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "01-July-2016"
		description = "This rule try to detects OmniRat"
		source = "https://blog.avast.com/2015/11/05/droidjack-isnt-the-only-spying-software-out-there-avast-discovers-that-omnirat-is-currently-being-used-and-spread-by-criminals-to-gain-full-remote-co"

	strings:
		$a = "android.engine.apk"
	condition:
		(androguard.activity(/com.app.MainActivity/i) and
		 androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/i) and
		 androguard.package_name(/com.app/i)) and $a
}
');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (260, 'android_mazarBot_z', '{android}', '{"author": "https://twitter.com/5h1vang", "sample": "73c9bf90cb8573db9139d028fa4872e93a528284c02616457749d40878af8cf8", "description": "Yara detection for MazarBOT", "reference_1": "https://heimdalsecurity.com/blog/security-alert-mazar-bot-active-attacks-android-malware/"}', '2020-12-04 20:51:30.002381', '/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/*
	Androguard module used in this rule file is under development by people at https://koodous.com/.

	You can get it, along with installation instructions, at https://github.com/Koodous/androguard-yara
*/

import "androguard"


rule android_mazarBot_z: android
{
	meta:
	  author = "https://twitter.com/5h1vang"
	  reference_1 = "https://heimdalsecurity.com/blog/security-alert-mazar-bot-active-attacks-android-malware/"
	  description = "Yara detection for MazarBOT"
	  sample = "73c9bf90cb8573db9139d028fa4872e93a528284c02616457749d40878af8cf8"

	strings:
		$str_1 = "android.app.extra.ADD_EXPLANATION"
		$str_2 = "device_policy"
		$str_3 = "content://sms/"
		$str_4 = "#admin_start"
		$str_5 = "kill call"
		$str_6 = "unstop all numbers"

	condition:
		androguard.certificate.sha1("50FD99C06C2EE360296DCDA9896AD93CAE32266B") or

		(androguard.package_name("com.mazar") and
		androguard.activity(/\.DevAdminDisabler/) and
		androguard.receiver(/\.DevAdminReceiver/) and
		androguard.service(/\.WorkerService/i)) or

		androguard.permission(/android.permission.INTERNET/) and
		androguard.permission(/android.permission.SEND_SMS/) and
		androguard.permission(/android.permission.CALL_PHONE/) and
		all of ($str_*)
}
');




INSERT INTO host (account, hostname)
SELECT '540155',
       'system' || seq || '.com'
FROM GENERATE_SERIES(1, :SEED_HOST_COUNT) seq;

INSERT INTO host_scan (created_at, host_id)
SELECT ((now()::date - :SEED_DAYS) + (random() * :SEED_DAYS)::int) + (random() * INTERVAL '1 day'),
       (SELECT array_agg(id) FROM host)[random() * (SELECT count(*) - 1 FROM host) + 1]
FROM GENERATE_SERIES(1, :SEED_HOST_COUNT * :SEED_DAYS) seq
ON CONFLICT DO NOTHING;

INSERT INTO rule_scan (host_scan_id, rule_id)
SELECT (SELECT array_agg(id) FROM host_scan)[random() * (SELECT count(*) - 1 FROM host_scan) + 1],
       (SELECT array_agg(id) FROM rule)[random() * (SELECT count(*) - 1 FROM rule) + 1]
FROM GENERATE_SERIES(1, :SEED_HOST_COUNT * :SEED_DAYS * :SEED_SCAN_PER_HOST) seq
ON CONFLICT DO NOTHING;

INSERT INTO string_match (rule_scan_id, source, string_identifier, string_offset, string_data)
SELECT (SELECT array_agg(id) FROM rule_scan)[random() * (SELECT count(*) - 1 FROM rule_scan) + 1],
       '/root/badfile.bin',
       '$string1',
       123456,
       'virus-string'
FROM GENERATE_SERIES(1, :SEED_HOST_COUNT * :SEED_DAYS * :SEED_MATCH_PER_HOST) seq
ON CONFLICT DO NOTHING;

