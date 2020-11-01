--PGPASSWORD=postgres pg_dump -U postgres -h localhost -p 5434 -d myapp -t rule --inserts > dev.sql
truncate rule CASCADE;

INSERT INTO public.rule VALUES (default, 'jjEncode', NULL, '{"ref": "http://blog.xanda.org/2015/06/10/yara-rule-for-jjencode/", "date": "10-June-2015", "hide": false, "author": "adnan.shukor@gmail.com", "impact": 3, "version": "1", "description": "jjencode detection"}', '[
    {
        "condition_terms": [
            "$jjencode"
        ],
        "metadata": [
            {
                "description": "jjencode detection"
            },
            {
                "ref": "http://blog.xanda.org/2015/06/10/yara-rule-for-jjencode/"
            },
            {
                "author": "adnan.shukor@gmail.com"
            },
            {
                "date": "10-June-2015"
            },
            {
                "version": "1"
            },
            {
                "impact": 3
            },
            {
                "hide": false
            }
        ],
        "raw_condition": "condition:\n      $jjencode\n",
        "raw_meta": "meta:\n      description = \"jjencode detection\"\n      ref = \"http://blog.xanda.org/2015/06/10/yara-rule-for-jjencode/\"\n      author = \"adnan.shukor@gmail.com\"\n      date = \"10-June-2015\"\n      version = \"1\"\n      impact = 3\n      hide = false\n   ",
        "raw_strings": "strings:\n      $jjencode = /(\\$|[\\S]+)=~\\[\\]\\;(\\$|[\\S]+)\\=\\{[\\_]{3}\\:[\\+]{2}(\\$|[\\S]+)\\,[\\$]{4}\\:\\(\\!\\[\\]\\+[\"]{2}\\)[\\S]+/ fullword \n   ",
        "rule_name": "jjEncode",
        "start_line": 5,
        "stop_line": 19,
        "strings": [
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$jjencode",
                "type": "regex",
                "value": "/(\\$|[\\S]+)=~\\[\\]\\;(\\$|[\\S]+)\\=\\{[\\_]{3}\\:[\\+]{2}(\\$|[\\S]+)\\,[\\$]{4}\\:\\(\\!\\[\\]\\+[\"]{2}\\)[\\S]+/"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Contains_hidden_PE_File_inside_a_sequence_of_numbers', '{maldoc}', '{"date": "2016-01-09", "author": "Martin Willing (https://evild3ad.com)", "filetype": "decompressed VBA macro code", "reference": "http://www.welivesecurity.com/2016/01/04/blackenergy-trojan-strikes-again-attacks-ukrainian-electric-power-industry/", "description": "Detect a hidden PE file inside a sequence of numbers (comma separated)"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Martin Willing (https://evild3ad.com)"
            },
            {
                "description": "Detect a hidden PE file inside a sequence of numbers (comma separated)"
            },
            {
                "reference": "http://blog.didierstevens.com/2016/01/07/blackenergy-xls-dropper/"
            },
            {
                "reference": "http://www.welivesecurity.com/2016/01/04/blackenergy-trojan-strikes-again-attacks-ukrainian-electric-power-industry/"
            },
            {
                "date": "2016-01-09"
            },
            {
                "filetype": "decompressed VBA macro code"
            }
        ],
        "raw_condition": "condition:\n\t \tall of them\n",
        "raw_meta": "meta:\n\t\tauthor = \"Martin Willing (https://evild3ad.com)\"\n\t\tdescription = \"Detect a hidden PE file inside a sequence of numbers (comma separated)\"\n\t\treference = \"http://blog.didierstevens.com/2016/01/07/blackenergy-xls-dropper/\"\n\t\treference = \"http://www.welivesecurity.com/2016/01/04/blackenergy-trojan-strikes-again-attacks-ukrainian-electric-power-industry/\"\n\t\tdate = \"2016-01-09\"\n\t\tfiletype = \"decompressed VBA macro code\"\n\t\t\n\t",
        "raw_strings": "strings:\n\t\t$a = \"= Array(\" // Array of bytes\n\t\t$b = \"77, 90,\" // MZ\n\t\t$c = \"33, 84, 104, 105, 115, 32, 112, 114, 111, 103, 114, 97, 109, 32, 99, 97, 110, 110, 111, 116, 32, 98, 101, 32, 114, 117, 110, 32, 105, 110, 32, 68, 79, 83, 32, 109, 111, 100, 101, 46,\" // !This program cannot be run in DOS mode.\n\t\n\t",
        "rule_name": "Contains_hidden_PE_File_inside_a_sequence_of_numbers",
        "start_line": 6,
        "stop_line": 23,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "= Array("
            },
            {
                "name": "$b",
                "type": "text",
                "value": "77, 90,"
            },
            {
                "name": "$c",
                "type": "text",
                "value": "33, 84, 104, 105, 115, 32, 112, 114, 111, 103, 114, 97, 109, 32, 99, 97, 110, 110, 111, 116, 32, 98, 101, 32, 114, 117, 110, 32, 105, 110, 32, 68, 79, 83, 32, 109, 111, 100, 101, 46,"
            }
        ],
        "tags": [
            "maldoc"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'MIME_MSO_ActiveMime_base64', '{maldoc}', '{"date": "2016-02-28", "author": "Martin Willing (https://evild3ad.com)", "filetype": "Office documents", "description": "Detect MIME MSO Base64 encoded ActiveMime file"}', '[
    {
        "condition_terms": [
            "$mime",
            "at",
            "0",
            "and",
            "$base64",
            "and",
            "$mso",
            "and",
            "$activemime"
        ],
        "metadata": [
            {
                "author": "Martin Willing (https://evild3ad.com)"
            },
            {
                "description": "Detect MIME MSO Base64 encoded ActiveMime file"
            },
            {
                "date": "2016-02-28"
            },
            {
                "filetype": "Office documents"
            }
        ],
        "raw_condition": "condition:\n\t\t$mime at 0 and $base64 and $mso and $activemime\n",
        "raw_meta": "meta:\n\t\tauthor = \"Martin Willing (https://evild3ad.com)\"\n\t\tdescription = \"Detect MIME MSO Base64 encoded ActiveMime file\"\n\t\tdate = \"2016-02-28\"\n\t\tfiletype = \"Office documents\"\n\t\t\n\t",
        "raw_strings": "strings:\n\t\t$mime = \"MIME-Version:\"\n\t\t$base64 = \"Content-Transfer-Encoding: base64\"\n\t\t$mso = \"Content-Type: application/x-mso\"\n\t\t$activemime = /Q(\\x0D\\x0A|)W(\\x0D\\x0A|)N(\\x0D\\x0A|)0(\\x0D\\x0A|)a(\\x0D\\x0A|)X(\\x0D\\x0A|)Z(\\x0D\\x0A|)l(\\x0D\\x0A|)T(\\x0D\\x0A|)W/\n\t\n\t",
        "rule_name": "MIME_MSO_ActiveMime_base64",
        "start_line": 6,
        "stop_line": 22,
        "strings": [
            {
                "name": "$mime",
                "type": "text",
                "value": "MIME-Version:"
            },
            {
                "name": "$base64",
                "type": "text",
                "value": "Content-Transfer-Encoding: base64"
            },
            {
                "name": "$mso",
                "type": "text",
                "value": "Content-Type: application/x-mso"
            },
            {
                "name": "$activemime",
                "type": "regex",
                "value": "/Q(\\x0D\\x0A|)W(\\x0D\\x0A|)N(\\x0D\\x0A|)0(\\x0D\\x0A|)a(\\x0D\\x0A|)X(\\x0D\\x0A|)Z(\\x0D\\x0A|)l(\\x0D\\x0A|)T(\\x0D\\x0A|)W/"
            }
        ],
        "tags": [
            "maldoc"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Word_2007_XML_Flat_OPC', '{maldoc}', '{"date": "2018-04-29", "hash1": "060c036ce059b465a05c42420efa07bf", "hash2": "2af21d35bb909a0ac081c2399d0939b1", "hash3": "72ffa688c228b0b833e69547885650fe", "author": "Martin Willing (https://evild3ad.com)", "filetype": "Office documents", "reference": "https://blogs.msdn.microsoft.com/ericwhite/2008/09/29/the-flat-opc-format/", "description": "Detect Word 2007 XML Document in the Flat OPC format w/ embedded Microsoft Office 2007+ document"}', '[
    {
        "condition_terms": [
            "$xml",
            "at",
            "0",
            "and",
            "$WordML",
            "and",
            "$OPC",
            "and",
            "$xmlns",
            "and",
            "$binaryData",
            "and",
            "$docm"
        ],
        "metadata": [
            {
                "author": "Martin Willing (https://evild3ad.com)"
            },
            {
                "description": "Detect Word 2007 XML Document in the Flat OPC format w/ embedded Microsoft Office 2007+ document"
            },
            {
                "date": "2018-04-29"
            },
            {
                "reference": "https://blogs.msdn.microsoft.com/ericwhite/2008/09/29/the-flat-opc-format/"
            },
            {
                "hash1": "060c036ce059b465a05c42420efa07bf"
            },
            {
                "hash2": "2af21d35bb909a0ac081c2399d0939b1"
            },
            {
                "hash3": "72ffa688c228b0b833e69547885650fe"
            },
            {
                "filetype": "Office documents"
            }
        ],
        "raw_condition": "condition:\n\t \t$xml at 0 and $WordML and $OPC and $xmlns and $binaryData and $docm\n",
        "raw_meta": "meta:\n\t\tauthor = \"Martin Willing (https://evild3ad.com)\"\n\t\tdescription = \"Detect Word 2007 XML Document in the Flat OPC format w/ embedded Microsoft Office 2007+ document\"\n\t\tdate = \"2018-04-29\"\n\t\treference = \"https://blogs.msdn.microsoft.com/ericwhite/2008/09/29/the-flat-opc-format/\"\n\t\thash1 = \"060c036ce059b465a05c42420efa07bf\"\n\t\thash2 = \"2af21d35bb909a0ac081c2399d0939b1\"\n\t\thash3 = \"72ffa688c228b0b833e69547885650fe\"\n\t\tfiletype = \"Office documents\"\n\t\t\n\t",
        "raw_strings": "strings:\n\t\t$xml = \"<?xml\" // XML declaration\n\t\t$WordML = \"<?mso-application progid=\\\"Word.Document\\\"?>\" // XML processing instruction => A Windows OS with Microsoft Office installed will recognize the file as a MS Word document.\n\t\t$OPC = \"<pkg:package\" // Open XML Package\n\t\t$xmlns = \"http://schemas.microsoft.com/office/2006/xmlPackage\" // XML namespace => Microsoft Office 2007 XML Schema Reference\n\t\t$binaryData = \"<pkg:binaryData>0M8R4KGxGuE\" // Binary Part (Microsoft Office 2007+ document encoded in a Base64 string, broken into lines of 76 characters) => D0 CF 11 E0 A1 B1 1A E1 (vbaProject.bin / DOCM)\n\t\t$docm = \"pkg:name=\\\"/word/vbaProject.bin\\\"\" // Binary Object\n\t\t\n\t",
        "rule_name": "Word_2007_XML_Flat_OPC",
        "start_line": 5,
        "stop_line": 27,
        "strings": [
            {
                "name": "$xml",
                "type": "text",
                "value": "<?xml"
            },
            {
                "name": "$WordML",
                "type": "text",
                "value": "<?mso-application progid=\\\"Word.Document\\\"?>"
            },
            {
                "name": "$OPC",
                "type": "text",
                "value": "<pkg:package"
            },
            {
                "name": "$xmlns",
                "type": "text",
                "value": "http://schemas.microsoft.com/office/2006/xmlPackage"
            },
            {
                "name": "$binaryData",
                "type": "text",
                "value": "<pkg:binaryData>0M8R4KGxGuE"
            },
            {
                "name": "$docm",
                "type": "text",
                "value": "pkg:name=\\\"/word/vbaProject.bin\\\""
            }
        ],
        "tags": [
            "maldoc"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'APT_OLE_JSRat', '{maldoc,APT}', '{"Date": "2015-06-16", "author": "Rahul Mohandas", "Description": "Targeted attack using Excel/word documents"}', '[
    {
        "condition_terms": [
            "$header",
            "at",
            "0",
            "and",
            "(",
            "all",
            "of",
            "(",
            "$key*",
            ")",
            ")"
        ],
        "metadata": [
            {
                "author": "Rahul Mohandas"
            },
            {
                "Date": "2015-06-16"
            },
            {
                "Description": "Targeted attack using Excel/word documents"
            }
        ],
        "raw_condition": "condition:\n\t$header at 0 and (all of ($key*) )\n",
        "raw_meta": "meta:\n\tauthor = \"Rahul Mohandas\"\n\tDate = \"2015-06-16\"\n\tDescription = \"Targeted attack using Excel/word documents\"\n",
        "raw_strings": "strings:\n\t$header = {D0 CF 11 E0 A1 B1 1A E1}\n\t$key1 = \"AAAAAAAAAA\"\n\t$key2 = \"Base64Str\" nocase\n\t$key3 = \"DeleteFile\" nocase\n\t$key4 = \"Scripting.FileSystemObject\" nocase\n",
        "rule_name": "APT_OLE_JSRat",
        "start_line": 6,
        "stop_line": 20,
        "strings": [
            {
                "name": "$header",
                "type": "byte",
                "value": "{D0 CF 11 E0 A1 B1 1A E1}"
            },
            {
                "name": "$key1",
                "type": "text",
                "value": "AAAAAAAAAA"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$key2",
                "type": "text",
                "value": "Base64Str"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$key3",
                "type": "text",
                "value": "DeleteFile"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$key4",
                "type": "text",
                "value": "Scripting.FileSystemObject"
            }
        ],
        "tags": [
            "maldoc",
            "APT"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Meterpreter_Reverse_Tcp', NULL, '{"author": "chort (@chort0)", "description": "Meterpreter reverse TCP backdoor in memory. Tested on Win7x64."}', '[
    {
        "comments": [
            "// This is the standard backdoor/RAT from Metasploit, could be used by any actor "
        ],
        "condition_terms": [
            "$a",
            "or",
            "(",
            "any",
            "of",
            "(",
            "$b",
            ",",
            "$d",
            ")",
            "and",
            "$c",
            ")"
        ],
        "metadata": [
            {
                "author": "chort (@chort0)"
            },
            {
                "description": "Meterpreter reverse TCP backdoor in memory. Tested on Win7x64."
            }
        ],
        "raw_condition": "condition: \n    $a or (any of ($b, $d) and $c) \n  ",
        "raw_meta": "meta: // This is the standard backdoor/RAT from Metasploit, could be used by any actor \n    author = \"chort (@chort0)\" \n    description = \"Meterpreter reverse TCP backdoor in memory. Tested on Win7x64.\" \n  ",
        "raw_strings": "strings: \n    $a = { 4d 45 54 45 52 50 52 45 54 45 52 5f 54 52 41 4e 53 50 4f 52 54 5f 53 53 4c [32-48] 68 74 74 70 73 3a 2f 2f 58 58 58 58 58 58 } // METERPRETER_TRANSPORT_SSL \u2026 https://XXXXXX \n    $b = { 4d 45 54 45 52 50 52 45 54 45 52 5f 55 41 } // METERPRETER_UA \n    $c = { 47 45 54 20 2f 31 32 33 34 35 36 37 38 39 20 48 54 54 50 2f 31 2e 30 } // GET /123456789 HTTP/1.0 \n    $d = { 6d 65 74 73 72 76 2e 64 6c 6c [2-4] 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } // metsrv.dll \u2026 ReflectiveLoader \n    \n  ",
        "rule_name": "Meterpreter_Reverse_Tcp",
        "start_line": 5,
        "stop_line": 17,
        "strings": [
            {
                "name": "$a",
                "type": "byte",
                "value": "{ 4d 45 54 45 52 50 52 45 54 45 52 5f 54 52 41 4e 53 50 4f 52 54 5f 53 53 4c [32-48] 68 74 74 70 73 3a 2f 2f 58 58 58 58 58 58 }"
            },
            {
                "name": "$b",
                "type": "byte",
                "value": "{ 4d 45 54 45 52 50 52 45 54 45 52 5f 55 41 }"
            },
            {
                "name": "$c",
                "type": "byte",
                "value": "{ 47 45 54 20 2f 31 32 33 34 35 36 37 38 39 20 48 54 54 50 2f 31 2e 30 }"
            },
            {
                "name": "$d",
                "type": "byte",
                "value": "{ 6d 65 74 73 72 76 2e 64 6c 6c [2-4] 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 }"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Maldoc_APT10_MenuPass', NULL, '{"date": "2018-09-13", "author": "Colin Cowie", "reference": "https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html", "description": "Detects APT10 MenuPass Phishing"}', '[
    {
        "condition_terms": [
            "any",
            "of",
            "them",
            "or",
            "hash.md5",
            "(",
            "0",
            ",",
            "filesize",
            ")",
            "==",
            "\"4f83c01e8f7507d23c67ab085bf79e97\"",
            "or",
            "hash.md5",
            "(",
            "0",
            ",",
            "filesize",
            ")",
            "==",
            "\"f188936d2c8423cf064d6b8160769f21\"",
            "or",
            "hash.md5",
            "(",
            "0",
            ",",
            "filesize",
            ")",
            "==",
            "\"cca227f70a64e1e7fcf5bccdc6cc25dd\""
        ],
        "imports": [
            "hash"
        ],
        "metadata": [
            {
                "description": "Detects APT10 MenuPass Phishing"
            },
            {
                "author": "Colin Cowie"
            },
            {
                "reference": "https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html"
            },
            {
                "date": "2018-09-13"
            }
        ],
        "raw_condition": "condition:\n      any of them or\n      hash.md5(0, filesize) == \"4f83c01e8f7507d23c67ab085bf79e97\" or\n      hash.md5(0, filesize) == \"f188936d2c8423cf064d6b8160769f21\" or\n      hash.md5(0, filesize) == \"cca227f70a64e1e7fcf5bccdc6cc25dd\"\n",
        "raw_meta": "meta:\n      description = \"Detects APT10 MenuPass Phishing\"\n      author = \"Colin Cowie\"\n      reference = \"https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html\"\n      date = \"2018-09-13\"\n   ",
        "raw_strings": "strings:\n      $s1 = \"C:\\\\ProgramData\\\\padre1.txt\"\n      $s2 = \"C:\\\\ProgramData\\\\padre2.txt\"\n      $s3 = \"C:\\\\ProgramData\\\\padre3.txt\"\n      $s5 = \"C:\\\\ProgramData\\\\libcurl.txt\"\n      $s6 = \"C:\\\\ProgramData\\\\3F2E3AB9\"\n   ",
        "rule_name": "Maldoc_APT10_MenuPass",
        "start_line": 13,
        "stop_line": 30,
        "strings": [
            {
                "name": "$s1",
                "type": "text",
                "value": "C:\\\\ProgramData\\\\padre1.txt"
            },
            {
                "name": "$s2",
                "type": "text",
                "value": "C:\\\\ProgramData\\\\padre2.txt"
            },
            {
                "name": "$s3",
                "type": "text",
                "value": "C:\\\\ProgramData\\\\padre3.txt"
            },
            {
                "name": "$s5",
                "type": "text",
                "value": "C:\\\\ProgramData\\\\libcurl.txt"
            },
            {
                "name": "$s6",
                "type": "text",
                "value": "C:\\\\ProgramData\\\\3F2E3AB9"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Contains_UserForm_Object', NULL, '{"date": "2016-03-05", "author": "Martin Willing (https://evild3ad.com)", "filetype": "Office documents", "reference": "https://msdn.microsoft.com/en-us/library/office/gg264663.aspx", "description": "Detect UserForm object in MS Office document"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Martin Willing (https://evild3ad.com)"
            },
            {
                "description": "Detect UserForm object in MS Office document"
            },
            {
                "reference": "https://msdn.microsoft.com/en-us/library/office/gg264663.aspx"
            },
            {
                "date": "2016-03-05"
            },
            {
                "filetype": "Office documents"
            }
        ],
        "raw_condition": "condition:\n\t \tall of them\n",
        "raw_meta": "meta:\n\t\tauthor = \"Martin Willing (https://evild3ad.com)\"\n\t\tdescription = \"Detect UserForm object in MS Office document\"\n\t\treference = \"https://msdn.microsoft.com/en-us/library/office/gg264663.aspx\"\n\t\tdate = \"2016-03-05\"\n\t\tfiletype = \"Office documents\"\n\t\t\n\t",
        "raw_strings": "strings:\n\t\t$a = \"UserForm1\"\n\t\t$b = \"TextBox1\"\n\t\t$c = \"Microsoft Forms 2.0\"\n\t\n\t",
        "rule_name": "Contains_UserForm_Object",
        "start_line": 7,
        "stop_line": 23,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "UserForm1"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "TextBox1"
            },
            {
                "name": "$c",
                "type": "text",
                "value": "Microsoft Forms 2.0"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'rtf_objdata_urlmoniker_http', NULL, '{"ref": "https://blog.nviso.be/2017/04/12/analysis-of-a-cve-2017-0199-malicious-rtf-document/"}', '[
    {
        "condition_terms": [
            "$header",
            "at",
            "0",
            "and",
            "$objdata",
            "and",
            "$urlmoniker",
            "and",
            "$http"
        ],
        "metadata": [
            {
                "ref": "https://blog.nviso.be/2017/04/12/analysis-of-a-cve-2017-0199-malicious-rtf-document/"
            }
        ],
        "raw_condition": "condition:\n $header at 0 and $objdata and $urlmoniker and $http\n ",
        "raw_meta": "meta:\n\tref = \"https://blog.nviso.be/2017/04/12/analysis-of-a-cve-2017-0199-malicious-rtf-document/\"\n ",
        "raw_strings": "strings:\n $header = \"{\\\\rtf1\"\n $objdata = \"objdata 0105000002000000\" nocase\n $urlmoniker = \"E0C9EA79F9BACE118C8200AA004BA90B\" nocase\n $http = \"68007400740070003a002f002f00\" nocase\n ",
        "rule_name": "rtf_objdata_urlmoniker_http",
        "start_line": 5,
        "stop_line": 15,
        "strings": [
            {
                "name": "$header",
                "type": "text",
                "value": "{\\\\rtf1"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$objdata",
                "type": "text",
                "value": "objdata 0105000002000000"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$urlmoniker",
                "type": "text",
                "value": "E0C9EA79F9BACE118C8200AA004BA90B"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$http",
                "type": "text",
                "value": "68007400740070003a002f002f00"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Maldoc_Suspicious_OLE_target', NULL, '{"date": "2018-06-13", "author": "Donguk Seo", "filetype": "Office documents", "reference": "https://blog.malwarebytes.com/threat-analysis/2017/10/decoy-microsoft-word-document-delivers-malware-through-rat/", "description": "Detects maldoc With Tartgeting Suspicuios OLE"}', '[
    {
        "condition_terms": [
            "any",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Detects maldoc With Tartgeting Suspicuios OLE"
            },
            {
                "author": "Donguk Seo"
            },
            {
                "reference": "https://blog.malwarebytes.com/threat-analysis/2017/10/decoy-microsoft-word-document-delivers-malware-through-rat/"
            },
            {
                "filetype": "Office documents"
            },
            {
                "date": "2018-06-13"
            }
        ],
        "raw_condition": "condition:\n    any of them\n",
        "raw_meta": "meta:\n    description =  \"Detects maldoc With Tartgeting Suspicuios OLE\"\n    author = \"Donguk Seo\"\n    reference = \"https://blog.malwarebytes.com/threat-analysis/2017/10/decoy-microsoft-word-document-delivers-malware-through-rat/\"\n    filetype = \"Office documents\"\n    date = \"2018-06-13\"\n  ",
        "raw_strings": "strings:\n    $env1 = /oleObject\".*Target=.*.http.*.doc\"/\n    $env2 = /oleObject\".*Target=.*.http.*.ppt\"/\n    $env3 = /oleObject\".*Target=.*.http.*.xlx\"/\n  ",
        "rule_name": "Maldoc_Suspicious_OLE_target",
        "start_line": 1,
        "stop_line": 14,
        "strings": [
            {
                "name": "$env1",
                "type": "regex",
                "value": "/oleObject\".*Target=.*.http.*.doc\"/"
            },
            {
                "name": "$env2",
                "type": "regex",
                "value": "/oleObject\".*Target=.*.http.*.ppt\"/"
            },
            {
                "name": "$env3",
                "type": "regex",
                "value": "/oleObject\".*Target=.*.http.*.xlx\"/"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Contains_DDE_Protocol', NULL, '{"date": "2017-10-19", "author": "Nick Beede", "filetype": "Office documents", "reference": "https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/", "description": "Detect Dynamic Data Exchange protocol in doc/docx"}', '[
    {
        "condition_terms": [
            "(",
            "$doc",
            "at",
            "0",
            ")",
            "and",
            "2",
            "of",
            "(",
            "$s1",
            ",",
            "$s2",
            ",",
            "$s3",
            ",",
            "$s4",
            ")"
        ],
        "metadata": [
            {
                "author": "Nick Beede"
            },
            {
                "description": "Detect Dynamic Data Exchange protocol in doc/docx"
            },
            {
                "reference": "https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/"
            },
            {
                "date": "2017-10-19"
            },
            {
                "filetype": "Office documents"
            }
        ],
        "raw_condition": "condition:\n                ($doc at 0) and 2 of ($s1, $s2, $s3, $s4)\n",
        "raw_meta": "meta:\n                author = \"Nick Beede\"\n                description = \"Detect Dynamic Data Exchange protocol in doc/docx\"\n                reference = \"https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/\"\n                date = \"2017-10-19\"\n                filetype = \"Office documents\"\n        \n        ",
        "raw_strings": "strings:\n                $doc = {D0 CF 11 E0 A1 B1 1A E1}\n                $s1 = { 13 64 64 65 61 75 74 6F 20 } // !!ddeauto\n                $s2 = { 13 64 64 65 20 } // !!dde\n                $s3 = \"dde\" nocase\n                $s4 = \"ddeauto\" nocase\n\n        ",
        "rule_name": "Contains_DDE_Protocol",
        "start_line": 1,
        "stop_line": 19,
        "strings": [
            {
                "name": "$doc",
                "type": "byte",
                "value": "{D0 CF 11 E0 A1 B1 1A E1}"
            },
            {
                "name": "$s1",
                "type": "byte",
                "value": "{ 13 64 64 65 61 75 74 6F 20 }"
            },
            {
                "name": "$s2",
                "type": "byte",
                "value": "{ 13 64 64 65 20 }"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$s3",
                "type": "text",
                "value": "dde"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$s4",
                "type": "text",
                "value": "ddeauto"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'hancitor_dropper', '{vb_win32api}', '{"date": "18AUG2016", "hash1": "03aef51be133425a0e5978ab2529890854ecf1b98a7cf8289c142a62de7acd1a", "hash2": "4b3912077ef47515b2b74bc1f39de44ddd683a3a79f45c93777e49245f0e9848", "hash3": "a78972ac6dee8c7292ae06783cfa1f918bacfe956595d30a0a8d99858ce94b5a", "author": "Jeff White - jwhite@paloaltonetworks @noottrak"}', '[
    {
        "condition_terms": [
            "uint32be",
            "(",
            "0",
            ")",
            "==",
            "0xD0CF11E0",
            "and",
            "all",
            "of",
            "(",
            "$api_*",
            ")",
            "and",
            "$magic"
        ],
        "metadata": [
            {
                "author": "Jeff White - jwhite@paloaltonetworks @noottrak"
            },
            {
                "date": "18AUG2016"
            },
            {
                "hash1": "03aef51be133425a0e5978ab2529890854ecf1b98a7cf8289c142a62de7acd1a"
            },
            {
                "hash2": "4b3912077ef47515b2b74bc1f39de44ddd683a3a79f45c93777e49245f0e9848"
            },
            {
                "hash3": "a78972ac6dee8c7292ae06783cfa1f918bacfe956595d30a0a8d99858ce94b5a"
            }
        ],
        "raw_condition": "condition:\n    uint32be(0) == 0xD0CF11E0 and all of ($api_*) and $magic\n",
        "raw_meta": "meta:\n    author = \"Jeff White - jwhite@paloaltonetworks @noottrak\"\n    date   = \"18AUG2016\"\n    hash1  = \"03aef51be133425a0e5978ab2529890854ecf1b98a7cf8289c142a62de7acd1a\"\n    hash2  = \"4b3912077ef47515b2b74bc1f39de44ddd683a3a79f45c93777e49245f0e9848\"\n    hash3  = \"a78972ac6dee8c7292ae06783cfa1f918bacfe956595d30a0a8d99858ce94b5a\"\n\n  ",
        "raw_strings": "strings:\n    $api_01 = { 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 }  // VirtualAlloc\n    $api_02 = { 00 52 74 6C 4D 6F 76 65 4D 65 6D 6F 72 79 00 }  // RtlMoveMemory\n    $api_04 = { 00 43 61 6C 6C 57 69 6E 64 6F 77 50 72 6F 63 41 00 }  // CallWindowProcAi\n    $magic  = { 50 4F 4C 41 }  // POLA\n\n  ",
        "rule_name": "hancitor_dropper",
        "start_line": 4,
        "stop_line": 21,
        "strings": [
            {
                "name": "$api_01",
                "type": "byte",
                "value": "{ 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 }"
            },
            {
                "name": "$api_02",
                "type": "byte",
                "value": "{ 00 52 74 6C 4D 6F 76 65 4D 65 6D 6F 72 79 00 }"
            },
            {
                "name": "$api_04",
                "type": "byte",
                "value": "{ 00 43 61 6C 6C 57 69 6E 64 6F 77 50 72 6F 63 41 00 }"
            },
            {
                "name": "$magic",
                "type": "byte",
                "value": "{ 50 4F 4C 41 }"
            }
        ],
        "tags": [
            "vb_win32api"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Contains_VBE_File', '{maldoc}', '{"author": "Didier Stevens (https://DidierStevens.com)", "method": "Find string starting with #@~^ and ending with ^#~@", "description": "Detect a VBE file inside a byte sequence"}', '[
    {
        "condition_terms": [
            "$vbe"
        ],
        "metadata": [
            {
                "author": "Didier Stevens (https://DidierStevens.com)"
            },
            {
                "description": "Detect a VBE file inside a byte sequence"
            },
            {
                "method": "Find string starting with #@~^ and ending with ^#~@"
            }
        ],
        "raw_condition": "condition:\n        $vbe\n",
        "raw_meta": "meta:\n        author = \"Didier Stevens (https://DidierStevens.com)\"\n        description = \"Detect a VBE file inside a byte sequence\"\n        method = \"Find string starting with #@~^ and ending with ^#~@\"\n    ",
        "raw_strings": "strings:\n        $vbe = /#@~\\^.+\\^#~@/\n    ",
        "rule_name": "Contains_VBE_File",
        "start_line": 18,
        "stop_line": 28,
        "strings": [
            {
                "name": "$vbe",
                "type": "regex",
                "value": "/#@~\\^.+\\^#~@/"
            }
        ],
        "tags": [
            "maldoc"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Contains_VBA_macro_code', NULL, '{"date": "2016-01-09", "author": "evild3ad", "filetype": "Office documents", "description": "Detect a MS Office document with embedded VBA macro code"}', '[
    {
        "condition_terms": [
            "(",
            "$officemagic",
            "at",
            "0",
            "and",
            "any",
            "of",
            "(",
            "$97str*",
            ")",
            ")",
            "or",
            "(",
            "$zipmagic",
            "at",
            "0",
            "and",
            "any",
            "of",
            "(",
            "$xmlstr*",
            ")",
            ")"
        ],
        "metadata": [
            {
                "author": "evild3ad"
            },
            {
                "description": "Detect a MS Office document with embedded VBA macro code"
            },
            {
                "date": "2016-01-09"
            },
            {
                "filetype": "Office documents"
            }
        ],
        "raw_condition": "condition:\n\t\t($officemagic at 0 and any of ($97str*)) or ($zipmagic at 0 and any of ($xmlstr*))\n",
        "raw_meta": "meta:\n\t\tauthor = \"evild3ad\"\n\t\tdescription = \"Detect a MS Office document with embedded VBA macro code\"\n\t\tdate = \"2016-01-09\"\n\t\tfiletype = \"Office documents\"\n\n\t",
        "raw_strings": "strings:\n\t\t$officemagic = { D0 CF 11 E0 A1 B1 1A E1 }\n\t\t$zipmagic = \"PK\"\n\n\t\t$97str1 = \"_VBA_PROJECT_CUR\" wide\n\t\t$97str2 = \"VBAProject\"\n\t\t$97str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F } // Attribute VB_\n\n\t\t$xmlstr1 = \"vbaProject.bin\"\n\t\t$xmlstr2 = \"vbaData.xml\"\n\n\t",
        "rule_name": "Contains_VBA_macro_code",
        "start_line": 7,
        "stop_line": 28,
        "strings": [
            {
                "name": "$officemagic",
                "type": "byte",
                "value": "{ D0 CF 11 E0 A1 B1 1A E1 }"
            },
            {
                "name": "$zipmagic",
                "type": "text",
                "value": "PK"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$97str1",
                "type": "text",
                "value": "_VBA_PROJECT_CUR"
            },
            {
                "name": "$97str2",
                "type": "text",
                "value": "VBAProject"
            },
            {
                "name": "$97str3",
                "type": "byte",
                "value": "{ 41 74 74 72 69 62 75 74 00 65 20 56 42 5F }"
            },
            {
                "name": "$xmlstr1",
                "type": "text",
                "value": "vbaProject.bin"
            },
            {
                "name": "$xmlstr2",
                "type": "text",
                "value": "vbaData.xml"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'malrtf_ole2link', '{exploit}', '{"author": "@h3x2b <tracker _AT h3x.eu>", "description": "Detect weaponized RTF documents with OLE2Link exploit"}', '[
    {
        "comments": [
            "//new_file and",
            "//normal rtf beginning"
        ],
        "condition_terms": [
            "any",
            "of",
            "(",
            "$rtf_format_*",
            ")",
            "and",
            "all",
            "of",
            "(",
            "$rtf_olelink_*",
            ")",
            "and",
            "any",
            "of",
            "(",
            "$rtf_payload_*",
            ")"
        ],
        "metadata": [
            {
                "author": "@h3x2b <tracker _AT h3x.eu>"
            },
            {
                "description": "Detect weaponized RTF documents with OLE2Link exploit"
            }
        ],
        "raw_condition": "condition:\n\t\t//new_file and\n\t\tany of ($rtf_format_*)\n\t\tand all of ($rtf_olelink_*)\n\t\tand any of ($rtf_payload_*)\n",
        "raw_meta": "meta:\n\t\tauthor = \"@h3x2b <tracker _AT h3x.eu>\"\n\t\tdescription = \"Detect weaponized RTF documents with OLE2Link exploit\"\n\n\t",
        "raw_strings": "strings:\n\t\t//normal rtf beginning\n\t\t$rtf_format_00 = \"{\\\\rtf1\"\n\t\t//malformed rtf can have for example {\\\\rtA1\n\t\t$rtf_format_01 = \"{\\\\rt\"\n\n\t\t//having objdata structure\n\t\t$rtf_olelink_01 = \"\\\\objdata\" nocase\n\n\t\t//hex encoded OLE2Link\n\t\t$rtf_olelink_02 = \"4f4c45324c696e6b\" nocase\n\n\t\t//hex encoded docfile magic - doc file albilae\n\t\t$rtf_olelink_03 = \"d0cf11e0a1b11ae1\" nocase\n\n\t\t//hex encoded \"http://\"\n\t\t$rtf_payload_01 = \"68007400740070003a002f002f00\" nocase\n\n\t\t//hex encoded \"https://\"\n\t\t$rtf_payload_02 = \"680074007400700073003a002f002f00\" nocase\n\n\t\t//hex encoded \"ftp://\"\n\t\t$rtf_payload_03 = \"6600740070003a002f002f00\" nocase\n\n\n\t",
        "rule_name": "malrtf_ole2link",
        "start_line": 5,
        "stop_line": 41,
        "strings": [
            {
                "name": "$rtf_format_00",
                "type": "text",
                "value": "{\\\\rtf1"
            },
            {
                "name": "$rtf_format_01",
                "type": "text",
                "value": "{\\\\rt"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$rtf_olelink_01",
                "type": "text",
                "value": "\\\\objdata"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$rtf_olelink_02",
                "type": "text",
                "value": "4f4c45324c696e6b"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$rtf_olelink_03",
                "type": "text",
                "value": "d0cf11e0a1b11ae1"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$rtf_payload_01",
                "type": "text",
                "value": "68007400740070003a002f002f00"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$rtf_payload_02",
                "type": "text",
                "value": "680074007400700073003a002f002f00"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$rtf_payload_03",
                "type": "text",
                "value": "6600740070003a002f002f00"
            }
        ],
        "tags": [
            "exploit"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Maldoc_CVE_2017_11882', '{Exploit}', '{"date": "2017-10-20", "author": "Marc Salinas (@Bondey_m)", "reference": "c63ccc5c08c3863d7eb330b69f96c1bcf1e031201721754132a4c4d0baff36f8", "description": "Detects maldoc With exploit for CVE_2017_11882"}', '[
    {
        "condition_terms": [
            "$s0",
            "and",
            "(",
            "$h0",
            "or",
            "$s1",
            ")"
        ],
        "metadata": [
            {
                "description": "Detects maldoc With exploit for CVE_2017_11882"
            },
            {
                "author": "Marc Salinas (@Bondey_m)"
            },
            {
                "reference": "c63ccc5c08c3863d7eb330b69f96c1bcf1e031201721754132a4c4d0baff36f8"
            },
            {
                "date": "2017-10-20"
            }
        ],
        "raw_condition": "condition: \n        $s0 and ($h0 or $s1)\n",
        "raw_meta": "meta:\n        description = \"Detects maldoc With exploit for CVE_2017_11882\"\n        author = \"Marc Salinas (@Bondey_m)\"\n        reference = \"c63ccc5c08c3863d7eb330b69f96c1bcf1e031201721754132a4c4d0baff36f8\"\n        date = \"2017-10-20\"\n    ",
        "raw_strings": "strings:\n        $s0 = \"Equation\"\n        $s1 = \"1c000000020\"\n        $h0 = {1C 00 00 00 02 00}\n\n    ",
        "rule_name": "Maldoc_CVE_2017_11882",
        "start_line": 1,
        "stop_line": 14,
        "strings": [
            {
                "name": "$s0",
                "type": "text",
                "value": "Equation"
            },
            {
                "name": "$s1",
                "type": "text",
                "value": "1c000000020"
            },
            {
                "name": "$h0",
                "type": "byte",
                "value": "{1C 00 00 00 02 00}"
            }
        ],
        "tags": [
            "Exploit"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'maldoc_OLE_file_magic_number', '{maldoc}', '{"author": "Didier Stevens (https://DidierStevens.com)"}', '[
    {
        "condition_terms": [
            "$a"
        ],
        "metadata": [
            {
                "author": "Didier Stevens (https://DidierStevens.com)"
            }
        ],
        "raw_condition": "condition:\n        $a\n",
        "raw_meta": "meta:\n        author = \"Didier Stevens (https://DidierStevens.com)\"\n    ",
        "raw_strings": "strings:\n        $a = {D0 CF 11 E0}\n    ",
        "rule_name": "maldoc_OLE_file_magic_number",
        "start_line": 6,
        "stop_line": 14,
        "strings": [
            {
                "name": "$a",
                "type": "byte",
                "value": "{D0 CF 11 E0}"
            }
        ],
        "tags": [
            "maldoc"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'contains_base64', '{Base64}', '{"notes": "https://github.com/Yara-Rules/rules/issues/153", "author": "Jaume Martin", "version": "0.2", "description": "This rule finds for base64 strings"}', '[
    {
        "condition_terms": [
            "$a"
        ],
        "metadata": [
            {
                "author": "Jaume Martin"
            },
            {
                "description": "This rule finds for base64 strings"
            },
            {
                "version": "0.2"
            },
            {
                "notes": "https://github.com/Yara-Rules/rules/issues/153"
            }
        ],
        "raw_condition": "condition:\n        $a\n",
        "raw_meta": "meta:\n        author = \"Jaume Martin\"\n        description = \"This rule finds for base64 strings\"\n        version = \"0.2\"\n        notes = \"https://github.com/Yara-Rules/rules/issues/153\"\n    ",
        "raw_strings": "strings:\n        $a = /([A-Za-z0-9+\\/]{4}){3,}([A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=)?/\n    ",
        "rule_name": "contains_base64",
        "start_line": 6,
        "stop_line": 17,
        "strings": [
            {
                "name": "$a",
                "type": "regex",
                "value": "/([A-Za-z0-9+\\/]{4}){3,}([A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=)?/"
            }
        ],
        "tags": [
            "Base64"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'url', NULL, '{"author": "Antonio S. <asanchez@plutec.net>"}', '[
    {
        "condition_terms": [
            "$url_regex"
        ],
        "metadata": [
            {
                "author": "Antonio S. <asanchez@plutec.net>"
            }
        ],
        "raw_condition": "condition:\n        $url_regex\n",
        "raw_meta": "meta:\n        author = \"Antonio S. <asanchez@plutec.net>\"\n    ",
        "raw_strings": "strings:\n        $url_regex = /https?:\\/\\/([\\w\\.-]+)([\\/\\w \\.-]*)/ wide ascii\n    ",
        "rule_name": "url",
        "start_line": 6,
        "stop_line": 13,
        "strings": [
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$url_regex",
                "type": "regex",
                "value": "/https?:\\/\\/([\\w\\.-]+)([\\/\\w \\.-]*)/"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'IP', NULL, '{"author": "Antonio S. <asanchez@plutec.net>"}', '[
    {
        "condition_terms": [
            "any",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Antonio S. <asanchez@plutec.net>"
            }
        ],
        "raw_condition": "condition:\n        any of them\n",
        "raw_meta": "meta:\n        author = \"Antonio S. <asanchez@plutec.net>\"\n    ",
        "raw_strings": "strings:\n        $ipv4 = /([0-9]{1,3}\\.){3}[0-9]{1,3}/ wide ascii\n        $ipv6 = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/ wide ascii\n    ",
        "rule_name": "IP",
        "start_line": 6,
        "stop_line": 14,
        "strings": [
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$ipv4",
                "type": "regex",
                "value": "/([0-9]{1,3}\\.){3}[0-9]{1,3}/"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$ipv6",
                "type": "regex",
                "value": "/(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'domain', NULL, '{"author": "Antonio S. <asanchez@plutec.net>"}', '[
    {
        "condition_terms": [
            "$domain_regex"
        ],
        "metadata": [
            {
                "author": "Antonio S. <asanchez@plutec.net>"
            }
        ],
        "raw_condition": "condition:\n        $domain_regex\n",
        "raw_meta": "meta:\n        author = \"Antonio S. <asanchez@plutec.net>\"\n    ",
        "raw_strings": "strings:\n        $domain_regex = /([\\w\\.-]+)/ wide ascii\n    ",
        "rule_name": "domain",
        "start_line": 6,
        "stop_line": 13,
        "strings": [
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$domain_regex",
                "type": "regex",
                "value": "/([\\w\\.-]+)/"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Email_Generic_Phishing', '{email}', '{"Author": "Tyler <@InfoSecTyler>", "Description": "Generic rule to identify phishing emails"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "(",
            "$eml*",
            ")",
            "and",
            "any",
            "of",
            "(",
            "$greeting*",
            ")",
            "and",
            "any",
            "of",
            "(",
            "$url*",
            ")",
            "and",
            "any",
            "of",
            "(",
            "$lie*",
            ")"
        ],
        "metadata": [
            {
                "Author": "Tyler <@InfoSecTyler>"
            },
            {
                "Description": "Generic rule to identify phishing emails"
            }
        ],
        "raw_condition": "condition:\n    all of ($eml*) and\n    any of ($greeting*) and\n    any of ($url*) and\n    any of ($lie*)\n",
        "raw_meta": "meta:\n\t\tAuthor = \"Tyler <@InfoSecTyler>\"\n\t\tDescription =\"Generic rule to identify phishing emails\"\n\n  ",
        "raw_strings": "strings:\n    $eml_1=\"From:\"\n    $eml_2=\"To:\"\n    $eml_3=\"Subject:\"\n\n    $greeting_1=\"Hello sir/madam\" nocase\n    $greeting_2=\"Attention\" nocase\n    $greeting_3=\"Dear user\" nocase\n    $greeting_4=\"Account holder\" nocase\n\n    $url_1=\"Click\" nocase\n    $url_2=\"Confirm\" nocase\n    $url_3=\"Verify\" nocase\n    $url_4=\"Here\" nocase\n    $url_5=\"Now\" nocase\n    $url_6=\"Change password\" nocase \n\n    $lie_1=\"Unauthorized\" nocase\n    $lie_2=\"Expired\" nocase\n    $lie_3=\"Deleted\" nocase\n    $lie_4=\"Suspended\" nocase\n    $lie_5=\"Revoked\" nocase\n    $lie_6=\"Unable\" nocase\n\n  ",
        "rule_name": "Email_Generic_Phishing",
        "start_line": 7,
        "stop_line": 42,
        "strings": [
            {
                "name": "$eml_1",
                "type": "text",
                "value": "From:"
            },
            {
                "name": "$eml_2",
                "type": "text",
                "value": "To:"
            },
            {
                "name": "$eml_3",
                "type": "text",
                "value": "Subject:"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$greeting_1",
                "type": "text",
                "value": "Hello sir/madam"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$greeting_2",
                "type": "text",
                "value": "Attention"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$greeting_3",
                "type": "text",
                "value": "Dear user"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$greeting_4",
                "type": "text",
                "value": "Account holder"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$url_1",
                "type": "text",
                "value": "Click"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$url_2",
                "type": "text",
                "value": "Confirm"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$url_3",
                "type": "text",
                "value": "Verify"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$url_4",
                "type": "text",
                "value": "Here"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$url_5",
                "type": "text",
                "value": "Now"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$url_6",
                "type": "text",
                "value": "Change password"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$lie_1",
                "type": "text",
                "value": "Unauthorized"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$lie_2",
                "type": "text",
                "value": "Expired"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$lie_3",
                "type": "text",
                "value": "Deleted"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$lie_4",
                "type": "text",
                "value": "Suspended"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$lie_5",
                "type": "text",
                "value": "Revoked"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$lie_6",
                "type": "text",
                "value": "Unable"
            }
        ],
        "tags": [
            "email"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Email_quota_limit_warning', '{mail}', '{"Author": "Tyler Linne <@InfoSecTyler>", "Description": "Rule to prevent against known email quota limit phishing campaign"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "(",
            "$eml_*",
            ")",
            "and",
            "1",
            "of",
            "(",
            "$subject*",
            ")",
            "and",
            "1",
            "of",
            "(",
            "$hello*",
            ")",
            "and",
            "4",
            "of",
            "(",
            "$body*",
            ")"
        ],
        "metadata": [
            {
                "Author": "Tyler Linne <@InfoSecTyler>"
            },
            {
                "Description": "Rule to prevent against known email quota limit phishing campaign"
            }
        ],
        "raw_condition": "condition:\n    all of ($eml_*) and\n    1 of ($subject*) and \n    1 of ($hello*) and \n    4 of ($body*) \n",
        "raw_meta": "meta:\n\t\tAuthor = \"Tyler Linne <@InfoSecTyler>\"\n\t\tDescription =\"Rule to prevent against known email quota limit phishing campaign\"\n    \n  ",
        "raw_strings": "strings:\n    $eml_01 = \"From:\" //Added eml context\n    $eml_02 = \"To:\"\n    $eml_03 = \"Subject:\"\n    $subject1={ 44 65 61 72 20 [0-11] 20 41 63 63 6f 75 6e 74 20 55 73 65 72 73 } // Range allows for different company names to be accepted\n    $hello1={ 44 65 61 72 20 [0-11] 20 41 63 63 6f 75 6e 74 20 55 73 65 72 73 }\n    $body1=\"You have exceded\" nocase\n    $body2={65 2d 6d 61 69 6c 20 61 63 63 6f 75 6e 74 20 6c 69 6d 69 74 20 71 75 6f 74 61 20 6f 66 } //Range allows for different quota \"upgrade\" sizes\n    $body3=\"requested to expand it within 24 hours\" nocase\n    $body4=\"e-mail account will be disable from our database\" nocase\n    $body5=\"simply click with the complete information\" nocase\n    $body6=\"requested to expand your account quota\" nocase\n    $body7={54 68 61 6e 6b 20 79 6f 75 20 66 6f 72 20 75 73 69 6e 67 20 [0-11] 20 57 65 62 6d 61 69 6c } // Range allows for different company names to be accepted\n\n  ",
        "rule_name": "Email_quota_limit_warning",
        "start_line": 6,
        "stop_line": 31,
        "strings": [
            {
                "name": "$eml_01",
                "type": "text",
                "value": "From:"
            },
            {
                "name": "$eml_02",
                "type": "text",
                "value": "To:"
            },
            {
                "name": "$eml_03",
                "type": "text",
                "value": "Subject:"
            },
            {
                "name": "$subject1",
                "type": "byte",
                "value": "{ 44 65 61 72 20 [0-11] 20 41 63 63 6f 75 6e 74 20 55 73 65 72 73 }"
            },
            {
                "name": "$hello1",
                "type": "byte",
                "value": "{ 44 65 61 72 20 [0-11] 20 41 63 63 6f 75 6e 74 20 55 73 65 72 73 }"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$body1",
                "type": "text",
                "value": "You have exceded"
            },
            {
                "name": "$body2",
                "type": "byte",
                "value": "{65 2d 6d 61 69 6c 20 61 63 63 6f 75 6e 74 20 6c 69 6d 69 74 20 71 75 6f 74 61 20 6f 66 }"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$body3",
                "type": "text",
                "value": "requested to expand it within 24 hours"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$body4",
                "type": "text",
                "value": "e-mail account will be disable from our database"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$body5",
                "type": "text",
                "value": "simply click with the complete information"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$body6",
                "type": "text",
                "value": "requested to expand your account quota"
            },
            {
                "name": "$body7",
                "type": "byte",
                "value": "{54 68 61 6e 6b 20 79 6f 75 20 66 6f 72 20 75 73 69 6e 67 20 [0-11] 20 57 65 62 6d 61 69 6c }"
            }
        ],
        "tags": [
            "mail"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'extortion_email', NULL, '{"data": "12th May 2020", "author": "milann shrestha <Twitter - @x0verhaul>", "description": "Detects the possible extortion scam on the basis of subjects and keywords"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "(",
            "$eml*",
            ")",
            "and",
            "any",
            "of",
            "(",
            "$sub*",
            ")",
            "and",
            "any",
            "of",
            "(",
            "$key*",
            ")"
        ],
        "metadata": [
            {
                "author": "milann shrestha <Twitter - @x0verhaul>"
            },
            {
                "description": "Detects the possible extortion scam on the basis of subjects and keywords"
            },
            {
                "data": "12th May 2020"
            }
        ],
        "raw_condition": "condition: \n    all of ($eml*) and\n    any of ($sub*) and\n    any of ($key*)\n",
        "raw_meta": "meta:\n    author = \"milann shrestha <Twitter - @x0verhaul>\"\n\t\tdescription = \"Detects the possible extortion scam on the basis of subjects and keywords\"\n\t\tdata = \"12th May 2020\"\n\n\t",
        "raw_strings": "strings:\n\t  $eml1=\"From:\"\n    $eml2=\"To:\"\n    $eml3=\"Subject:\"\n\t\t\n\t\t// Common Subjects scammer keep for luring the targets \n    $sub1 = \"Hackers know password from your account.\"\n    $sub2 = \"Security Alert. Your accounts were hacked by a criminal group.\"\n    $sub3 = \"Your account was under attack! Change your credentials!\"\n    $sub4 = \"The decision to suspend your account. Waiting for payment\"\n    $sub5 = \"Fraudsters know your old passwords. Access data must be changed.\"\n    $sub6 = \"Your account has been hacked! You need to unlock it.\"\n    $sub7 = \"Be sure to read this message! Your personal data is threatened!\"\n    $sub8 = \"Password must be changed now.\"\n\n\t\t// Keywords used for extortion\n    $key1 = \"BTC\" nocase\n    $key2 = \"Wallet\" nocase\n    $key3 = \"Bitcoin\" nocase\n    $key4 = \"hours\" nocase\n    $key5 = \"payment\" nocase\n    $key6 = \"malware\" nocase\n    $key = \"bitcoin address\" nocase\n    $key7 = \"access\" nocase\n    $key8 = \"virus\" nocase\n\n\t",
        "rule_name": "extortion_email",
        "start_line": 1,
        "stop_line": 38,
        "strings": [
            {
                "name": "$eml1",
                "type": "text",
                "value": "From:"
            },
            {
                "name": "$eml2",
                "type": "text",
                "value": "To:"
            },
            {
                "name": "$eml3",
                "type": "text",
                "value": "Subject:"
            },
            {
                "name": "$sub1",
                "type": "text",
                "value": "Hackers know password from your account."
            },
            {
                "name": "$sub2",
                "type": "text",
                "value": "Security Alert. Your accounts were hacked by a criminal group."
            },
            {
                "name": "$sub3",
                "type": "text",
                "value": "Your account was under attack! Change your credentials!"
            },
            {
                "name": "$sub4",
                "type": "text",
                "value": "The decision to suspend your account. Waiting for payment"
            },
            {
                "name": "$sub5",
                "type": "text",
                "value": "Fraudsters know your old passwords. Access data must be changed."
            },
            {
                "name": "$sub6",
                "type": "text",
                "value": "Your account has been hacked! You need to unlock it."
            },
            {
                "name": "$sub7",
                "type": "text",
                "value": "Be sure to read this message! Your personal data is threatened!"
            },
            {
                "name": "$sub8",
                "type": "text",
                "value": "Password must be changed now."
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$key1",
                "type": "text",
                "value": "BTC"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$key2",
                "type": "text",
                "value": "Wallet"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$key3",
                "type": "text",
                "value": "Bitcoin"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$key4",
                "type": "text",
                "value": "hours"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$key5",
                "type": "text",
                "value": "payment"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$key6",
                "type": "text",
                "value": "malware"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$key",
                "type": "text",
                "value": "bitcoin address"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$key7",
                "type": "text",
                "value": "access"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$key8",
                "type": "text",
                "value": "virus"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Fake_it_maintenance_bulletin', '{mail}', '{"Author": "Tyler Linne <@InfoSecTyler>", "Description": "Rule to prevent against known phishing campaign targeting American companies using Microsoft Exchange"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "(",
            "$eml_*",
            ")",
            "and",
            "1",
            "of",
            "(",
            "$subject*",
            ")",
            "and",
            "4",
            "of",
            "(",
            "$body*",
            ")"
        ],
        "metadata": [
            {
                "Author": "Tyler Linne <@InfoSecTyler>"
            },
            {
                "Description": "Rule to prevent against known phishing campaign targeting American companies using Microsoft Exchange"
            }
        ],
        "raw_condition": "condition:\n    all of ($eml_*)and\n    1 of ($subject*) and\n    4 of ($body*) \n",
        "raw_meta": "meta:\n\t\tAuthor = \"Tyler Linne <@InfoSecTyler>\"\n\t\tDescription =\"Rule to prevent against known phishing campaign targeting American companies using Microsoft Exchange\"\n  ",
        "raw_strings": "strings:\n    $eml_1=\"From:\"\n    $eml_2=\"To:\"\n    $eml_3=\"Subject:\"\n    $subject1={49 54 20 53 45 52 56 49 43 45 20 4d 61 69 6e 74 65 6e 61 6e 63 65 20 42 75 6c 6c 65 74 69 6e} //Range is for varying date of \"notification\"\n    $subject2={44 45 53 43 52 49 50 54 49 4f 4e 3a 20 53 65 72 76 65 72 20 55 70 67 72 61 64 65 20 4d 61 69 6e 74 65 6e 61 6e 63 65} //Range is for server name varriation \n    $body1=\"Message prompted from IT Helpdesk Support\" nocase\n    $body2=\"We are currently undergoing server maintenance upgrade\" nocase\n    $body3=\"Upgrade is to improve our security and new mail experience\" nocase\n    $body4=\"As an active Outlook user, you are kindly instructed  to upgrade your mail account by Logging-in the below link\" nocase\n    $body5=\"Sign in to Access Upgrade\" nocase\n    $body6=\"Our goal is to provide excellent customer service\" nocase\n    $body7=\"Thanks,/n OWA - IT Helpdesk Service\" nocase\n\n  ",
        "rule_name": "Fake_it_maintenance_bulletin",
        "start_line": 1,
        "stop_line": 24,
        "strings": [
            {
                "name": "$eml_1",
                "type": "text",
                "value": "From:"
            },
            {
                "name": "$eml_2",
                "type": "text",
                "value": "To:"
            },
            {
                "name": "$eml_3",
                "type": "text",
                "value": "Subject:"
            },
            {
                "name": "$subject1",
                "type": "byte",
                "value": "{49 54 20 53 45 52 56 49 43 45 20 4d 61 69 6e 74 65 6e 61 6e 63 65 20 42 75 6c 6c 65 74 69 6e}"
            },
            {
                "name": "$subject2",
                "type": "byte",
                "value": "{44 45 53 43 52 49 50 54 49 4f 4e 3a 20 53 65 72 76 65 72 20 55 70 67 72 61 64 65 20 4d 61 69 6e 74 65 6e 61 6e 63 65}"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$body1",
                "type": "text",
                "value": "Message prompted from IT Helpdesk Support"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$body2",
                "type": "text",
                "value": "We are currently undergoing server maintenance upgrade"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$body3",
                "type": "text",
                "value": "Upgrade is to improve our security and new mail experience"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$body4",
                "type": "text",
                "value": "As an active Outlook user, you are kindly instructed  to upgrade your mail account by Logging-in the below link"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$body5",
                "type": "text",
                "value": "Sign in to Access Upgrade"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$body6",
                "type": "text",
                "value": "Our goal is to provide excellent customer service"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$body7",
                "type": "text",
                "value": "Thanks,/n OWA - IT Helpdesk Service"
            }
        ],
        "tags": [
            "mail"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'CVE_2013_0422', NULL, '{"cve": "CVE-2013-0422", "ref": "http://pastebin.com/JVedyrCe", "date": "12-Jan-2013", "hide": false, "author": "adnan.shukor@gmail.com", "impact": 4, "version": "1", "description": "Java Applet JMX Remote Code Execution"}', '[
    {
        "condition_terms": [
            "(",
            "all",
            "of",
            "(",
            "$0422_*",
            ")",
            ")",
            "or",
            "(",
            "all",
            "of",
            "them",
            ")"
        ],
        "metadata": [
            {
                "description": "Java Applet JMX Remote Code Execution"
            },
            {
                "cve": "CVE-2013-0422"
            },
            {
                "ref": "http://pastebin.com/JVedyrCe"
            },
            {
                "author": "adnan.shukor@gmail.com"
            },
            {
                "date": "12-Jan-2013"
            },
            {
                "version": "1"
            },
            {
                "impact": 4
            },
            {
                "hide": false
            }
        ],
        "raw_condition": "condition:\n                (all of ($0422_*)) or (all of them)\n",
        "raw_meta": "meta:\n                description = \"Java Applet JMX Remote Code Execution\"\n                cve = \"CVE-2013-0422\"\n                ref = \"http://pastebin.com/JVedyrCe\"\n                author = \"adnan.shukor@gmail.com\"\n                date = \"12-Jan-2013\"\n                version = \"1\"\n                impact = 4\n                hide = false\n        ",
        "raw_strings": "strings:\n                $0422_1 = \"com/sun/jmx/mbeanserver/JmxMBeanServer\" fullword\n                $0422_2 = \"com/sun/jmx/mbeanserver/JmxMBeanServerBuilder\" fullword\n                $0422_3 = \"com/sun/jmx/mbeanserver/MBeanInstantiator\" fullword\n                $0422_4 = \"findClass\" fullword\n                $0422_5 = \"publicLookup\" fullword\n                $class = /sun\\.org\\.mozilla\\.javascript\\.internal\\.(Context|GeneratedClassLoader)/ fullword \n        ",
        "rule_name": "CVE_2013_0422",
        "start_line": 1,
        "stop_line": 21,
        "strings": [
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$0422_1",
                "type": "text",
                "value": "com/sun/jmx/mbeanserver/JmxMBeanServer"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$0422_2",
                "type": "text",
                "value": "com/sun/jmx/mbeanserver/JmxMBeanServerBuilder"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$0422_3",
                "type": "text",
                "value": "com/sun/jmx/mbeanserver/MBeanInstantiator"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$0422_4",
                "type": "text",
                "value": "findClass"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$0422_5",
                "type": "text",
                "value": "publicLookup"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$class",
                "type": "regex",
                "value": "/sun\\.org\\.mozilla\\.javascript\\.internal\\.(Context|GeneratedClassLoader)/"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'MSIETabularActivex', NULL, '{"ref": "CVE-2010-0805", "hide": true, "author": "@d3t0n4t0r", "impact": 7}', '[
    {
        "condition_terms": [
            "(",
            "$cve20100805_1",
            "and",
            "$cve20100805_3",
            ")",
            "or",
            "(",
            "all",
            "of",
            "them",
            ")"
        ],
        "metadata": [
            {
                "ref": "CVE-2010-0805"
            },
            {
                "impact": 7
            },
            {
                "hide": true
            },
            {
                "author": "@d3t0n4t0r"
            }
        ],
        "raw_condition": "condition:\n                ($cve20100805_1 and $cve20100805_3) or (all of them)\n",
        "raw_meta": "meta:\n                ref = \"CVE-2010-0805\"\n                impact = 7\n                hide = true\n                author = \"@d3t0n4t0r\"\n        ",
        "raw_strings": "strings:\n                $cve20100805_1 = \"333C7BC4-460F-11D0-BC04-0080C7055A83\" nocase fullword\n                $cve20100805_2 = \"DataURL\" nocase fullword\n                $cve20100805_3 = \"true\"\n        ",
        "rule_name": "MSIETabularActivex",
        "start_line": 1,
        "stop_line": 14,
        "strings": [
            {
                "modifiers": [
                    "nocase",
                    "fullword"
                ],
                "name": "$cve20100805_1",
                "type": "text",
                "value": "333C7BC4-460F-11D0-BC04-0080C7055A83"
            },
            {
                "modifiers": [
                    "nocase",
                    "fullword"
                ],
                "name": "$cve20100805_2",
                "type": "text",
                "value": "DataURL"
            },
            {
                "name": "$cve20100805_3",
                "type": "text",
                "value": "true"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Flash_CVE_2015_5119_APT3', '{Exploit}', '{"date": "2015-08-01", "score": 70, "author": "Florian Roth", "description": "Exploit Sample CVE-2015-5119"}', '[
    {
        "condition_terms": [
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5746",
            "and",
            "1",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Exploit Sample CVE-2015-5119"
            },
            {
                "author": "Florian Roth"
            },
            {
                "score": 70
            },
            {
                "date": "2015-08-01"
            }
        ],
        "raw_condition": "condition:\n        uint16(0) == 0x5746 and 1 of them\n",
        "raw_meta": "meta:\n        description = \"Exploit Sample CVE-2015-5119\"\n        author = \"Florian Roth\"\n        score = 70\n        date = \"2015-08-01\"\n    ",
        "raw_strings": "strings:\n        $s0 = \"HT_exploit\" fullword ascii\n        $s1 = \"HT_Exploit\" fullword ascii\n        $s2 = \"flash_exploit_\" ascii\n        $s3 = \"exp1_fla/MainTimeline\" ascii fullword\n        $s4 = \"exp2_fla/MainTimeline\" ascii fullword\n        $s5 = \"_shellcode_32\" fullword ascii\n        $s6 = \"todo: unknown 32-bit target\" fullword ascii \n    ",
        "rule_name": "Flash_CVE_2015_5119_APT3",
        "start_line": 6,
        "stop_line": 22,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s0",
                "type": "text",
                "value": "HT_exploit"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "HT_Exploit"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$s2",
                "type": "text",
                "value": "flash_exploit_"
            },
            {
                "modifiers": [
                    "ascii",
                    "fullword"
                ],
                "name": "$s3",
                "type": "text",
                "value": "exp1_fla/MainTimeline"
            },
            {
                "modifiers": [
                    "ascii",
                    "fullword"
                ],
                "name": "$s4",
                "type": "text",
                "value": "exp2_fla/MainTimeline"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s5",
                "type": "text",
                "value": "_shellcode_32"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s6",
                "type": "text",
                "value": "todo: unknown 32-bit target"
            }
        ],
        "tags": [
            "Exploit"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'CVE_2018_20250', '{AceArchive,UNACEV2_DLL_EXP}', '{"date": "2019-03-17", "author": "xylitol@temari.fr", "reference": "https://research.checkpoint.com/extracting-code-execution-from-winrar/", "description": "Generic rule for hostile ACE archive using CVE-2018-20250"}', '[
    {
        "comments": [
            "// May only the challenge guide you"
        ],
        "condition_terms": [
            "$string1",
            "at",
            "7",
            "and",
            "$string2",
            "at",
            "31",
            "and",
            "1",
            "of",
            "(",
            "$hexstring*",
            ")"
        ],
        "metadata": [
            {
                "description": "Generic rule for hostile ACE archive using CVE-2018-20250"
            },
            {
                "author": "xylitol@temari.fr"
            },
            {
                "date": "2019-03-17"
            },
            {
                "reference": "https://research.checkpoint.com/extracting-code-execution-from-winrar/"
            }
        ],
        "raw_condition": "condition:  \n         $string1 at 7 and $string2 at 31 and 1 of ($hexstring*)\n",
        "raw_meta": "meta:\n        description = \"Generic rule for hostile ACE archive using CVE-2018-20250\"\n        author = \"xylitol@temari.fr\"\n        date = \"2019-03-17\"\n        reference = \"https://research.checkpoint.com/extracting-code-execution-from-winrar/\"\n        // May only the challenge guide you\n    ",
        "raw_strings": "strings:\n        $string1 = \"**ACE**\" ascii wide\n        $string2 = \"*UNREGISTERED VERSION*\" ascii wide\n        // $hexstring1 = C:\\C:\\\n        $hexstring1 = {?? 3A 5C ?? 3A 5C}\n        // $hexstring2 = C:\\C:C:..\n        $hexstring2 = {?? 3A 5C ?? 3A ?? 3A 2E}\n    ",
        "rule_name": "CVE_2018_20250",
        "start_line": 5,
        "stop_line": 22,
        "strings": [
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$string1",
                "type": "text",
                "value": "**ACE**"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$string2",
                "type": "text",
                "value": "*UNREGISTERED VERSION*"
            },
            {
                "name": "$hexstring1",
                "type": "byte",
                "value": "{?? 3A 5C ?? 3A 5C}"
            },
            {
                "name": "$hexstring2",
                "type": "byte",
                "value": "{?? 3A 5C ?? 3A ?? 3A 2E}"
            }
        ],
        "tags": [
            "AceArchive",
            "UNACEV2_DLL_EXP"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'CVE_2012_0158_KeyBoy', NULL, '{"file": "8307e444cad98b1b59568ad2eba5f201", "author": "Etienne Maynier <etienne@citizenlab.ca>", "description": "CVE-2012-0158 variant"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Etienne Maynier <etienne@citizenlab.ca>"
            },
            {
                "description": "CVE-2012-0158 variant"
            },
            {
                "file": "8307e444cad98b1b59568ad2eba5f201"
            }
        ],
        "raw_condition": "condition:\n      all of them\n",
        "raw_meta": "meta:\n      author = \"Etienne Maynier <etienne@citizenlab.ca>\"\n      description = \"CVE-2012-0158 variant\"\n      file = \"8307e444cad98b1b59568ad2eba5f201\"\n\n  ",
        "raw_strings": "strings:\n      $a = \"d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff09000600000000000000000000000100000001\" nocase // OLE header\n      $b = \"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\" nocase // junk data\n      $c = /5(\\{\\\\b0\\}|)[ ]*2006F00(\\{\\\\b0\\}|)[ ]*6F007(\\{\\\\b0\\}|)[ ]*400200045(\\{\\\\b0\\}|)[ ]*006(\\{\\\\b0\\}|)[ ]*E007(\\{\\\\b0\\}|)[ ]*400720079/ nocase\n      $d = \"MSComctlLib.ListViewCtrl.2\"\n      $e = \"ac38c874503c307405347aaaebf2ac2c31ebf6e8e3\" nocase //decoding shellcode\n\n\n  ",
        "rule_name": "CVE_2012_0158_KeyBoy",
        "start_line": 7,
        "stop_line": 23,
        "strings": [
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$a",
                "type": "text",
                "value": "d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff09000600000000000000000000000100000001"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$b",
                "type": "text",
                "value": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$c",
                "type": "regex",
                "value": "/5(\\{\\\\b0\\}|)[ ]*2006F00(\\{\\\\b0\\}|)[ ]*6F007(\\{\\\\b0\\}|)[ ]*400200045(\\{\\\\b0\\}|)[ ]*006(\\{\\\\b0\\}|)[ ]*E007(\\{\\\\b0\\}|)[ ]*400720079/"
            },
            {
                "name": "$d",
                "type": "text",
                "value": "MSComctlLib.ListViewCtrl.2"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$e",
                "type": "text",
                "value": "ac38c874503c307405347aaaebf2ac2c31ebf6e8e3"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Linux_DirtyCow_Exploit', NULL, '{"date": "2016-10-21", "author": "Florian Roth", "reference": "http://dirtycow.ninja/", "description": "Detects Linux Dirty Cow Exploit - CVE-2012-0056 and CVE-2016-5195"}', '[
    {
        "condition_terms": [
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x457f",
            "and",
            "$a1",
            ")",
            "or",
            "all",
            "of",
            "(",
            "$b*",
            ")",
            "or",
            "3",
            "of",
            "(",
            "$source*",
            ")",
            "or",
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x457f",
            "and",
            "1",
            "of",
            "(",
            "$s*",
            ")",
            "and",
            "all",
            "of",
            "(",
            "$p*",
            ")",
            "and",
            "filesize",
            "<",
            "20KB",
            ")"
        ],
        "metadata": [
            {
                "description": "Detects Linux Dirty Cow Exploit - CVE-2012-0056 and CVE-2016-5195"
            },
            {
                "author": "Florian Roth"
            },
            {
                "reference": "http://dirtycow.ninja/"
            },
            {
                "date": "2016-10-21"
            }
        ],
        "raw_condition": "condition:\n      ( uint16(0) == 0x457f and $a1 ) or\n      all of ($b*) or\n      3 of ($source*) or\n      ( uint16(0) == 0x457f and 1 of ($s*) and all of ($p*) and filesize < 20KB )\n",
        "raw_meta": "meta:\n      description = \"Detects Linux Dirty Cow Exploit - CVE-2012-0056 and CVE-2016-5195\"\n      author = \"Florian Roth\"\n      reference = \"http://dirtycow.ninja/\"\n      date = \"2016-10-21\"\n   ",
        "raw_strings": "strings:\n      $a1 = { 48 89 D6 41 B9 00 00 00 00 41 89 C0 B9 02 00 00 00 BA 01 00 00 00 BF 00 00 00 00 }\n\n      $b1 = { E8 ?? FC FF FF 48 8B 45 E8 BE 00 00 00 00 48 89 C7 E8 ?? FC FF FF 48 8B 45 F0 BE 00 00 00 00 48 89 }\n      $b2 = { E8 ?? FC FF FF B8 00 00 00 00 }\n\n      $source1 = \"madvise(map,100,MADV_DONTNEED);\"\n      $source2 = \"=open(\\\"/proc/self/mem\\\",O_RDWR);\"\n      $source3 = \",map,SEEK_SET);\"\n\n      $source_printf1 = \"mmap %x\"\n      $source_printf2 = \"procselfmem %d\"\n      $source_printf3 = \"madvise %d\"\n      $source_printf4 = \"[-] failed to patch payload\"\n      $source_printf5 = \"[-] failed to win race condition...\"\n      $source_printf6 = \"[*] waiting for reverse connect shell...\"\n\n      $s1 = \"/proc/self/mem\"\n      $s2 = \"/proc/%d/mem\"\n      $s3 = \"/proc/self/map\"\n      $s4 = \"/proc/%d/map\"\n\n      $p1 = \"pthread_create\" fullword ascii\n      $p2 = \"pthread_join\" fullword ascii\n   ",
        "rule_name": "Linux_DirtyCow_Exploit",
        "start_line": 2,
        "stop_line": 37,
        "strings": [
            {
                "name": "$a1",
                "type": "byte",
                "value": "{ 48 89 D6 41 B9 00 00 00 00 41 89 C0 B9 02 00 00 00 BA 01 00 00 00 BF 00 00 00 00 }"
            },
            {
                "name": "$b1",
                "type": "byte",
                "value": "{ E8 ?? FC FF FF 48 8B 45 E8 BE 00 00 00 00 48 89 C7 E8 ?? FC FF FF 48 8B 45 F0 BE 00 00 00 00 48 89 }"
            },
            {
                "name": "$b2",
                "type": "byte",
                "value": "{ E8 ?? FC FF FF B8 00 00 00 00 }"
            },
            {
                "name": "$source1",
                "type": "text",
                "value": "madvise(map,100,MADV_DONTNEED);"
            },
            {
                "name": "$source2",
                "type": "text",
                "value": "=open(\\\"/proc/self/mem\\\",O_RDWR);"
            },
            {
                "name": "$source3",
                "type": "text",
                "value": ",map,SEEK_SET);"
            },
            {
                "name": "$source_printf1",
                "type": "text",
                "value": "mmap %x"
            },
            {
                "name": "$source_printf2",
                "type": "text",
                "value": "procselfmem %d"
            },
            {
                "name": "$source_printf3",
                "type": "text",
                "value": "madvise %d"
            },
            {
                "name": "$source_printf4",
                "type": "text",
                "value": "[-] failed to patch payload"
            },
            {
                "name": "$source_printf5",
                "type": "text",
                "value": "[-] failed to win race condition..."
            },
            {
                "name": "$source_printf6",
                "type": "text",
                "value": "[*] waiting for reverse connect shell..."
            },
            {
                "name": "$s1",
                "type": "text",
                "value": "/proc/self/mem"
            },
            {
                "name": "$s2",
                "type": "text",
                "value": "/proc/%d/mem"
            },
            {
                "name": "$s3",
                "type": "text",
                "value": "/proc/self/map"
            },
            {
                "name": "$s4",
                "type": "text",
                "value": "/proc/%d/map"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$p1",
                "type": "text",
                "value": "pthread_create"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$p2",
                "type": "text",
                "value": "pthread_join"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'crime_ole_loadswf_cve_2018_4878', NULL, '{"actor": "Purported North Korean actors", "author": "Vitali Kremez, Flashpoint", "report": "https://www.flashpoint-intel.com/blog/targeted-attacks-south-korean-entities/", "version": "1.1", "reference": "hxxps://www[.]krcert[.]or[.kr/data/secNoticeView.do?bulletin_writing_sequence=26998", "vuln_type": "Remote Code Execution", "description": "Detects CVE-2018-4878", "mitigation0": "Implement Protected View for Office documents", "mitigation1": "Disable Adobe Flash", "vuln_impact": "Use-after-free", "weaponization": "Embedded in Microsoft Office first payloads", "affected_versions": "Adobe Flash 28.0.0.137 and earlier versions"}', '[
    {
        "comments": [
            "// EMBEDDED FLASH OBJECT BIN HEADER"
        ],
        "condition_terms": [
            "all",
            "of",
            "(",
            "$header*",
            ")",
            "and",
            "all",
            "of",
            "(",
            "$title*",
            ")",
            "and",
            "3",
            "of",
            "(",
            "$s*",
            ")",
            "or",
            "all",
            "of",
            "(",
            "$pdb*",
            ")",
            "and",
            "all",
            "of",
            "(",
            "$header*",
            ")",
            "and",
            "1",
            "of",
            "(",
            "$s*",
            ")"
        ],
        "metadata": [
            {
                "description": "Detects CVE-2018-4878"
            },
            {
                "vuln_type": "Remote Code Execution"
            },
            {
                "vuln_impact": "Use-after-free"
            },
            {
                "affected_versions": "Adobe Flash 28.0.0.137 and earlier versions"
            },
            {
                "mitigation0": "Implement Protected View for Office documents"
            },
            {
                "mitigation1": "Disable Adobe Flash"
            },
            {
                "weaponization": "Embedded in Microsoft Office first payloads"
            },
            {
                "actor": "Purported North Korean actors"
            },
            {
                "reference": "hxxps://www[.]krcert[.]or[.kr/data/secNoticeView.do?bulletin_writing_sequence=26998"
            },
            {
                "report": "https://www.flashpoint-intel.com/blog/targeted-attacks-south-korean-entities/"
            },
            {
                "author": "Vitali Kremez, Flashpoint"
            },
            {
                "version": "1.1"
            }
        ],
        "raw_condition": "condition:\nall of ($header*) and all of ($title*) and 3 of ($s*) or all of ($pdb*) and all of ($header*) and 1 of ($s*)\n",
        "raw_meta": "meta:\ndescription = \"Detects CVE-2018-4878\"\nvuln_type = \"Remote Code Execution\"\nvuln_impact = \"Use-after-free\"\naffected_versions = \"Adobe Flash 28.0.0.137 and earlier versions\"\nmitigation0 = \"Implement Protected View for Office documents\"\nmitigation1 = \"Disable Adobe Flash\"\nweaponization = \"Embedded in Microsoft Office first payloads\"\nactor = \"Purported North Korean actors\"\nreference = \"hxxps://www[.]krcert[.]or[.kr/data/secNoticeView.do?bulletin_writing_sequence=26998\"\nreport = \"https://www.flashpoint-intel.com/blog/targeted-attacks-south-korean-entities/\"\nauthor = \"Vitali Kremez, Flashpoint\"\nversion = \"1.1\"\n\n",
        "raw_strings": "strings:\n// EMBEDDED FLASH OBJECT BIN HEADER\n$header = \"rdf:RDF\" wide ascii\n\n// OBJECT APPLICATION TYPE TITLE\n$title = \"Adobe Flex\" wide ascii\n\n// PDB PATH \n$pdb = \"F:\\\\work\\\\flash\\\\obfuscation\\\\loadswf\\\\src\" wide ascii\n\n// LOADER STRINGS\n$s0 = \"URLRequest\" wide ascii\n$s1 = \"URLLoader\" wide ascii\n$s2 = \"loadswf\" wide ascii\n$s3 = \"myUrlReqest\" wide ascii\n\n",
        "rule_name": "crime_ole_loadswf_cve_2018_4878",
        "start_line": 1,
        "stop_line": 35,
        "strings": [
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$header",
                "type": "text",
                "value": "rdf:RDF"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$title",
                "type": "text",
                "value": "Adobe Flex"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$pdb",
                "type": "text",
                "value": "F:\\\\work\\\\flash\\\\obfuscation\\\\loadswf\\\\src"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s0",
                "type": "text",
                "value": "URLRequest"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "URLLoader"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s2",
                "type": "text",
                "value": "loadswf"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s3",
                "type": "text",
                "value": "myUrlReqest"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'CVE_2015_1701_Taihou', NULL, '{"date": "2015-05-13", "hash1": "90d17ebd75ce7ff4f15b2df951572653efe2ea17", "hash2": "acf181d6c2c43356e92d4ee7592700fa01e30ffb", "hash3": "b8aabe12502f7d55ae332905acee80a10e3bc399", "hash4": "d9989a46d590ebc792f14aa6fec30560dfe931b1", "hash5": "63d1d33e7418daf200dc4660fc9a59492ddd50d9", "score": 70, "author": "Florian Roth", "reference": "http://goo.gl/W4nU0q", "description": "CVE-2015-1701 compiled exploit code"}', '[
    {
        "condition_terms": [
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "filesize",
            "<",
            "160KB",
            "and",
            "all",
            "of",
            "(",
            "$s*",
            ")",
            "and",
            "1",
            "of",
            "(",
            "$w*",
            ")"
        ],
        "metadata": [
            {
                "description": "CVE-2015-1701 compiled exploit code"
            },
            {
                "author": "Florian Roth"
            },
            {
                "reference": "http://goo.gl/W4nU0q"
            },
            {
                "date": "2015-05-13"
            },
            {
                "hash1": "90d17ebd75ce7ff4f15b2df951572653efe2ea17"
            },
            {
                "hash2": "acf181d6c2c43356e92d4ee7592700fa01e30ffb"
            },
            {
                "hash3": "b8aabe12502f7d55ae332905acee80a10e3bc399"
            },
            {
                "hash4": "d9989a46d590ebc792f14aa6fec30560dfe931b1"
            },
            {
                "hash5": "63d1d33e7418daf200dc4660fc9a59492ddd50d9"
            },
            {
                "score": 70
            }
        ],
        "raw_condition": "condition:\n\t\tuint16(0) == 0x5a4d and filesize < 160KB and all of ($s*) and 1 of ($w*)\n",
        "raw_meta": "meta:\n\t\tdescription = \"CVE-2015-1701 compiled exploit code\"\n\t\tauthor = \"Florian Roth\"\n\t\treference = \"http://goo.gl/W4nU0q\"\n\t\tdate = \"2015-05-13\"\n\t\thash1 = \"90d17ebd75ce7ff4f15b2df951572653efe2ea17\"\n\t\thash2 = \"acf181d6c2c43356e92d4ee7592700fa01e30ffb\"\n\t\thash3 = \"b8aabe12502f7d55ae332905acee80a10e3bc399\"\n\t\thash4 = \"d9989a46d590ebc792f14aa6fec30560dfe931b1\"\n\t\thash5 = \"63d1d33e7418daf200dc4660fc9a59492ddd50d9\"\n\t\tscore = 70\n\t",
        "raw_strings": "strings:\t\n\t\t$s3 = \"VirtualProtect\" fullword\n\t\t$s4 = \"RegisterClass\"\n\t\t$s5 = \"LoadIcon\"\n\t\t$s6 = \"PsLookupProcessByProcessId\" fullword ascii \n\t\t$s7 = \"LoadLibraryExA\" fullword ascii\n\t\t$s8 = \"gSharedInfo\" fullword\n\n\t\t$w1 = \"user32.dll\" wide\n\t\t$w2 = \"ntdll\" wide\t\n\t",
        "rule_name": "CVE_2015_1701_Taihou",
        "start_line": 6,
        "stop_line": 30,
        "strings": [
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$s3",
                "type": "text",
                "value": "VirtualProtect"
            },
            {
                "name": "$s4",
                "type": "text",
                "value": "RegisterClass"
            },
            {
                "name": "$s5",
                "type": "text",
                "value": "LoadIcon"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s6",
                "type": "text",
                "value": "PsLookupProcessByProcessId"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s7",
                "type": "text",
                "value": "LoadLibraryExA"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$s8",
                "type": "text",
                "value": "gSharedInfo"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$w1",
                "type": "text",
                "value": "user32.dll"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$w2",
                "type": "text",
                "value": "ntdll"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'JavaDeploymentToolkit', NULL, '{"ref": "CVE-2010-0887", "author": "@d3t0n4t0r", "impact": 7}', '[
    {
        "condition_terms": [
            "3",
            "of",
            "them"
        ],
        "metadata": [
            {
                "ref": "CVE-2010-0887"
            },
            {
                "impact": 7
            },
            {
                "author": "@d3t0n4t0r"
            }
        ],
        "raw_condition": "condition:\n      3 of them\n",
        "raw_meta": "meta:\n      ref = \"CVE-2010-0887\"\n      impact = 7\n      author = \"@d3t0n4t0r\"\n   ",
        "raw_strings": "strings:\n      $cve20100887_1 = \"CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA\" nocase fullword\n      $cve20100887_2 = \"document.createElement(\\\"OBJECT\\\")\" nocase fullword\n      $cve20100887_3 = \"application/npruntime-scriptable-plugin;deploymenttoolkit\" nocase fullword\n      $cve20100887_4 = \"application/java-deployment-toolkit\" nocase fullword\n      $cve20100887_5 = \"document.body.appendChild(\" nocase fullword\n      $cve20100887_6 = \"launch(\"\n      $cve20100887_7 = \"-J-jar -J\" nocase fullword\n   ",
        "rule_name": "JavaDeploymentToolkit",
        "start_line": 5,
        "stop_line": 21,
        "strings": [
            {
                "modifiers": [
                    "nocase",
                    "fullword"
                ],
                "name": "$cve20100887_1",
                "type": "text",
                "value": "CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA"
            },
            {
                "modifiers": [
                    "nocase",
                    "fullword"
                ],
                "name": "$cve20100887_2",
                "type": "text",
                "value": "document.createElement(\\\"OBJECT\\\")"
            },
            {
                "modifiers": [
                    "nocase",
                    "fullword"
                ],
                "name": "$cve20100887_3",
                "type": "text",
                "value": "application/npruntime-scriptable-plugin;deploymenttoolkit"
            },
            {
                "modifiers": [
                    "nocase",
                    "fullword"
                ],
                "name": "$cve20100887_4",
                "type": "text",
                "value": "application/java-deployment-toolkit"
            },
            {
                "modifiers": [
                    "nocase",
                    "fullword"
                ],
                "name": "$cve20100887_5",
                "type": "text",
                "value": "document.body.appendChild("
            },
            {
                "name": "$cve20100887_6",
                "type": "text",
                "value": "launch("
            },
            {
                "modifiers": [
                    "nocase",
                    "fullword"
                ],
                "name": "$cve20100887_7",
                "type": "text",
                "value": "-J-jar -J"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'FlashNewfunction', '{decodedPDF}', '{"ref": "http://blog.xanda.org/tag/jsunpack/", "hide": true, "impact": 5}', '[
    {
        "condition_terms": [
            "(",
            "$unescape",
            "and",
            "$shellcode",
            "and",
            "$cve20101297",
            ")",
            "or",
            "(",
            "$shellcode5",
            "and",
            "$cve20101297",
            ")"
        ],
        "metadata": [
            {
                "ref": "CVE-2010-1297"
            },
            {
                "hide": true
            },
            {
                "impact": 5
            },
            {
                "ref": "http://blog.xanda.org/tag/jsunpack/"
            }
        ],
        "raw_condition": "condition:\n      ($unescape and $shellcode and $cve20101297) or ($shellcode5 and $cve20101297)\n",
        "raw_meta": "meta:  \n      ref = \"CVE-2010-1297\"\n      hide = true\n      impact = 5 \n      ref = \"http://blog.xanda.org/tag/jsunpack/\"\n   ",
        "raw_strings": "strings:\n      $unescape = \"unescape\" fullword nocase\n      $shellcode = /%u[A-Fa-f0-9]{4}/\n      $shellcode5 = /(%u[A-Fa-f0-9]{4}){5}/\n      $cve20101297 = /\\/Subtype ?\\/Flash/\n   ",
        "rule_name": "FlashNewfunction",
        "start_line": 1,
        "stop_line": 15,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "nocase"
                ],
                "name": "$unescape",
                "type": "text",
                "value": "unescape"
            },
            {
                "name": "$shellcode",
                "type": "regex",
                "value": "/%u[A-Fa-f0-9]{4}/"
            },
            {
                "name": "$shellcode5",
                "type": "regex",
                "value": "/(%u[A-Fa-f0-9]{4}){5}/"
            },
            {
                "name": "$cve20101297",
                "type": "regex",
                "value": "/\\/Subtype ?\\/Flash/"
            }
        ],
        "tags": [
            "decodedPDF"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'cve_2013_0074', NULL, '{"date": "2015-07-23", "author": "Kaspersky Lab", "version": "1.0", "filetype": "Win32 EXE"}', '[
    {
        "condition_terms": [
            "(",
            "(",
            "2",
            "of",
            "(",
            "$b*",
            ")",
            ")",
            ")"
        ],
        "metadata": [
            {
                "author": "Kaspersky Lab"
            },
            {
                "filetype": "Win32 EXE"
            },
            {
                "date": "2015-07-23"
            },
            {
                "version": "1.0"
            }
        ],
        "raw_condition": "condition:\n\t( (2 of ($b*)) )\n",
        "raw_meta": "meta:\n\tauthor = \"Kaspersky Lab\"\n\tfiletype = \"Win32 EXE\"\n\tdate = \"2015-07-23\"\n\tversion = \"1.0\"\n\n",
        "raw_strings": "strings:\n\t$b2=\"Can''t find Payload() address\" ascii wide\n\t$b3=\"/SilverApp1;component/App.xaml\" ascii wide\n\t$b4=\"Can''t allocate ums after buf[]\" ascii wide\n\t$b5=\"------------ START ------------\"\n\n",
        "rule_name": "cve_2013_0074",
        "start_line": 1,
        "stop_line": 17,
        "strings": [
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$b2",
                "type": "text",
                "value": "Can''t find Payload() address"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$b3",
                "type": "text",
                "value": "/SilverApp1;component/App.xaml"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$b4",
                "type": "text",
                "value": "Can''t allocate ums after buf[]"
            },
            {
                "name": "$b5",
                "type": "text",
                "value": "------------ START ------------"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'rovnix_downloader', '{downloader}', '{"author": "Intel Security", "reference": "https://blogs.mcafee.com/mcafee-labs/rovnix-downloader-sinkhole-time-checks/", "description": "Rovnix downloader with sinkhole checks"}', '[
    {
        "condition_terms": [
            "$mz",
            "in",
            "(",
            "0",
            "..",
            "2",
            ")",
            "and",
            "all",
            "of",
            "(",
            "$sink*",
            ")",
            "and",
            "$boot"
        ],
        "metadata": [
            {
                "author": "Intel Security"
            },
            {
                "description": "Rovnix downloader with sinkhole checks"
            },
            {
                "reference": "https://blogs.mcafee.com/mcafee-labs/rovnix-downloader-sinkhole-time-checks/"
            }
        ],
        "raw_condition": "condition:\n\t\t$mz in (0..2) and all of ($sink*) and $boot\n",
        "raw_meta": "meta:\n\t\tauthor=\"Intel Security\"\n\t\tdescription=\"Rovnix downloader with sinkhole checks\"\n\t\treference = \"https://blogs.mcafee.com/mcafee-labs/rovnix-downloader-sinkhole-time-checks/\"\n\t",
        "raw_strings": "strings:\n\t\t\t$sink1= \"control\"\n\t\t\t$sink2 = \"sink\"\n\t\t\t$sink3 = \"hole\"\n\t\t\t$sink4= \"dynadot\"\n\t\t\t$sink5= \"block\"\n\t\t\t$sink6= \"malw\"\n\t\t\t$sink7= \"anti\"\n\t\t\t$sink8= \"googl\"\n\t\t\t$sink9= \"hack\"\n\t\t\t$sink10= \"trojan\"\n\t\t\t$sink11= \"abuse\"\n\t\t\t$sink12= \"virus\"\n\t\t\t$sink13= \"black\"\n\t\t\t$sink14= \"spam\"\n\t\t\t$boot= \"BOOTKIT_DLL.dll\"\n\t\t\t$mz = { 4D 5A }\n\t",
        "rule_name": "rovnix_downloader",
        "start_line": 1,
        "stop_line": 26,
        "strings": [
            {
                "name": "$sink1",
                "type": "text",
                "value": "control"
            },
            {
                "name": "$sink2",
                "type": "text",
                "value": "sink"
            },
            {
                "name": "$sink3",
                "type": "text",
                "value": "hole"
            },
            {
                "name": "$sink4",
                "type": "text",
                "value": "dynadot"
            },
            {
                "name": "$sink5",
                "type": "text",
                "value": "block"
            },
            {
                "name": "$sink6",
                "type": "text",
                "value": "malw"
            },
            {
                "name": "$sink7",
                "type": "text",
                "value": "anti"
            },
            {
                "name": "$sink8",
                "type": "text",
                "value": "googl"
            },
            {
                "name": "$sink9",
                "type": "text",
                "value": "hack"
            },
            {
                "name": "$sink10",
                "type": "text",
                "value": "trojan"
            },
            {
                "name": "$sink11",
                "type": "text",
                "value": "abuse"
            },
            {
                "name": "$sink12",
                "type": "text",
                "value": "virus"
            },
            {
                "name": "$sink13",
                "type": "text",
                "value": "black"
            },
            {
                "name": "$sink14",
                "type": "text",
                "value": "spam"
            },
            {
                "name": "$boot",
                "type": "text",
                "value": "BOOTKIT_DLL.dll"
            },
            {
                "name": "$mz",
                "type": "byte",
                "value": "{ 4D 5A }"
            }
        ],
        "tags": [
            "downloader"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Cerberus', '{RAT,memory}', '{"date": "2013-01-12", "author": "Jean-Philippe Teissier / @Jipe_", "version": "1.0", "filetype": "memory", "description": "Cerberus"}', '[
    {
        "condition_terms": [
            "any",
            "of",
            "them"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "description": "Cerberus"
            },
            {
                "author": "Jean-Philippe Teissier / @Jipe_"
            },
            {
                "date": "2013-01-12"
            },
            {
                "filetype": "memory"
            },
            {
                "version": "1.0"
            }
        ],
        "raw_condition": "condition:\n\t\tany of them\n",
        "raw_meta": "meta:\n\t\tdescription = \"Cerberus\"\n\t\tauthor = \"Jean-Philippe Teissier / @Jipe_\"\n\t\tdate = \"2013-01-12\"\n\t\tfiletype = \"memory\"\n\t\tversion = \"1.0\" \n\n\t",
        "raw_strings": "strings:\n\t\t$checkin = \"Ypmw1Syv023QZD\"\n\t\t$clientpong = \"wZ2pla\"\n\t\t$serverping = \"wBmpf3Pb7RJe\"\n\t\t$generic = \"cerberus\" nocase\n\n\t",
        "rule_name": "Cerberus",
        "start_line": 8,
        "stop_line": 25,
        "strings": [
            {
                "name": "$checkin",
                "type": "text",
                "value": "Ypmw1Syv023QZD"
            },
            {
                "name": "$clientpong",
                "type": "text",
                "value": "wZ2pla"
            },
            {
                "name": "$serverping",
                "type": "text",
                "value": "wBmpf3Pb7RJe"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$generic",
                "type": "text",
                "value": "cerberus"
            }
        ],
        "tags": [
            "RAT",
            "memory"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'LinuxBew', '{MALW}', '{"MD5": "27d857e12b9be5d43f935b8cc86eaabf", "date": "2017-07-10", "SHA256": "80c4d1a1ef433ac44c4fe72e6ca42395261fbca36eff243b07438263a1b1cf06", "author": "Joan Soriano / @w0lfvan", "version": "1.0", "description": "Linux.Bew Backdoor"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Linux.Bew Backdoor"
            },
            {
                "author": "Joan Soriano / @w0lfvan"
            },
            {
                "date": "2017-07-10"
            },
            {
                "version": "1.0"
            },
            {
                "MD5": "27d857e12b9be5d43f935b8cc86eaabf"
            },
            {
                "SHA256": "80c4d1a1ef433ac44c4fe72e6ca42395261fbca36eff243b07438263a1b1cf06"
            }
        ],
        "raw_condition": "condition:\n\t\tall of them\n",
        "raw_meta": "meta:\n\t\tdescription = \"Linux.Bew Backdoor\"\n\t\tauthor = \"Joan Soriano / @w0lfvan\"\n\t\tdate = \"2017-07-10\"\n\t\tversion = \"1.0\"\n\t\tMD5 = \"27d857e12b9be5d43f935b8cc86eaabf\"\n\t\tSHA256 = \"80c4d1a1ef433ac44c4fe72e6ca42395261fbca36eff243b07438263a1b1cf06\"\n\t",
        "raw_strings": "strings:\n\t\t$a = \"src/secp256k1.c\"\n\t\t$b = \"hfir.u230.org\"\n\t\t$c = \"tempfile-x11session\"\n\t",
        "rule_name": "LinuxBew",
        "start_line": 1,
        "stop_line": 16,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "src/secp256k1.c"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "hfir.u230.org"
            },
            {
                "name": "$c",
                "type": "text",
                "value": "tempfile-x11session"
            }
        ],
        "tags": [
            "MALW"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'PittyTiger', NULL, '{"author": " (@chort0)", "description": "Detect PittyTiger Trojan via common strings"}', '[
    {
        "condition_terms": [
            "(",
            "any",
            "of",
            "(",
            "$pt*",
            ")",
            ")",
            "and",
            "(",
            "any",
            "of",
            "(",
            "$trj*",
            ")",
            ")",
            "and",
            "(",
            "any",
            "of",
            "(",
            "$odd*",
            ")",
            ")"
        ],
        "metadata": [
            {
                "author": " (@chort0)"
            },
            {
                "description": "Detect PittyTiger Trojan via common strings"
            }
        ],
        "raw_condition": "condition: \n  (any of ($pt*)) and (any of ($trj*)) and (any of ($odd*)) \n  ",
        "raw_meta": "meta: \n    author = \" (@chort0)\"\n    description = \"Detect PittyTiger Trojan via common strings\"\n    ",
        "raw_strings": "strings: \n      $ptUserAgent = \"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.; SV1)\" // missing minor digit\n      $ptFC001 = \"FC001\" fullword \n      $ptPittyTiger = \"PittyTiger\" fullword \n      $trjHTMLerr = \"trj:HTML Err.\" nocase fullword \n      $trjworkFunc = \"trj:workFunc start.\" nocase fullword \n      $trjcmdtout = \"trj:cmd time out.\" nocase fullword \n      $trjThrtout = \"trj:Thread time out.\" nocase fullword\n      $trjCrPTdone = \"trj:Create PT done.\" nocase fullword\n      $trjCrPTerr = \"trj:Create PT error: mutex already exists.\" nocase fullword \n      $oddPippeFailed = \"Create Pippe Failed!\" fullword // extra ''p''\n      $oddXferingFile = \"Transfering File\" fullword // missing ''r'' \n      $oddParasError = \"put Paras Error:\" fullword // abbreviated ''parameters''? \n      $oddCmdTOutkilled = \"Cmd Time Out..Cmd has been killed.\" fullword \n",
        "rule_name": "PittyTiger",
        "start_line": 1,
        "stop_line": 21,
        "strings": [
            {
                "name": "$ptUserAgent",
                "type": "text",
                "value": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.; SV1)"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$ptFC001",
                "type": "text",
                "value": "FC001"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$ptPittyTiger",
                "type": "text",
                "value": "PittyTiger"
            },
            {
                "modifiers": [
                    "nocase",
                    "fullword"
                ],
                "name": "$trjHTMLerr",
                "type": "text",
                "value": "trj:HTML Err."
            },
            {
                "modifiers": [
                    "nocase",
                    "fullword"
                ],
                "name": "$trjworkFunc",
                "type": "text",
                "value": "trj:workFunc start."
            },
            {
                "modifiers": [
                    "nocase",
                    "fullword"
                ],
                "name": "$trjcmdtout",
                "type": "text",
                "value": "trj:cmd time out."
            },
            {
                "modifiers": [
                    "nocase",
                    "fullword"
                ],
                "name": "$trjThrtout",
                "type": "text",
                "value": "trj:Thread time out."
            },
            {
                "modifiers": [
                    "nocase",
                    "fullword"
                ],
                "name": "$trjCrPTdone",
                "type": "text",
                "value": "trj:Create PT done."
            },
            {
                "modifiers": [
                    "nocase",
                    "fullword"
                ],
                "name": "$trjCrPTerr",
                "type": "text",
                "value": "trj:Create PT error: mutex already exists."
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$oddPippeFailed",
                "type": "text",
                "value": "Create Pippe Failed!"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$oddXferingFile",
                "type": "text",
                "value": "Transfering File"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$oddParasError",
                "type": "text",
                "value": "put Paras Error:"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$oddCmdTOutkilled",
                "type": "text",
                "value": "Cmd Time Out..Cmd has been killed."
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'eicar', NULL, '{"hash1": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "author": "Marc Rivero | @seifreed", "description": "Rule to detect Eicar pattern"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Rule to detect Eicar pattern"
            },
            {
                "author": "Marc Rivero | @seifreed"
            },
            {
                "hash1": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            }
        ],
        "raw_condition": "condition:\n\t\tall of them\n",
        "raw_meta": "meta:\n\t\tdescription = \"Rule to detect Eicar pattern\"\n\t\tauthor = \"Marc Rivero | @seifreed\"\n\t\thash1 = \"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\"\n\n\t",
        "raw_strings": "strings:\n\t\t$s1 = \"X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\" fullword ascii\n\n\t",
        "rule_name": "eicar",
        "start_line": 1,
        "stop_line": 13,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'crime_ransomware_windows_GPGQwerty', '{crime_ransomware_windows_GPGQwerty}', '{"author": "McAfee Labs", "reference": "https://securingtomorrow.mcafee.com/mcafee-labs/ransomware-takes-open-source-path-encrypts-gnu-privacy-guard/", "description": "Detect GPGQwerty ransomware"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "McAfee Labs"
            },
            {
                "description": "Detect GPGQwerty ransomware"
            },
            {
                "reference": "https://securingtomorrow.mcafee.com/mcafee-labs/ransomware-takes-open-source-path-encrypts-gnu-privacy-guard/"
            }
        ],
        "raw_condition": "condition:\n\nall of them\n\n",
        "raw_meta": "meta:\n\nauthor = \"McAfee Labs\"\n\ndescription = \"Detect GPGQwerty ransomware\"\n\nreference = \"https://securingtomorrow.mcafee.com/mcafee-labs/ransomware-takes-open-source-path-encrypts-gnu-privacy-guard/\"\n\n",
        "raw_strings": "strings:\n\n$a = \"gpg.exe \u2013recipient qwerty  -o\"\n\n$b = \"%s%s.%d.qwerty\"\n\n$c = \"del /Q /F /S %s$recycle.bin\"\n\n$d = \"cryz1@protonmail.com\"\n\n",
        "rule_name": "crime_ransomware_windows_GPGQwerty",
        "start_line": 1,
        "stop_line": 27,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "gpg.exe \u2013recipient qwerty  -o"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "%s%s.%d.qwerty"
            },
            {
                "name": "$c",
                "type": "text",
                "value": "del /Q /F /S %s$recycle.bin"
            },
            {
                "name": "$d",
                "type": "text",
                "value": "cryz1@protonmail.com"
            }
        ],
        "tags": [
            "crime_ransomware_windows_GPGQwerty"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'KelihosHlux', NULL, '{"date": "22/02/2014", "author": "@malpush", "maltype": "KelihosHlux", "description": "http://malwared.ru"}', '[
    {
        "condition_terms": [
            "$KelihosHlux_HexString"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "@malpush"
            },
            {
                "maltype": "KelihosHlux"
            },
            {
                "description": "http://malwared.ru"
            },
            {
                "date": "22/02/2014"
            }
        ],
        "raw_condition": "condition:\n    $KelihosHlux_HexString\n",
        "raw_meta": "meta:\n\tauthor = \"@malpush\"\n\tmaltype = \"KelihosHlux\"\n\tdescription = \"http://malwared.ru\"\n\tdate = \"22/02/2014\"\n  ",
        "raw_strings": "strings:\n    $KelihosHlux_HexString = { 73 20 7D 8B FE 95 E4 12 4F 3F 99 3F 6E C8 28 26 C2 41 D9 8F C1 6A 72 A6 CE 36 0F 73 DD 2A 72 B0 CC D1 07 8B 2B 98 73 0E 7E 8C 07 DC 6C 71 63 F4 23 27 DD 17 56 AE AB 1E 30 52 E7 54 51 F7 20 ED C7 2D 4B 72 E0 77 8E B4 D2 A8 0D 8D 6A 64 F9 B7 7B 08 70 8D EF F3 9A 77 F6 0D 88 3A 8F BB C8 89 F5 F8 39 36 BA 0E CB 38 40 BF 39 73 F4 01 DC C1 17 BF C1 76 F6 84 8F BD 87 76 BC 7F 85 41 81 BD C6 3F BC 39 BD C0 89 47 3E 92 BD 80 60 9D 89 15 6A C6 B9 89 37 C4 FF 00 3D 45 38 09 CD 29 00 90 BB B6 38 FD 28 9C 01 39 0E F9 30 A9 66 6B 19 C9 F8 4C 3E B1 C7 CB 1B C9 3A 87 3E 8E 74 E7 71 D1 }\n   \n  ",
        "rule_name": "KelihosHlux",
        "start_line": 8,
        "stop_line": 20,
        "strings": [
            {
                "name": "$KelihosHlux_HexString",
                "type": "byte",
                "value": "{ 73 20 7D 8B FE 95 E4 12 4F 3F 99 3F 6E C8 28 26 C2 41 D9 8F C1 6A 72 A6 CE 36 0F 73 DD 2A 72 B0 CC D1 07 8B 2B 98 73 0E 7E 8C 07 DC 6C 71 63 F4 23 27 DD 17 56 AE AB 1E 30 52 E7 54 51 F7 20 ED C7 2D 4B 72 E0 77 8E B4 D2 A8 0D 8D 6A 64 F9 B7 7B 08 70 8D EF F3 9A 77 F6 0D 88 3A 8F BB C8 89 F5 F8 39 36 BA 0E CB 38 40 BF 39 73 F4 01 DC C1 17 BF C1 76 F6 84 8F BD 87 76 BC 7F 85 41 81 BD C6 3F BC 39 BD C0 89 47 3E 92 BD 80 60 9D 89 15 6A C6 B9 89 37 C4 FF 00 3D 45 38 09 CD 29 00 90 BB B6 38 FD 28 9C 01 39 0E F9 30 A9 66 6B 19 C9 F8 4C 3E B1 C7 CB 1B C9 3A 87 3E 8E 74 E7 71 D1 }"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'jeff_dev_ransomware', NULL, '{"author": "Marc Rivero | @seifreed", "reference": "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/", "description": "Rule to detect Jeff DEV Ransomware"}', '[
    {
        "condition_terms": [
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "filesize",
            "<",
            "5000KB",
            ")",
            "and",
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Rule to detect Jeff DEV Ransomware"
            },
            {
                "author": "Marc Rivero | @seifreed"
            },
            {
                "reference": "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/"
            }
        ],
        "raw_condition": "condition:\n\n      ( uint16(0) == 0x5a4d and filesize < 5000KB ) and all of them\n",
        "raw_meta": "meta:\n   \n      description = \"Rule to detect Jeff DEV Ransomware\"\n      author = \"Marc Rivero | @seifreed\"\n      reference = \"https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/\"\n      \n   ",
        "raw_strings": "strings:\n\n      $s1 = \"C:\\\\Users\\\\Umut\\\\Desktop\\\\takemeon\" fullword wide\n      $s2 = \"C:\\\\Users\\\\Umut\\\\Desktop\\\\\" fullword ascii\n      $s3 = \"PRESS HERE TO STOP THIS CREEPY SOUND AND VIEW WHAT HAPPENED TO YOUR COMPUTER\" fullword wide\n      $s4 = \"WHAT YOU DO TO MY COMPUTER??!??!!!\" fullword wide\n\n   ",
        "rule_name": "jeff_dev_ransomware",
        "start_line": 1,
        "stop_line": 19,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s1",
                "type": "text",
                "value": "C:\\\\Users\\\\Umut\\\\Desktop\\\\takemeon"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s2",
                "type": "text",
                "value": "C:\\\\Users\\\\Umut\\\\Desktop\\\\"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s3",
                "type": "text",
                "value": "PRESS HERE TO STOP THIS CREEPY SOUND AND VIEW WHAT HAPPENED TO YOUR COMPUTER"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s4",
                "type": "text",
                "value": "WHAT YOU DO TO MY COMPUTER??!??!!!"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'leverage_a', NULL, '{"date": "2013/09", "author": "earada@alienvault.com", "version": "1.0", "description": "OSX/Leverage.A"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "earada@alienvault.com"
            },
            {
                "version": "1.0"
            },
            {
                "description": "OSX/Leverage.A"
            },
            {
                "date": "2013/09"
            }
        ],
        "raw_condition": "condition:\n\t\tall of them\n",
        "raw_meta": "meta:\n\t\tauthor = \"earada@alienvault.com\"\n\t\tversion = \"1.0\"\n\t\tdescription = \"OSX/Leverage.A\"\n\t\tdate = \"2013/09\"\n\t",
        "raw_strings": "strings:\n\t\t$a1 = \"ioreg -l | grep \\\"IOPlatformSerialNumber\\\" | awk -F\"\n\t\t$a2 = \"+:Users:Shared:UserEvent.app:Contents:MacOS:\"\n\t\t$a3 = \"rm ''/Users/Shared/UserEvent.app/Contents/Resources/UserEvent.icns''\"\n\t\t$script1 = \"osascript -e ''tell application \\\"System Events\\\" to get the hidden of every login item''\"\n\t\t$script2 = \"osascript -e ''tell application \\\"System Events\\\" to get the name of every login item''\"\n\t\t$script3 = \"osascript -e ''tell application \\\"System Events\\\" to get the path of every login item''\"\n\t\t$properties = \"serverVisible \\x00\"\n\t",
        "rule_name": "leverage_a",
        "start_line": 8,
        "stop_line": 25,
        "strings": [
            {
                "name": "$a1",
                "type": "text",
                "value": "ioreg -l | grep \\\"IOPlatformSerialNumber\\\" | awk -F"
            },
            {
                "name": "$a2",
                "type": "text",
                "value": "+:Users:Shared:UserEvent.app:Contents:MacOS:"
            },
            {
                "name": "$a3",
                "type": "text",
                "value": "rm ''/Users/Shared/UserEvent.app/Contents/Resources/UserEvent.icns''"
            },
            {
                "name": "$script1",
                "type": "text",
                "value": "osascript -e ''tell application \\\"System Events\\\" to get the hidden of every login item''"
            },
            {
                "name": "$script2",
                "type": "text",
                "value": "osascript -e ''tell application \\\"System Events\\\" to get the name of every login item''"
            },
            {
                "name": "$script3",
                "type": "text",
                "value": "osascript -e ''tell application \\\"System Events\\\" to get the path of every login item''"
            },
            {
                "name": "$properties",
                "type": "text",
                "value": "serverVisible \\x00"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Kwampirs', NULL, '{"family": "Kwampirs", "copyright": "Symantec", "reference": "https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia", "description": "Kwampirs dropper and main payload components"}', '[
    {
        "condition_terms": [
            "2",
            "of",
            "them"
        ],
        "metadata": [
            {
                "copyright": "Symantec"
            },
            {
                "reference": "https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia"
            },
            {
                "family": "Kwampirs"
            },
            {
                "description": "Kwampirs dropper and main payload components"
            }
        ],
        "raw_condition": "condition:\n 2 of them\n",
        "raw_meta": "meta:\n copyright = \"Symantec\"\n reference = \"https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia\"\n family = \"Kwampirs\"\n description = \"Kwampirs dropper and main payload components\"\n ",
        "raw_strings": "strings:\n$pubkey =\n {\n 06 02 00 00 00 A4 00 00 52 53 41 31 00 08 00 00\n 01 00 01 00 CD 74 15 BC 47 7E 0A 5E E4 35 22 A5\n 97 0C 65 BE E0 33 22 F2 94 9D F5 40 97 3C 53 F9\n E4 7E DD 67 CF 5F 0A 5E F4 AD C9 CF 27 D3 E6 31\n 48 B8 00 32 1D BE 87 10 89 DA 8B 2F 21 B4 5D 0A\n CD 43 D7 B4 75 C9 19 FE CC 88 4A 7B E9 1D 8C 11\n 56 A6 A7 21 D8 C6 82 94 C1 66 11 08 E6 99 2C 33\n 02 E2 3A 50 EA 58 D2 A7 36 EE 5A D6 8F 5D 5D D2\n 9E 04 24 4A CE 4C B6 91 C0 7A C9 5C E7 5F 51 28\n 4C 72 E1 60 AB 76 73 30 66 18 BE EC F3 99 5E 4B\n 4F 59 F5 56 AD 65 75 2B 8F 14 0C 0D 27 97 12 71\n 6B 49 08 84 61 1D 03 BA A5 42 92 F9 13 33 57 D9\n 59 B3 E4 05 F9 12 23 08 B3 50 9A DA 6E 79 02 36\n EE CE 6D F3 7F 8B C9 BE 6A 7E BE 8F 85 B8 AA 82\n C6 1E 14 C6 1A 28 29 59 C2 22 71 44 52 05 E5 E6\n FE 58 80 6E D4 95 2D 57 CB 99 34 61 E9 E9 B3 3D\n 90 DC 6C 26 5D 70 B4 78 F9 5E C9 7D 59 10 61 DF\n F7 E4 0C B3\n }\n \n $network_xor_key =\n {\n B7 E9 F9 2D F8 3E 18 57 B9 18 2B 1F 5F D9 A5 38\n C8 E7 67 E9 C6 62 9C 50 4E 8D 00 A6 59 F8 72 E0\n 91 42 FF 18 A6 D1 81 F2 2B C8 29 EB B9 87 6F 58\n C2 C9 8E 75 3F 71 ED 07 D0 AC CE 28 A1 E7 B5 68\n CD CF F1 D8 2B 26 5C 31 1E BC 52 7C 23 6C 3E 6B\n 8A 24 61 0A 17 6C E2 BB 1D 11 3B 79 E0 29 75 02\n D9 25 31 5F 95 E7 28 28 26 2B 31 EC 4D B3 49 D9\n 62 F0 3E D4 89 E4 CC F8 02 41 CC 25 15 6E 63 1B\n 10 3B 60 32 1C 0D 5B FA 52 DA 39 DF D1 42 1E 3E\n BD BC 17 A5 96 D9 43 73 3C 09 7F D2 C6 D4 29 83\n 3E 44 44 6C 97 85 9E 7B F0 EE 32 C3 11 41 A3 6B\n A9 27 F4 A3 FB 2B 27 2B B6 A6 AF 6B 39 63 2D 91\n 75 AE 83 2E 1E F8 5F B5 65 ED B3 40 EA 2A 36 2C\n A6 CF 8E 4A 4A 3E 10 6C 9D 28 49 66 35 83 30 E7\n 45 0E 05 ED 69 8D CF C5 40 50 B1 AA 13 74 33 0F\n DF 41 82 3B 1A 79 DC 3B 9D C3 BD EA B1 3E 04 33\n }\n\n$decrypt_string =\n {\n 85 DB 75 09 85 F6 74 05 89 1E B0 01 C3 85 FF 74\n 4F F6 C3 01 75 4A 85 F6 74 46 8B C3 D1 E8 33 C9\n 40 BA 02 00 00 00 F7 E2 0F 90 C1 F7 D9 0B C8 51\n E8 12 28 00 00 89 06 8B C8 83 C4 04 33 C0 85 DB\n 74 16 8B D0 83 E2 0F 8A 92 1C 33 02 10 32 14 38\n 40 88 11 41 3B C3 72 EA 66 C7 01 00 00 B0 01 C3\n 32 C0 C3\n }\n\n $init_strings =\n {\n 55 8B EC 83 EC 10 33 C9 B8 0D 00 00 00 BA 02 00\n 00 00 F7 E2 0F 90 C1 53 56 57 F7 D9 0B C8 51 E8\n B3 27 00 00 BF 05 00 00 00 8D 77 FE BB 4A 35 02\n 10 2B DE 89 5D F4 BA 48 35 02 10 4A BB 4C 35 02\n 10 83 C4 04 2B DF A3 C8 FC 03 10 C7 45 FC 00 00\n 00 00 8D 4F FC 89 55 F8 89 5D F0 EB 06\n }\n\n ",
        "rule_name": "Kwampirs",
        "start_line": 1,
        "stop_line": 74,
        "strings": [
            {
                "name": "$pubkey",
                "type": "byte",
                "value": "{\n 06 02 00 00 00 A4 00 00 52 53 41 31 00 08 00 00\n 01 00 01 00 CD 74 15 BC 47 7E 0A 5E E4 35 22 A5\n 97 0C 65 BE E0 33 22 F2 94 9D F5 40 97 3C 53 F9\n E4 7E DD 67 CF 5F 0A 5E F4 AD C9 CF 27 D3 E6 31\n 48 B8 00 32 1D BE 87 10 89 DA 8B 2F 21 B4 5D 0A\n CD 43 D7 B4 75 C9 19 FE CC 88 4A 7B E9 1D 8C 11\n 56 A6 A7 21 D8 C6 82 94 C1 66 11 08 E6 99 2C 33\n 02 E2 3A 50 EA 58 D2 A7 36 EE 5A D6 8F 5D 5D D2\n 9E 04 24 4A CE 4C B6 91 C0 7A C9 5C E7 5F 51 28\n 4C 72 E1 60 AB 76 73 30 66 18 BE EC F3 99 5E 4B\n 4F 59 F5 56 AD 65 75 2B 8F 14 0C 0D 27 97 12 71\n 6B 49 08 84 61 1D 03 BA A5 42 92 F9 13 33 57 D9\n 59 B3 E4 05 F9 12 23 08 B3 50 9A DA 6E 79 02 36\n EE CE 6D F3 7F 8B C9 BE 6A 7E BE 8F 85 B8 AA 82\n C6 1E 14 C6 1A 28 29 59 C2 22 71 44 52 05 E5 E6\n FE 58 80 6E D4 95 2D 57 CB 99 34 61 E9 E9 B3 3D\n 90 DC 6C 26 5D 70 B4 78 F9 5E C9 7D 59 10 61 DF\n F7 E4 0C B3\n }"
            },
            {
                "name": "$network_xor_key",
                "type": "byte",
                "value": "{\n B7 E9 F9 2D F8 3E 18 57 B9 18 2B 1F 5F D9 A5 38\n C8 E7 67 E9 C6 62 9C 50 4E 8D 00 A6 59 F8 72 E0\n 91 42 FF 18 A6 D1 81 F2 2B C8 29 EB B9 87 6F 58\n C2 C9 8E 75 3F 71 ED 07 D0 AC CE 28 A1 E7 B5 68\n CD CF F1 D8 2B 26 5C 31 1E BC 52 7C 23 6C 3E 6B\n 8A 24 61 0A 17 6C E2 BB 1D 11 3B 79 E0 29 75 02\n D9 25 31 5F 95 E7 28 28 26 2B 31 EC 4D B3 49 D9\n 62 F0 3E D4 89 E4 CC F8 02 41 CC 25 15 6E 63 1B\n 10 3B 60 32 1C 0D 5B FA 52 DA 39 DF D1 42 1E 3E\n BD BC 17 A5 96 D9 43 73 3C 09 7F D2 C6 D4 29 83\n 3E 44 44 6C 97 85 9E 7B F0 EE 32 C3 11 41 A3 6B\n A9 27 F4 A3 FB 2B 27 2B B6 A6 AF 6B 39 63 2D 91\n 75 AE 83 2E 1E F8 5F B5 65 ED B3 40 EA 2A 36 2C\n A6 CF 8E 4A 4A 3E 10 6C 9D 28 49 66 35 83 30 E7\n 45 0E 05 ED 69 8D CF C5 40 50 B1 AA 13 74 33 0F\n DF 41 82 3B 1A 79 DC 3B 9D C3 BD EA B1 3E 04 33\n }"
            },
            {
                "name": "$decrypt_string",
                "type": "byte",
                "value": "{\n 85 DB 75 09 85 F6 74 05 89 1E B0 01 C3 85 FF 74\n 4F F6 C3 01 75 4A 85 F6 74 46 8B C3 D1 E8 33 C9\n 40 BA 02 00 00 00 F7 E2 0F 90 C1 F7 D9 0B C8 51\n E8 12 28 00 00 89 06 8B C8 83 C4 04 33 C0 85 DB\n 74 16 8B D0 83 E2 0F 8A 92 1C 33 02 10 32 14 38\n 40 88 11 41 3B C3 72 EA 66 C7 01 00 00 B0 01 C3\n 32 C0 C3\n }"
            },
            {
                "name": "$init_strings",
                "type": "byte",
                "value": "{\n 55 8B EC 83 EC 10 33 C9 B8 0D 00 00 00 BA 02 00\n 00 00 F7 E2 0F 90 C1 53 56 57 F7 D9 0B C8 51 E8\n B3 27 00 00 BF 05 00 00 00 8D 77 FE BB 4A 35 02\n 10 2B DE 89 5D F4 BA 48 35 02 10 4A BB 4C 35 02\n 10 83 C4 04 2B DF A3 C8 FC 03 10 C7 45 FC 00 00\n 00 00 8D 4F FC 89 55 F8 89 5D F0 EB 06\n }"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Tedroo', '{Spammer}', '{"date": "22/11/2015", "author": "Kevin Falcoz", "description": "Tedroo Spammer"}', '[
    {
        "condition_terms": [
            "$signature1",
            "and",
            "$signature2"
        ],
        "metadata": [
            {
                "author": "Kevin Falcoz"
            },
            {
                "date": "22/11/2015"
            },
            {
                "description": "Tedroo Spammer"
            }
        ],
        "raw_condition": "condition:\n\t\t$signature1 and $signature2\n",
        "raw_meta": "meta:\n\t\tauthor=\"Kevin Falcoz\"\n\t\tdate=\"22/11/2015\"\n\t\tdescription=\"Tedroo Spammer\"\n\n\t",
        "raw_strings": "strings:\n\t\t$signature1={25 73 25 73 2E 65 78 65}\n\t\t$signature2={5F 6C 6F 67 2E 74 78 74}\n\n\t",
        "rule_name": "Tedroo",
        "start_line": 6,
        "stop_line": 19,
        "strings": [
            {
                "name": "$signature1",
                "type": "byte",
                "value": "{25 73 25 73 2E 65 78 65}"
            },
            {
                "name": "$signature2",
                "type": "byte",
                "value": "{5F 6C 6F 67 2E 74 78 74}"
            }
        ],
        "tags": [
            "Spammer"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Odinaff_swift', '{malware,odinaff,swift,raw}', '{"date": "2016/10/27", "author": "@j0sm1", "filetype": "binary", "reference": "https://www.symantec.com/security_response/writeup.jsp?docid=2016-083006-4847-99", "description": "Odinaff malware"}', '[
    {
        "condition_terms": [
            "(",
            "$s1",
            "or",
            "pe.exports",
            "(",
            "\"Tyman32\"",
            ")",
            ")",
            "and",
            "(",
            "2",
            "of",
            "(",
            "$i*",
            ")",
            ")"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "@j0sm1"
            },
            {
                "date": "2016/10/27"
            },
            {
                "description": "Odinaff malware"
            },
            {
                "reference": "https://www.symantec.com/security_response/writeup.jsp?docid=2016-083006-4847-99"
            },
            {
                "filetype": "binary"
            }
        ],
        "raw_condition": "condition:\n                ($s1 or pe.exports(\"Tyman32\")) and (2 of ($i*))\n",
        "raw_meta": "meta:\n                author = \"@j0sm1\"\n                date = \"2016/10/27\"\n                description = \"Odinaff malware\"\n                reference = \"https://www.symantec.com/security_response/writeup.jsp?docid=2016-083006-4847-99\"\n                filetype = \"binary\"\n\n        ",
        "raw_strings": "strings:\n\n                $s1 = \"getapula.pdb\"\n                $i1 = \"wtsapi32.dll\"\n                $i2 = \"cmpbk32.dll\"\n                $i3 = \"PostMessageA\"\n                $i4 = \"PeekMessageW\"\n                $i5 = \"DispatchMessageW\"\n                $i6 = \"WTSEnumerateSessionsA\"\n\n        ",
        "rule_name": "Odinaff_swift",
        "start_line": 8,
        "stop_line": 28,
        "strings": [
            {
                "name": "$s1",
                "type": "text",
                "value": "getapula.pdb"
            },
            {
                "name": "$i1",
                "type": "text",
                "value": "wtsapi32.dll"
            },
            {
                "name": "$i2",
                "type": "text",
                "value": "cmpbk32.dll"
            },
            {
                "name": "$i3",
                "type": "text",
                "value": "PostMessageA"
            },
            {
                "name": "$i4",
                "type": "text",
                "value": "PeekMessageW"
            },
            {
                "name": "$i5",
                "type": "text",
                "value": "DispatchMessageW"
            },
            {
                "name": "$i6",
                "type": "text",
                "value": "WTSEnumerateSessionsA"
            }
        ],
        "tags": [
            "malware",
            "odinaff",
            "swift",
            "raw"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'ws_f0xy_downloader', NULL, '{"author": "Nick Griffin (Websense)", "description": "f0xy malware downloader"}', '[
    {
        "condition_terms": [
            "(",
            "$mz",
            "at",
            "0",
            ")",
            "and",
            "(",
            "all",
            "of",
            "(",
            "$string*",
            ")",
            ")"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "description": "f0xy malware downloader"
            },
            {
                "author": "Nick Griffin (Websense)"
            }
        ],
        "raw_condition": "condition:\n    ($mz at 0) and (all of ($string*))\n",
        "raw_meta": "meta:\n    description = \"f0xy malware downloader\"\n    author = \"Nick Griffin (Websense)\"\n\n  ",
        "raw_strings": "strings:\n    $mz=\"MZ\"\n    $string1=\"bitsadmin /transfer\"\n    $string2=\"del rm.bat\"\n    $string3=\"av_list=\"\n  \n  ",
        "rule_name": "ws_f0xy_downloader",
        "start_line": 8,
        "stop_line": 21,
        "strings": [
            {
                "name": "$mz",
                "type": "text",
                "value": "MZ"
            },
            {
                "name": "$string1",
                "type": "text",
                "value": "bitsadmin /transfer"
            },
            {
                "name": "$string2",
                "type": "text",
                "value": "del rm.bat"
            },
            {
                "name": "$string3",
                "type": "text",
                "value": "av_list="
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Win32Toxic', '{tox,ransomware}', '{"date": "2015-06-02", "hash0": "70624c13be4d8a4c1361be38b49cb3eb", "hash1": "4f20d25cd3ae2e5c63d451d095d97046", "hash2": "e0473434cc83b57c4b579d585d4c4c57", "hash3": "c52090d184b63e5cc71b524153bb079e", "hash4": "7ac0b49baba9914b234cde62058c96a5", "hash5": "048c007de4902b6f4731fde45fa8e6a9", "hash6": "238ef3e35b14e304c87b9c62f18953a9", "hash7": "8908ccd681f66429c578a889e6e708e1", "hash8": "de9fe2b7d9463982cc77c78ee51e4d51", "hash9": "37add8d26a35a3dc9700b92b67625fa4", "author": "@GelosSnake", "hash10": "a0f30e89a3431fca1d389f90dba1d56e", "hash11": "d4d0658302c731003bf0683127618bd9", "hash12": "d1d89e1c7066f41c1d30985ac7b569db", "hash13": "97d52d7281dfae8ff9e704bf30ce2484", "hash14": "2cc85be01e86e0505697cf61219e66da", "hash15": "02ecfb44b9b11b846ea8233d524ecda3", "hash16": "703a6ebe71131671df6bc92086c9a641", "hash17": "df23629b4a4aed05d6a453280256c05a", "hash18": "07466ff2572f16c63e1fee206b081d11", "hash19": "792a1c0971775d32bad374b288792468", "hash20": "fb7fd5623fa6b7791a221fad463223cd", "hash21": "83a562aab1d66e5d170f091b2ae6a213", "hash22": "99214c8c9ff4653b533dc1b19a21d389", "hash23": "a92aec198eee23a3a9a145e64d0250ee", "hash24": "e0f7e6b96ca72b9755965b9dac3ce77e", "hash25": "f520fc947a6d5edb87aa01510bee9c8d", "hash26": "6d7babbe5e438539a9fa2c5d6128d3b4", "hash27": "3133c2231fcee5d6b0b4c988a5201da1", "hash28": "e5b1d198edc413376e0c0091566198e4", "hash29": "50515b5a6e717976823895465d5dc684", "hash30": "510389e8c7f22f2076fc7c5388e01220", "hash31": "60573c945aa3b8cfaca0bdb6dd7d2019", "hash32": "394187056697463eba97382018dfe151", "hash33": "045a5d3c95e28629927c72cf3313f4cd", "hash34": "70951624eb06f7db0dcab5fc33f49127", "hash35": "5def9e3f7b15b2a75c80596b5e24e0f4", "hash36": "35a42fb1c65ebd7d763db4abb26d33b0", "hash37": "b0030f5072864572f8e6ba9b295615fc", "hash38": "62706f48689f1ba3d1d79780010b8739", "hash39": "be86183fa029629ee9c07310cd630871", "hash40": "9755c3920d3a38eb1b5b7edbce6d4914", "hash41": "cb42611b4bed97d152721e8db5abd860", "hash42": "5475344d69fc6778e12dc1cbba23b382", "hash43": "8c1bf70742b62dec1b350a4e5046c7b6", "hash44": "6a6541c0f63f45eff725dec951ec90a7", "hash45": "a592c5bee0d81ee127cbfbcb4178afe8", "hash46": "b74c6d86ec3904f4d73d05b2797f1cc3", "hash47": "28d76fd4dd2dbfc61b0c99d2ad08cd8e", "hash48": "fc859ae67dc1596ac3fdd79b2ed02910", "hash49": "cb65d5e929da8ff5c8434fd8d36e5dfb", "hash50": "888dd1acce29cd37f0696a0284ab740a", "hash51": "0e3e231c255a5eefefd20d70c247d5f0", "hash52": "e5ebe35d934106f9f4cebbd84e04534b", "hash53": "3b580f1fa0c961a83920ce32b4e4e86d", "hash54": "d807a704f78121250227793ea15aa9c4", "hash55": "db462159bddc0953444afd7b0d57e783", "hash56": "2ed4945fb9e6202c10fad0761723cb0e", "hash57": "51183ab4fd2304a278e36d36b5fb990c", "hash58": "65d602313c585c8712ea0560a655ddeb", "hash59": "0128c12d4a72d14bb67e459b3700a373", "hash60": "5d3dfc161c983f8e820e59c370f65581", "hash61": "d4dd475179cd9f6180d5b931e8740ed6", "hash62": "5dd3782ce5f94686448326ddbbac934c", "hash63": "c85c6171a7ff05d66d497ad0d73a51ed", "hash64": "b42dda2100da688243fe85a819d61e2e", "hash65": "a5cf8f2b7d97d86f4d8948360f3db714", "hash66": "293cae15e4db1217ea72581836a6642c", "hash67": "56c3a5bae3cb1d0d315c1353ae67cf58", "hash68": "c86dc1d0378cc0b579a11d873ac944e7", "hash69": "54cef0185798f3ec1f4cb95fad4ddd7c", "hash70": "eb2eff9838043b67e8024ccadcfe1a8f", "hash71": "78778fe62ee28ef949eec2e7e5961ca8", "hash72": "e75c5762471a490d49b79d01da745498", "hash73": "1564d3e27b90a166a0989a61dc3bd646", "hash74": "59ba111403842c1f260f886d69e8757d", "hash75": "d840dfbe52a04665e40807c9d960cccc", "hash76": "77f543f4a8f54ecf84b15da8e928d3f9", "hash77": "bd9512679fdc1e1e89a24f6ebe0d5ad8", "hash78": "202f042d02be4f6469ed6f2e71f42c04", "hash79": "28f827673833175dd9094002f2f9b780", "hash80": "0ff10287b4c50e0d11ab998a28529415", "hash81": "644daa2b294c5583ce6aa8bc68f1d21f", "hash82": "1c9db47778a41775bbcb70256cc1a035", "hash83": "c203bc5752e5319b81cf1ca970c3ca96", "hash84": "656f2571e4f5172182fc970a5b21c0e7", "hash85": "c17122a9864e3bbf622285c4d5503282", "hash86": "f9e3a9636b45edbcef2ee28bd6b1cfbb", "hash87": "291ff8b46d417691a83c73a9d3a30cc9", "hash88": "1217877d3f7824165bb28281ccc80182", "hash89": "18419d775652f47a657c5400d4aef4a3", "hash90": "04417923bf4f2be48dd567dfd33684e2", "hash91": "31efe902ec6a5ab9e6876cfe715d7c84", "hash92": "a2e4472c5097d7433b91d65579711664", "hash93": "98854d7aba1874c39636ff3b703a1ed1", "hash94": "5149f0e0a56b33e7bbed1457aab8763f", "hash95": "7a4338193ce12529d6ae5cfcbb1019af", "hash96": "aa7f37206aba3cbe5e11d336424c549a", "hash97": "51cad5d45cdbc2940a66d044d5a8dabf", "hash98": "85edb7b8dee5b60e3ce32e1286207faa", "hash99": "34ca5292ae56fea78ba14abe8fe11f06", "hash100": "154187f07621a9213d77a18c0758960f", "hash101": "4e633f0478b993551db22afddfa22262", "hash102": "5c50e4427fe178566cada96b2afbc2d4", "hash103": "263001ac21ef78c31f4ca7ad2e7f191d", "hash104": "53fd9e7500e3522065a2dabb932d9dc5", "hash105": "48043dc55718eb9e5b134dac93ebb5f6", "hash106": "ca19a1b85363cfed4d36e3e7b990c8b6", "hash107": "41b5403a5443a3a84f0007131173c126", "hash108": "6f3833bc6e5940155aa804e58500da81", "hash109": "9bd50fcfa7ca6e171516101673c4e795", "hash110": "6d52ba0d48d5bf3242cd11488c75b9a7", "hash111": "c52afb663ff4165e407f53a82e34e1d5", "hash112": "5a16396d418355731c6d7bb7b21e05f7", "hash113": "05559db924e71cccee87d21b968d0930", "hash114": "824312bf8e8e7714616ba62997467fa8", "hash115": "dfec435e6264a0bfe47fc5239631903c", "hash116": "3512e7da9d66ca62be3418bead2fb091", "hash117": "7ad4df88db6f292e7ddeec7cf63fa2bc", "hash118": "d512da73d0ca103df3c9e7c074babc99", "hash119": "c622b844388c16278d1bc768dcfbbeab", "hash120": "170ffa1cd19a1cecc6dae5bdd10efb58", "hash121": "3a19c91c1c0baa7dd4a9def2e0b7c3e9", "hash122": "3b7ce3ceb8d2b85ab822f355904d47ce", "hash123": "a7bac2ace1f04a7ad440bd2f5f811edc", "hash124": "66594a62d8c98e1387ec8deb3fe39431", "hash125": "a1add9e5d7646584fd4140528d02e4c3", "hash126": "11328bbf5a76535e53ab35315321f904", "hash127": "048f19d79c953e523675e96fb6e417a9", "hash128": "eb65fc2922eafd62defd978a3215814b", "hash129": "51cc9987f86a76d75bf335a8864ec250", "hash130": "a7f91301712b5a3cc8c3ab9c119530ce", "hash131": "de976a5b3d603161a737e7b947fdbb9a", "hash132": "288a3659cc1aec47530752b3a31c232b", "hash133": "91da679f417040558059ccd5b1063688", "hash134": "4ce9a0877b5c6f439f3e90f52eb85398", "hash135": "1f9e097ff9724d4384c09748a71ef99d", "hash136": "7d8a64a94e71a5c24ad82e8a58f4b7e6", "hash137": "db119e3c6b57d9c6b739b0f9cbaeb6fd", "hash138": "52c9d25179bf010a4bb20d5b5b4e0615", "hash139": "4b9995578d51fb891040a7f159613a99", "description": "https://blogs.mcafee.com/mcafee-labs/meet-tox-ransomware-for-the-rest-of-us", "yaragenerator": "https://github.com/Xen0ph0n/YaraGenerator", "sample_filetype": "exe"}', '[
    {
        "condition_terms": [
            "2",
            "of",
            "them"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "@GelosSnake"
            },
            {
                "date": "2015-06-02"
            },
            {
                "description": "https://blogs.mcafee.com/mcafee-labs/meet-tox-ransomware-for-the-rest-of-us"
            },
            {
                "hash0": "70624c13be4d8a4c1361be38b49cb3eb"
            },
            {
                "hash1": "4f20d25cd3ae2e5c63d451d095d97046"
            },
            {
                "hash2": "e0473434cc83b57c4b579d585d4c4c57"
            },
            {
                "hash3": "c52090d184b63e5cc71b524153bb079e"
            },
            {
                "hash4": "7ac0b49baba9914b234cde62058c96a5"
            },
            {
                "hash5": "048c007de4902b6f4731fde45fa8e6a9"
            },
            {
                "hash6": "238ef3e35b14e304c87b9c62f18953a9"
            },
            {
                "hash7": "8908ccd681f66429c578a889e6e708e1"
            },
            {
                "hash8": "de9fe2b7d9463982cc77c78ee51e4d51"
            },
            {
                "hash9": "37add8d26a35a3dc9700b92b67625fa4"
            },
            {
                "hash10": "a0f30e89a3431fca1d389f90dba1d56e"
            },
            {
                "hash11": "d4d0658302c731003bf0683127618bd9"
            },
            {
                "hash12": "d1d89e1c7066f41c1d30985ac7b569db"
            },
            {
                "hash13": "97d52d7281dfae8ff9e704bf30ce2484"
            },
            {
                "hash14": "2cc85be01e86e0505697cf61219e66da"
            },
            {
                "hash15": "02ecfb44b9b11b846ea8233d524ecda3"
            },
            {
                "hash16": "703a6ebe71131671df6bc92086c9a641"
            },
            {
                "hash17": "df23629b4a4aed05d6a453280256c05a"
            },
            {
                "hash18": "07466ff2572f16c63e1fee206b081d11"
            },
            {
                "hash19": "792a1c0971775d32bad374b288792468"
            },
            {
                "hash20": "fb7fd5623fa6b7791a221fad463223cd"
            },
            {
                "hash21": "83a562aab1d66e5d170f091b2ae6a213"
            },
            {
                "hash22": "99214c8c9ff4653b533dc1b19a21d389"
            },
            {
                "hash23": "a92aec198eee23a3a9a145e64d0250ee"
            },
            {
                "hash24": "e0f7e6b96ca72b9755965b9dac3ce77e"
            },
            {
                "hash25": "f520fc947a6d5edb87aa01510bee9c8d"
            },
            {
                "hash26": "6d7babbe5e438539a9fa2c5d6128d3b4"
            },
            {
                "hash27": "3133c2231fcee5d6b0b4c988a5201da1"
            },
            {
                "hash28": "e5b1d198edc413376e0c0091566198e4"
            },
            {
                "hash29": "50515b5a6e717976823895465d5dc684"
            },
            {
                "hash30": "510389e8c7f22f2076fc7c5388e01220"
            },
            {
                "hash31": "60573c945aa3b8cfaca0bdb6dd7d2019"
            },
            {
                "hash32": "394187056697463eba97382018dfe151"
            },
            {
                "hash33": "045a5d3c95e28629927c72cf3313f4cd"
            },
            {
                "hash34": "70951624eb06f7db0dcab5fc33f49127"
            },
            {
                "hash35": "5def9e3f7b15b2a75c80596b5e24e0f4"
            },
            {
                "hash36": "35a42fb1c65ebd7d763db4abb26d33b0"
            },
            {
                "hash37": "b0030f5072864572f8e6ba9b295615fc"
            },
            {
                "hash38": "62706f48689f1ba3d1d79780010b8739"
            },
            {
                "hash39": "be86183fa029629ee9c07310cd630871"
            },
            {
                "hash40": "9755c3920d3a38eb1b5b7edbce6d4914"
            },
            {
                "hash41": "cb42611b4bed97d152721e8db5abd860"
            },
            {
                "hash42": "5475344d69fc6778e12dc1cbba23b382"
            },
            {
                "hash43": "8c1bf70742b62dec1b350a4e5046c7b6"
            },
            {
                "hash44": "6a6541c0f63f45eff725dec951ec90a7"
            },
            {
                "hash45": "a592c5bee0d81ee127cbfbcb4178afe8"
            },
            {
                "hash46": "b74c6d86ec3904f4d73d05b2797f1cc3"
            },
            {
                "hash47": "28d76fd4dd2dbfc61b0c99d2ad08cd8e"
            },
            {
                "hash48": "fc859ae67dc1596ac3fdd79b2ed02910"
            },
            {
                "hash49": "cb65d5e929da8ff5c8434fd8d36e5dfb"
            },
            {
                "hash50": "888dd1acce29cd37f0696a0284ab740a"
            },
            {
                "hash51": "0e3e231c255a5eefefd20d70c247d5f0"
            },
            {
                "hash52": "e5ebe35d934106f9f4cebbd84e04534b"
            },
            {
                "hash53": "3b580f1fa0c961a83920ce32b4e4e86d"
            },
            {
                "hash54": "d807a704f78121250227793ea15aa9c4"
            },
            {
                "hash55": "db462159bddc0953444afd7b0d57e783"
            },
            {
                "hash56": "2ed4945fb9e6202c10fad0761723cb0e"
            },
            {
                "hash57": "51183ab4fd2304a278e36d36b5fb990c"
            },
            {
                "hash58": "65d602313c585c8712ea0560a655ddeb"
            },
            {
                "hash59": "0128c12d4a72d14bb67e459b3700a373"
            },
            {
                "hash60": "5d3dfc161c983f8e820e59c370f65581"
            },
            {
                "hash61": "d4dd475179cd9f6180d5b931e8740ed6"
            },
            {
                "hash62": "5dd3782ce5f94686448326ddbbac934c"
            },
            {
                "hash63": "c85c6171a7ff05d66d497ad0d73a51ed"
            },
            {
                "hash64": "b42dda2100da688243fe85a819d61e2e"
            },
            {
                "hash65": "a5cf8f2b7d97d86f4d8948360f3db714"
            },
            {
                "hash66": "293cae15e4db1217ea72581836a6642c"
            },
            {
                "hash67": "56c3a5bae3cb1d0d315c1353ae67cf58"
            },
            {
                "hash68": "c86dc1d0378cc0b579a11d873ac944e7"
            },
            {
                "hash69": "54cef0185798f3ec1f4cb95fad4ddd7c"
            },
            {
                "hash70": "eb2eff9838043b67e8024ccadcfe1a8f"
            },
            {
                "hash71": "78778fe62ee28ef949eec2e7e5961ca8"
            },
            {
                "hash72": "e75c5762471a490d49b79d01da745498"
            },
            {
                "hash73": "1564d3e27b90a166a0989a61dc3bd646"
            },
            {
                "hash74": "59ba111403842c1f260f886d69e8757d"
            },
            {
                "hash75": "d840dfbe52a04665e40807c9d960cccc"
            },
            {
                "hash76": "77f543f4a8f54ecf84b15da8e928d3f9"
            },
            {
                "hash77": "bd9512679fdc1e1e89a24f6ebe0d5ad8"
            },
            {
                "hash78": "202f042d02be4f6469ed6f2e71f42c04"
            },
            {
                "hash79": "28f827673833175dd9094002f2f9b780"
            },
            {
                "hash80": "0ff10287b4c50e0d11ab998a28529415"
            },
            {
                "hash81": "644daa2b294c5583ce6aa8bc68f1d21f"
            },
            {
                "hash82": "1c9db47778a41775bbcb70256cc1a035"
            },
            {
                "hash83": "c203bc5752e5319b81cf1ca970c3ca96"
            },
            {
                "hash84": "656f2571e4f5172182fc970a5b21c0e7"
            },
            {
                "hash85": "c17122a9864e3bbf622285c4d5503282"
            },
            {
                "hash86": "f9e3a9636b45edbcef2ee28bd6b1cfbb"
            },
            {
                "hash87": "291ff8b46d417691a83c73a9d3a30cc9"
            },
            {
                "hash88": "1217877d3f7824165bb28281ccc80182"
            },
            {
                "hash89": "18419d775652f47a657c5400d4aef4a3"
            },
            {
                "hash90": "04417923bf4f2be48dd567dfd33684e2"
            },
            {
                "hash91": "31efe902ec6a5ab9e6876cfe715d7c84"
            },
            {
                "hash92": "a2e4472c5097d7433b91d65579711664"
            },
            {
                "hash93": "98854d7aba1874c39636ff3b703a1ed1"
            },
            {
                "hash94": "5149f0e0a56b33e7bbed1457aab8763f"
            },
            {
                "hash95": "7a4338193ce12529d6ae5cfcbb1019af"
            },
            {
                "hash96": "aa7f37206aba3cbe5e11d336424c549a"
            },
            {
                "hash97": "51cad5d45cdbc2940a66d044d5a8dabf"
            },
            {
                "hash98": "85edb7b8dee5b60e3ce32e1286207faa"
            },
            {
                "hash99": "34ca5292ae56fea78ba14abe8fe11f06"
            },
            {
                "hash100": "154187f07621a9213d77a18c0758960f"
            },
            {
                "hash101": "4e633f0478b993551db22afddfa22262"
            },
            {
                "hash102": "5c50e4427fe178566cada96b2afbc2d4"
            },
            {
                "hash103": "263001ac21ef78c31f4ca7ad2e7f191d"
            },
            {
                "hash104": "53fd9e7500e3522065a2dabb932d9dc5"
            },
            {
                "hash105": "48043dc55718eb9e5b134dac93ebb5f6"
            },
            {
                "hash106": "ca19a1b85363cfed4d36e3e7b990c8b6"
            },
            {
                "hash107": "41b5403a5443a3a84f0007131173c126"
            },
            {
                "hash108": "6f3833bc6e5940155aa804e58500da81"
            },
            {
                "hash109": "9bd50fcfa7ca6e171516101673c4e795"
            },
            {
                "hash110": "6d52ba0d48d5bf3242cd11488c75b9a7"
            },
            {
                "hash111": "c52afb663ff4165e407f53a82e34e1d5"
            },
            {
                "hash112": "5a16396d418355731c6d7bb7b21e05f7"
            },
            {
                "hash113": "05559db924e71cccee87d21b968d0930"
            },
            {
                "hash114": "824312bf8e8e7714616ba62997467fa8"
            },
            {
                "hash115": "dfec435e6264a0bfe47fc5239631903c"
            },
            {
                "hash116": "3512e7da9d66ca62be3418bead2fb091"
            },
            {
                "hash117": "7ad4df88db6f292e7ddeec7cf63fa2bc"
            },
            {
                "hash118": "d512da73d0ca103df3c9e7c074babc99"
            },
            {
                "hash119": "c622b844388c16278d1bc768dcfbbeab"
            },
            {
                "hash120": "170ffa1cd19a1cecc6dae5bdd10efb58"
            },
            {
                "hash121": "3a19c91c1c0baa7dd4a9def2e0b7c3e9"
            },
            {
                "hash122": "3b7ce3ceb8d2b85ab822f355904d47ce"
            },
            {
                "hash123": "a7bac2ace1f04a7ad440bd2f5f811edc"
            },
            {
                "hash124": "66594a62d8c98e1387ec8deb3fe39431"
            },
            {
                "hash125": "a1add9e5d7646584fd4140528d02e4c3"
            },
            {
                "hash126": "11328bbf5a76535e53ab35315321f904"
            },
            {
                "hash127": "048f19d79c953e523675e96fb6e417a9"
            },
            {
                "hash128": "eb65fc2922eafd62defd978a3215814b"
            },
            {
                "hash129": "51cc9987f86a76d75bf335a8864ec250"
            },
            {
                "hash130": "a7f91301712b5a3cc8c3ab9c119530ce"
            },
            {
                "hash131": "de976a5b3d603161a737e7b947fdbb9a"
            },
            {
                "hash132": "288a3659cc1aec47530752b3a31c232b"
            },
            {
                "hash133": "91da679f417040558059ccd5b1063688"
            },
            {
                "hash134": "4ce9a0877b5c6f439f3e90f52eb85398"
            },
            {
                "hash135": "1f9e097ff9724d4384c09748a71ef99d"
            },
            {
                "hash136": "7d8a64a94e71a5c24ad82e8a58f4b7e6"
            },
            {
                "hash137": "db119e3c6b57d9c6b739b0f9cbaeb6fd"
            },
            {
                "hash138": "52c9d25179bf010a4bb20d5b5b4e0615"
            },
            {
                "hash139": "4b9995578d51fb891040a7f159613a99"
            },
            {
                "sample_filetype": "exe"
            },
            {
                "yaragenerator": "https://github.com/Xen0ph0n/YaraGenerator"
            }
        ],
        "raw_condition": "condition:\n\t2 of them\n",
        "raw_meta": "meta:\n\tauthor = \"@GelosSnake\"\n\tdate = \"2015-06-02\"\n\tdescription = \"https://blogs.mcafee.com/mcafee-labs/meet-tox-ransomware-for-the-rest-of-us\"\n\thash0 = \"70624c13be4d8a4c1361be38b49cb3eb\"\n\thash1 = \"4f20d25cd3ae2e5c63d451d095d97046\"\n\thash2 = \"e0473434cc83b57c4b579d585d4c4c57\"\n\thash3 = \"c52090d184b63e5cc71b524153bb079e\"\n\thash4 = \"7ac0b49baba9914b234cde62058c96a5\"\n\thash5 = \"048c007de4902b6f4731fde45fa8e6a9\"\n\thash6 = \"238ef3e35b14e304c87b9c62f18953a9\"\n\thash7 = \"8908ccd681f66429c578a889e6e708e1\"\n\thash8 = \"de9fe2b7d9463982cc77c78ee51e4d51\"\n\thash9 = \"37add8d26a35a3dc9700b92b67625fa4\"\n\thash10 = \"a0f30e89a3431fca1d389f90dba1d56e\"\n\thash11 = \"d4d0658302c731003bf0683127618bd9\"\n\thash12 = \"d1d89e1c7066f41c1d30985ac7b569db\"\n\thash13 = \"97d52d7281dfae8ff9e704bf30ce2484\"\n\thash14 = \"2cc85be01e86e0505697cf61219e66da\"\n\thash15 = \"02ecfb44b9b11b846ea8233d524ecda3\"\n\thash16 = \"703a6ebe71131671df6bc92086c9a641\"\n\thash17 = \"df23629b4a4aed05d6a453280256c05a\"\n\thash18 = \"07466ff2572f16c63e1fee206b081d11\"\n\thash19 = \"792a1c0971775d32bad374b288792468\"\n\thash20 = \"fb7fd5623fa6b7791a221fad463223cd\"\n\thash21 = \"83a562aab1d66e5d170f091b2ae6a213\"\n\thash22 = \"99214c8c9ff4653b533dc1b19a21d389\"\n\thash23 = \"a92aec198eee23a3a9a145e64d0250ee\"\n\thash24 = \"e0f7e6b96ca72b9755965b9dac3ce77e\"\n\thash25 = \"f520fc947a6d5edb87aa01510bee9c8d\"\n\thash26 = \"6d7babbe5e438539a9fa2c5d6128d3b4\"\n\thash27 = \"3133c2231fcee5d6b0b4c988a5201da1\"\n\thash28 = \"e5b1d198edc413376e0c0091566198e4\"\n\thash29 = \"50515b5a6e717976823895465d5dc684\"\n\thash30 = \"510389e8c7f22f2076fc7c5388e01220\"\n\thash31 = \"60573c945aa3b8cfaca0bdb6dd7d2019\"\n\thash32 = \"394187056697463eba97382018dfe151\"\n\thash33 = \"045a5d3c95e28629927c72cf3313f4cd\"\n\thash34 = \"70951624eb06f7db0dcab5fc33f49127\"\n\thash35 = \"5def9e3f7b15b2a75c80596b5e24e0f4\"\n\thash36 = \"35a42fb1c65ebd7d763db4abb26d33b0\"\n\thash37 = \"b0030f5072864572f8e6ba9b295615fc\"\n\thash38 = \"62706f48689f1ba3d1d79780010b8739\"\n\thash39 = \"be86183fa029629ee9c07310cd630871\"\n\thash40 = \"9755c3920d3a38eb1b5b7edbce6d4914\"\n\thash41 = \"cb42611b4bed97d152721e8db5abd860\"\n\thash42 = \"5475344d69fc6778e12dc1cbba23b382\"\n\thash43 = \"8c1bf70742b62dec1b350a4e5046c7b6\"\n\thash44 = \"6a6541c0f63f45eff725dec951ec90a7\"\n\thash45 = \"a592c5bee0d81ee127cbfbcb4178afe8\"\n\thash46 = \"b74c6d86ec3904f4d73d05b2797f1cc3\"\n\thash47 = \"28d76fd4dd2dbfc61b0c99d2ad08cd8e\"\n\thash48 = \"fc859ae67dc1596ac3fdd79b2ed02910\"\n\thash49 = \"cb65d5e929da8ff5c8434fd8d36e5dfb\"\n\thash50 = \"888dd1acce29cd37f0696a0284ab740a\"\n\thash51 = \"0e3e231c255a5eefefd20d70c247d5f0\"\n\thash52 = \"e5ebe35d934106f9f4cebbd84e04534b\"\n\thash53 = \"3b580f1fa0c961a83920ce32b4e4e86d\"\n\thash54 = \"d807a704f78121250227793ea15aa9c4\"\n\thash55 = \"db462159bddc0953444afd7b0d57e783\"\n\thash56 = \"2ed4945fb9e6202c10fad0761723cb0e\"\n\thash57 = \"51183ab4fd2304a278e36d36b5fb990c\"\n\thash58 = \"65d602313c585c8712ea0560a655ddeb\"\n\thash59 = \"0128c12d4a72d14bb67e459b3700a373\"\n\thash60 = \"5d3dfc161c983f8e820e59c370f65581\"\n\thash61 = \"d4dd475179cd9f6180d5b931e8740ed6\"\n\thash62 = \"5dd3782ce5f94686448326ddbbac934c\"\n\thash63 = \"c85c6171a7ff05d66d497ad0d73a51ed\"\n\thash64 = \"b42dda2100da688243fe85a819d61e2e\"\n\thash65 = \"a5cf8f2b7d97d86f4d8948360f3db714\"\n\thash66 = \"293cae15e4db1217ea72581836a6642c\"\n\thash67 = \"56c3a5bae3cb1d0d315c1353ae67cf58\"\n\thash68 = \"c86dc1d0378cc0b579a11d873ac944e7\"\n\thash69 = \"54cef0185798f3ec1f4cb95fad4ddd7c\"\n\thash70 = \"eb2eff9838043b67e8024ccadcfe1a8f\"\n\thash71 = \"78778fe62ee28ef949eec2e7e5961ca8\"\n\thash72 = \"e75c5762471a490d49b79d01da745498\"\n\thash73 = \"1564d3e27b90a166a0989a61dc3bd646\"\n\thash74 = \"59ba111403842c1f260f886d69e8757d\"\n\thash75 = \"d840dfbe52a04665e40807c9d960cccc\"\n\thash76 = \"77f543f4a8f54ecf84b15da8e928d3f9\"\n\thash77 = \"bd9512679fdc1e1e89a24f6ebe0d5ad8\"\n\thash78 = \"202f042d02be4f6469ed6f2e71f42c04\"\n\thash79 = \"28f827673833175dd9094002f2f9b780\"\n\thash80 = \"0ff10287b4c50e0d11ab998a28529415\"\n\thash81 = \"644daa2b294c5583ce6aa8bc68f1d21f\"\n\thash82 = \"1c9db47778a41775bbcb70256cc1a035\"\n\thash83 = \"c203bc5752e5319b81cf1ca970c3ca96\"\n\thash84 = \"656f2571e4f5172182fc970a5b21c0e7\"\n\thash85 = \"c17122a9864e3bbf622285c4d5503282\"\n\thash86 = \"f9e3a9636b45edbcef2ee28bd6b1cfbb\"\n\thash87 = \"291ff8b46d417691a83c73a9d3a30cc9\"\n\thash88 = \"1217877d3f7824165bb28281ccc80182\"\n\thash89 = \"18419d775652f47a657c5400d4aef4a3\"\n\thash90 = \"04417923bf4f2be48dd567dfd33684e2\"\n\thash91 = \"31efe902ec6a5ab9e6876cfe715d7c84\"\n\thash92 = \"a2e4472c5097d7433b91d65579711664\"\n\thash93 = \"98854d7aba1874c39636ff3b703a1ed1\"\n\thash94 = \"5149f0e0a56b33e7bbed1457aab8763f\"\n\thash95 = \"7a4338193ce12529d6ae5cfcbb1019af\"\n\thash96 = \"aa7f37206aba3cbe5e11d336424c549a\"\n\thash97 = \"51cad5d45cdbc2940a66d044d5a8dabf\"\n\thash98 = \"85edb7b8dee5b60e3ce32e1286207faa\"\n\thash99 = \"34ca5292ae56fea78ba14abe8fe11f06\"\n\thash100 = \"154187f07621a9213d77a18c0758960f\"\n\thash101 = \"4e633f0478b993551db22afddfa22262\"\n\thash102 = \"5c50e4427fe178566cada96b2afbc2d4\"\n\thash103 = \"263001ac21ef78c31f4ca7ad2e7f191d\"\n\thash104 = \"53fd9e7500e3522065a2dabb932d9dc5\"\n\thash105 = \"48043dc55718eb9e5b134dac93ebb5f6\"\n\thash106 = \"ca19a1b85363cfed4d36e3e7b990c8b6\"\n\thash107 = \"41b5403a5443a3a84f0007131173c126\"\n\thash108 = \"6f3833bc6e5940155aa804e58500da81\"\n\thash109 = \"9bd50fcfa7ca6e171516101673c4e795\"\n\thash110 = \"6d52ba0d48d5bf3242cd11488c75b9a7\"\n\thash111 = \"c52afb663ff4165e407f53a82e34e1d5\"\n\thash112 = \"5a16396d418355731c6d7bb7b21e05f7\"\n\thash113 = \"05559db924e71cccee87d21b968d0930\"\n\thash114 = \"824312bf8e8e7714616ba62997467fa8\"\n\thash115 = \"dfec435e6264a0bfe47fc5239631903c\"\n\thash116 = \"3512e7da9d66ca62be3418bead2fb091\"\n\thash117 = \"7ad4df88db6f292e7ddeec7cf63fa2bc\"\n\thash118 = \"d512da73d0ca103df3c9e7c074babc99\"\n\thash119 = \"c622b844388c16278d1bc768dcfbbeab\"\n\thash120 = \"170ffa1cd19a1cecc6dae5bdd10efb58\"\n\thash121 = \"3a19c91c1c0baa7dd4a9def2e0b7c3e9\"\n\thash122 = \"3b7ce3ceb8d2b85ab822f355904d47ce\"\n\thash123 = \"a7bac2ace1f04a7ad440bd2f5f811edc\"\n\thash124 = \"66594a62d8c98e1387ec8deb3fe39431\"\n\thash125 = \"a1add9e5d7646584fd4140528d02e4c3\"\n\thash126 = \"11328bbf5a76535e53ab35315321f904\"\n\thash127 = \"048f19d79c953e523675e96fb6e417a9\"\n\thash128 = \"eb65fc2922eafd62defd978a3215814b\"\n\thash129 = \"51cc9987f86a76d75bf335a8864ec250\"\n\thash130 = \"a7f91301712b5a3cc8c3ab9c119530ce\"\n\thash131 = \"de976a5b3d603161a737e7b947fdbb9a\"\n\thash132 = \"288a3659cc1aec47530752b3a31c232b\"\n\thash133 = \"91da679f417040558059ccd5b1063688\"\n\thash134 = \"4ce9a0877b5c6f439f3e90f52eb85398\"\n\thash135 = \"1f9e097ff9724d4384c09748a71ef99d\"\n\thash136 = \"7d8a64a94e71a5c24ad82e8a58f4b7e6\"\n\thash137 = \"db119e3c6b57d9c6b739b0f9cbaeb6fd\"\n\thash138 = \"52c9d25179bf010a4bb20d5b5b4e0615\"\n\thash139 = \"4b9995578d51fb891040a7f159613a99\"\n\tsample_filetype = \"exe\"\n\tyaragenerator = \"https://github.com/Xen0ph0n/YaraGenerator\"\n",
        "raw_strings": "strings:\n\t$string0 = \"n:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t;<<t;<<t;<<t;<<t;<<t;<<t;<<t;<<t<<<t;<<t;<<t;<<\"\n\t$string1 = \"t;<<t;<<t<<<t<<\"\n\t$string2 = \">>><<<\"\n",
        "rule_name": "Win32Toxic",
        "start_line": 9,
        "stop_line": 163,
        "strings": [
            {
                "name": "$string0",
                "type": "text",
                "value": "n:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t:;;t;<<t;<<t;<<t;<<t;<<t;<<t;<<t;<<t<<<t;<<t;<<t;<<"
            },
            {
                "name": "$string1",
                "type": "text",
                "value": "t;<<t;<<t<<<t<<"
            },
            {
                "name": "$string2",
                "type": "text",
                "value": ">>><<<"
            }
        ],
        "tags": [
            "tox",
            "ransomware"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Hsdfihdf', '{banking,malware}', '{"date": "2014-04-06", "hash0": "db1675c74a444fd35383d9a45631cada", "hash1": "f48ba39df38056449a3e9a1a7289f657", "author": "Adam Ziaja <adam@adamziaja.com> http://adamziaja.com", "filetype": "exe", "description": "Polish banking malware"}', '[
    {
        "condition_terms": [
            "14",
            "of",
            "(",
            "$s*",
            ")",
            "or",
            "all",
            "of",
            "(",
            "$a*",
            ")",
            "or",
            "1",
            "of",
            "(",
            "$b*",
            ")",
            "or",
            "2",
            "of",
            "(",
            "$c*",
            ")"
        ],
        "metadata": [
            {
                "author": "Adam Ziaja <adam@adamziaja.com> http://adamziaja.com"
            },
            {
                "date": "2014-04-06"
            },
            {
                "description": "Polish banking malware"
            },
            {
                "hash0": "db1675c74a444fd35383d9a45631cada"
            },
            {
                "hash1": "f48ba39df38056449a3e9a1a7289f657"
            },
            {
                "filetype": "exe"
            }
        ],
        "raw_condition": "condition:\n\t14 of ($s*) or all of ($a*) or 1 of ($b*) or 2 of ($c*)\n",
        "raw_meta": "meta:\n\tauthor = \"Adam Ziaja <adam@adamziaja.com> http://adamziaja.com\"\n\tdate = \"2014-04-06\"\n\tdescription = \"Polish banking malware\"\n\thash0 = \"db1675c74a444fd35383d9a45631cada\"\n\thash1 = \"f48ba39df38056449a3e9a1a7289f657\"\n\tfiletype = \"exe\"\n",
        "raw_strings": "strings:\n\t$s0 = \"ANSI_CHARSET\"\n\t$s1 = \"][Vee_d_[\"\n\t$s2 = \"qfcD:6<\"\n\t$s3 = \"%-%/%1%3%5%7%9%;%\"\n\t$s4 = \"imhzxsc\\\\WWKD<.)w\"\n\t$s5 = \"Vzlarf\\\\]VOZVMskf\"\n\t$s6 = \"JKWFAp\\\\Z\"\n\t$s7 = \"<aLLwhg\"\n\t$s8 = \"bdLeftToRight\"\n\t$s9 = \"F/.pTC7\"\n\t$s10 = \"O><8,)-$ \"\n\t$s11 = \"mjeUB>D.''8)5\\\\\\\\vhe[\"\n\t$s12 = \"JGiVRk[W]PL(\"\n\t$s13 = \"zwWNNG:8\"\n\t$s14 = \"zv7,''$\"\n\t$a0 = \"#hsdfihdf\"\n\t$a1 = \"polska.irc.pl\"\n\t$b0 = \"firehim@o2.pl\"\n\t$b1 = \"firehim@go2.pl\"\n\t$b2 = \"firehim@tlen.pl\"\n\t$c0 = \"cyberpunks.pl\"\n\t$c1 = \"kaper.phrack.pl\"\n\t$c2 = \"serwer.uk.to\"\n\t$c3 = \"ns1.ipv4.hu\"\n\t$c4 = \"scorebot.koth.hu\"\n\t$c5 = \"esopoland.pl\"\n",
        "rule_name": "Hsdfihdf",
        "start_line": 4,
        "stop_line": 42,
        "strings": [
            {
                "name": "$s0",
                "type": "text",
                "value": "ANSI_CHARSET"
            },
            {
                "name": "$s1",
                "type": "text",
                "value": "][Vee_d_["
            },
            {
                "name": "$s2",
                "type": "text",
                "value": "qfcD:6<"
            },
            {
                "name": "$s3",
                "type": "text",
                "value": "%-%/%1%3%5%7%9%;%"
            },
            {
                "name": "$s4",
                "type": "text",
                "value": "imhzxsc\\\\WWKD<.)w"
            },
            {
                "name": "$s5",
                "type": "text",
                "value": "Vzlarf\\\\]VOZVMskf"
            },
            {
                "name": "$s6",
                "type": "text",
                "value": "JKWFAp\\\\Z"
            },
            {
                "name": "$s7",
                "type": "text",
                "value": "<aLLwhg"
            },
            {
                "name": "$s8",
                "type": "text",
                "value": "bdLeftToRight"
            },
            {
                "name": "$s9",
                "type": "text",
                "value": "F/.pTC7"
            },
            {
                "name": "$s10",
                "type": "text",
                "value": "O><8,)-$ "
            },
            {
                "name": "$s11",
                "type": "text",
                "value": "mjeUB>D.''8)5\\\\\\\\vhe["
            },
            {
                "name": "$s12",
                "type": "text",
                "value": "JGiVRk[W]PL("
            },
            {
                "name": "$s13",
                "type": "text",
                "value": "zwWNNG:8"
            },
            {
                "name": "$s14",
                "type": "text",
                "value": "zv7,''$"
            },
            {
                "name": "$a0",
                "type": "text",
                "value": "#hsdfihdf"
            },
            {
                "name": "$a1",
                "type": "text",
                "value": "polska.irc.pl"
            },
            {
                "name": "$b0",
                "type": "text",
                "value": "firehim@o2.pl"
            },
            {
                "name": "$b1",
                "type": "text",
                "value": "firehim@go2.pl"
            },
            {
                "name": "$b2",
                "type": "text",
                "value": "firehim@tlen.pl"
            },
            {
                "name": "$c0",
                "type": "text",
                "value": "cyberpunks.pl"
            },
            {
                "name": "$c1",
                "type": "text",
                "value": "kaper.phrack.pl"
            },
            {
                "name": "$c2",
                "type": "text",
                "value": "serwer.uk.to"
            },
            {
                "name": "$c3",
                "type": "text",
                "value": "ns1.ipv4.hu"
            },
            {
                "name": "$c4",
                "type": "text",
                "value": "scorebot.koth.hu"
            },
            {
                "name": "$c5",
                "type": "text",
                "value": "esopoland.pl"
            }
        ],
        "tags": [
            "banking",
            "malware"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'XOR_DDosv1', '{DDoS}', '{"author": "Akamai CSIRT", "description": "Rule to detect XOR DDos infection"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Akamai CSIRT"
            },
            {
                "description": "Rule to detect XOR DDos infection"
            }
        ],
        "raw_condition": "condition:\n    all of them\n",
        "raw_meta": "meta:\n    author = \"Akamai CSIRT\"\n    description = \"Rule to detect XOR DDos infection\"\n  ",
        "raw_strings": "strings:\n    $st0 = \"BB2FA36AAA9541F0\"\n    $st1 = \"md5=\"\n    $st2 = \"denyip=\"\n    $st3 = \"filename=\"\n    $st4 = \"rmfile=\"\n    $st5 = \"exec_packet\"\n    $st6 = \"build_iphdr\"\n  ",
        "rule_name": "XOR_DDosv1",
        "start_line": 6,
        "stop_line": 21,
        "strings": [
            {
                "name": "$st0",
                "type": "text",
                "value": "BB2FA36AAA9541F0"
            },
            {
                "name": "$st1",
                "type": "text",
                "value": "md5="
            },
            {
                "name": "$st2",
                "type": "text",
                "value": "denyip="
            },
            {
                "name": "$st3",
                "type": "text",
                "value": "filename="
            },
            {
                "name": "$st4",
                "type": "text",
                "value": "rmfile="
            },
            {
                "name": "$st5",
                "type": "text",
                "value": "exec_packet"
            },
            {
                "name": "$st6",
                "type": "text",
                "value": "build_iphdr"
            }
        ],
        "tags": [
            "DDoS"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'BlackRev', NULL, '{"date": "2013-05-21", "author": "Dennis Schwarz", "origin": "https://github.com/arbor/yara/blob/master/blackrev.yara", "description": "Black Revolution DDoS Malware. http://www.arbornetworks.com/asert/2013/05/the-revolution-will-be-written-in-delphi/"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "(",
            "$base*",
            ")",
            "and",
            "5",
            "of",
            "(",
            "$opt*",
            ")"
        ],
        "metadata": [
            {
                "author": "Dennis Schwarz"
            },
            {
                "date": "2013-05-21"
            },
            {
                "description": "Black Revolution DDoS Malware. http://www.arbornetworks.com/asert/2013/05/the-revolution-will-be-written-in-delphi/"
            },
            {
                "origin": "https://github.com/arbor/yara/blob/master/blackrev.yara"
            }
        ],
        "raw_condition": "condition:\n      all of ($base*) and 5 of ($opt*)\n",
        "raw_meta": "meta:\n      author = \"Dennis Schwarz\"\n      date = \"2013-05-21\"\n      description = \"Black Revolution DDoS Malware. http://www.arbornetworks.com/asert/2013/05/the-revolution-will-be-written-in-delphi/\"\n      origin = \"https://github.com/arbor/yara/blob/master/blackrev.yara\"\n\n   ",
        "raw_strings": "strings: \n      $base1 = \"http\"\n      $base2 = \"simple\"\n      $base3 = \"loginpost\"\n      $base4 = \"datapost\"\n\n      $opt1 = \"blackrev\"\n      $opt2 = \"stop\"\n      $opt3 = \"die\"\n      $opt4 = \"sleep\"\n      $opt5 = \"syn\"\n      $opt6 = \"udp\"\n      $opt7 = \"udpdata\"\n      $opt8 = \"icmp\"\n      $opt9 = \"antiddos\"\n      $opt10 = \"range\"\n      $opt11 = \"fastddos\"\n      $opt12 = \"slowhttp\"\n      $opt13 = \"allhttp\"\n      $opt14 = \"tcpdata\"\n      $opt15 = \"dataget\"\n\n   ",
        "rule_name": "BlackRev",
        "start_line": 7,
        "stop_line": 39,
        "strings": [
            {
                "name": "$base1",
                "type": "text",
                "value": "http"
            },
            {
                "name": "$base2",
                "type": "text",
                "value": "simple"
            },
            {
                "name": "$base3",
                "type": "text",
                "value": "loginpost"
            },
            {
                "name": "$base4",
                "type": "text",
                "value": "datapost"
            },
            {
                "name": "$opt1",
                "type": "text",
                "value": "blackrev"
            },
            {
                "name": "$opt2",
                "type": "text",
                "value": "stop"
            },
            {
                "name": "$opt3",
                "type": "text",
                "value": "die"
            },
            {
                "name": "$opt4",
                "type": "text",
                "value": "sleep"
            },
            {
                "name": "$opt5",
                "type": "text",
                "value": "syn"
            },
            {
                "name": "$opt6",
                "type": "text",
                "value": "udp"
            },
            {
                "name": "$opt7",
                "type": "text",
                "value": "udpdata"
            },
            {
                "name": "$opt8",
                "type": "text",
                "value": "icmp"
            },
            {
                "name": "$opt9",
                "type": "text",
                "value": "antiddos"
            },
            {
                "name": "$opt10",
                "type": "text",
                "value": "range"
            },
            {
                "name": "$opt11",
                "type": "text",
                "value": "fastddos"
            },
            {
                "name": "$opt12",
                "type": "text",
                "value": "slowhttp"
            },
            {
                "name": "$opt13",
                "type": "text",
                "value": "allhttp"
            },
            {
                "name": "$opt14",
                "type": "text",
                "value": "tcpdata"
            },
            {
                "name": "$opt15",
                "type": "text",
                "value": "dataget"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Wabot', '{Worm}', '{"date": "14/08/2015", "author": "Kevin Falcoz", "description": "Wabot Trojan Worm"}', '[
    {
        "condition_terms": [
            "$signature1",
            "and",
            "$signature2"
        ],
        "metadata": [
            {
                "author": "Kevin Falcoz"
            },
            {
                "date": "14/08/2015"
            },
            {
                "description": "Wabot Trojan Worm"
            }
        ],
        "raw_condition": "condition:\n\t\t$signature1 and $signature2\n",
        "raw_meta": "meta:\n\t\tauthor=\"Kevin Falcoz\"\n\t\tdate=\"14/08/2015\"\n\t\tdescription=\"Wabot Trojan Worm\"\n\n\t",
        "raw_strings": "strings:\n\t\t$signature1={43 3A 5C 6D 61 72 69 6A 75 61 6E 61 2E 74 78 74}\n\t\t$signature2={73 49 52 43 34}\n\n\t",
        "rule_name": "Wabot",
        "start_line": 5,
        "stop_line": 18,
        "strings": [
            {
                "name": "$signature1",
                "type": "byte",
                "value": "{43 3A 5C 6D 61 72 69 6A 75 61 6E 61 2E 74 78 74}"
            },
            {
                "name": "$signature2",
                "type": "byte",
                "value": "{73 49 52 43 34}"
            }
        ],
        "tags": [
            "Worm"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'ransom_comodosec_mrcr1', NULL, '{"date": "2017/01", "author": " J from THL <j@techhelplist.com>", "maltype": "Ransomware", "version": 1, "filetype": "memory", "reference": "https://virustotal.com/en/file/75c82fd18fcf8a51bc1b32a89852d90978fa5e7a55281f42b0a1de98d14644fa/analysis/"}', '[
    {
        "condition_terms": [
            "10",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": " J from THL <j@techhelplist.com>"
            },
            {
                "date": "2017/01"
            },
            {
                "reference": "https://virustotal.com/en/file/75c82fd18fcf8a51bc1b32a89852d90978fa5e7a55281f42b0a1de98d14644fa/analysis/"
            },
            {
                "version": 1
            },
            {
                "maltype": "Ransomware"
            },
            {
                "filetype": "memory"
            }
        ],
        "raw_condition": "condition:\n        10 of them\n",
        "raw_meta": "meta:\n                author = \" J from THL <j@techhelplist.com>\"\n                date = \"2017/01\"\n                reference = \"https://virustotal.com/en/file/75c82fd18fcf8a51bc1b32a89852d90978fa5e7a55281f42b0a1de98d14644fa/analysis/\"\n                version = 1\n                maltype = \"Ransomware\"\n                filetype = \"memory\"\n\n        ",
        "raw_strings": "strings:\n                $text01 = \"WebKitFormBoundary\"\n                $text02 = \"Start NetworkScan\"\n                $text03 = \"Start DriveScan\"\n                $text04 = \"Start CryptFiles\"\n                $text05 = \"cmd /c vssadmin delete shadows /all /quiet\"\n                $text06 = \"isAutorun:\"\n                $text07 = \"isNetworkScan:\"\n                $text08 = \"isUserDataLast:\"\n                $text09 = \"isCryptFileNames:\"\n                $text10 = \"isChangeFileExts:\"\n                $text11 = \"isPowerOffWindows:\"\n                $text12 = \"GatePath:\"\n                $text13 = \"GatePort:\"\n                $text14 = \"DefaultCryptKey:\"\n                $text15 = \"UserAgent:\"\n                $text16 = \"Mozilla_\"\n                $text17 = \"On Error Resume Next\"\n                $text18 = \"Content-Disposition: form-data; name=\\\"uid\\\"\"\n                $text19 = \"Content-Disposition: form-data; name=\\\"uname\\\"\"\n                $text20 = \"Content-Disposition: form-data; name=\\\"cname\\\"\"\n                $regx21 = /\\|[0-9a-z]{2,5}\\|\\|[0-9a-z]{2,5}\\|\\|[0-9a-z]{2,5}\\|\\|[0-9a-z]{2,5}\\|/\n\n\n    ",
        "rule_name": "ransom_comodosec_mrcr1",
        "start_line": 5,
        "stop_line": 41,
        "strings": [
            {
                "name": "$text01",
                "type": "text",
                "value": "WebKitFormBoundary"
            },
            {
                "name": "$text02",
                "type": "text",
                "value": "Start NetworkScan"
            },
            {
                "name": "$text03",
                "type": "text",
                "value": "Start DriveScan"
            },
            {
                "name": "$text04",
                "type": "text",
                "value": "Start CryptFiles"
            },
            {
                "name": "$text05",
                "type": "text",
                "value": "cmd /c vssadmin delete shadows /all /quiet"
            },
            {
                "name": "$text06",
                "type": "text",
                "value": "isAutorun:"
            },
            {
                "name": "$text07",
                "type": "text",
                "value": "isNetworkScan:"
            },
            {
                "name": "$text08",
                "type": "text",
                "value": "isUserDataLast:"
            },
            {
                "name": "$text09",
                "type": "text",
                "value": "isCryptFileNames:"
            },
            {
                "name": "$text10",
                "type": "text",
                "value": "isChangeFileExts:"
            },
            {
                "name": "$text11",
                "type": "text",
                "value": "isPowerOffWindows:"
            },
            {
                "name": "$text12",
                "type": "text",
                "value": "GatePath:"
            },
            {
                "name": "$text13",
                "type": "text",
                "value": "GatePort:"
            },
            {
                "name": "$text14",
                "type": "text",
                "value": "DefaultCryptKey:"
            },
            {
                "name": "$text15",
                "type": "text",
                "value": "UserAgent:"
            },
            {
                "name": "$text16",
                "type": "text",
                "value": "Mozilla_"
            },
            {
                "name": "$text17",
                "type": "text",
                "value": "On Error Resume Next"
            },
            {
                "name": "$text18",
                "type": "text",
                "value": "Content-Disposition: form-data; name=\\\"uid\\\""
            },
            {
                "name": "$text19",
                "type": "text",
                "value": "Content-Disposition: form-data; name=\\\"uname\\\""
            },
            {
                "name": "$text20",
                "type": "text",
                "value": "Content-Disposition: form-data; name=\\\"cname\\\""
            },
            {
                "name": "$regx21",
                "type": "regex",
                "value": "/\\|[0-9a-z]{2,5}\\|\\|[0-9a-z]{2,5}\\|\\|[0-9a-z]{2,5}\\|\\|[0-9a-z]{2,5}\\|/"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'sitrof_fortis_scar', NULL, '{"date": "2018/23", "author": "J from THL <j@techhelplist.com>", "maltype": "Stealer", "version": 2, "filetype": "memory", "reference1": "https://www.virustotal.com/#/file/59ab6cb69712d82f3e13973ecc7e7d2060914cea6238d338203a69bac95fd96c/community", "reference2": "ETPRO rule 2806032, ETPRO TROJAN Win32.Scar.hhrw POST"}', '[
    {
        "condition_terms": [
            "6",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "J from THL <j@techhelplist.com>"
            },
            {
                "date": "2018/23"
            },
            {
                "reference1": "https://www.virustotal.com/#/file/59ab6cb69712d82f3e13973ecc7e7d2060914cea6238d338203a69bac95fd96c/community"
            },
            {
                "reference2": "ETPRO rule 2806032, ETPRO TROJAN Win32.Scar.hhrw POST"
            },
            {
                "version": 2
            },
            {
                "maltype": "Stealer"
            },
            {
                "filetype": "memory"
            }
        ],
        "raw_condition": "condition:\n        6 of them\n",
        "raw_meta": "meta:\n        author = \"J from THL <j@techhelplist.com>\"\n        date = \"2018/23\"\n        reference1 = \"https://www.virustotal.com/#/file/59ab6cb69712d82f3e13973ecc7e7d2060914cea6238d338203a69bac95fd96c/community\"\n\treference2 = \"ETPRO rule 2806032, ETPRO TROJAN Win32.Scar.hhrw POST\"\n\tversion = 2\n        maltype = \"Stealer\"\n        filetype = \"memory\"\n\n    ",
        "raw_strings": "strings:\n\t\n\t$a = \"?get&version\"\n\t$b = \"?reg&ver=\"\n\t$c = \"?get&exe\"\n\t$d = \"?get&download\"\n\t$e = \"?get&module\"\n\t$f = \"&ver=\"\n\t$g = \"&comp=\"\n\t$h = \"&addinfo=\"\n\t$i = \"%s@%s; %s %s \\\"%s\\\" processor(s)\"\n\t$j = \"User-Agent: fortis\"\n\n    ",
        "rule_name": "sitrof_fortis_scar",
        "start_line": 1,
        "stop_line": 27,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "?get&version"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "?reg&ver="
            },
            {
                "name": "$c",
                "type": "text",
                "value": "?get&exe"
            },
            {
                "name": "$d",
                "type": "text",
                "value": "?get&download"
            },
            {
                "name": "$e",
                "type": "text",
                "value": "?get&module"
            },
            {
                "name": "$f",
                "type": "text",
                "value": "&ver="
            },
            {
                "name": "$g",
                "type": "text",
                "value": "&comp="
            },
            {
                "name": "$h",
                "type": "text",
                "value": "&addinfo="
            },
            {
                "name": "$i",
                "type": "text",
                "value": "%s@%s; %s %s \\\"%s\\\" processor(s)"
            },
            {
                "name": "$j",
                "type": "text",
                "value": "User-Agent: fortis"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'locdoor_ransomware', NULL, '{"author": "Marc Rivero | @seifreed", "reference": "https://twitter.com/leotpsc/status/1036180615744376832", "description": "Rule to detect Locdoor/DryCry"}', '[
    {
        "condition_terms": [
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "filesize",
            "<",
            "600KB",
            ")",
            "and",
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Rule to detect Locdoor/DryCry"
            },
            {
                "author": "Marc Rivero | @seifreed"
            },
            {
                "reference": "https://twitter.com/leotpsc/status/1036180615744376832"
            }
        ],
        "raw_condition": "condition:\n\n      ( uint16(0) == 0x5a4d and filesize < 600KB ) and all of them \n",
        "raw_meta": "meta:\n\n      description = \"Rule to detect Locdoor/DryCry\"\n      author = \"Marc Rivero | @seifreed\"\n      reference = \"https://twitter.com/leotpsc/status/1036180615744376832\"\n\n   ",
        "raw_strings": "strings:\n\n      $s1 = \"copy \\\"Locdoor.exe\\\" \\\"C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\StartUp\\\\temp00000000.exe\\\"\" fullword ascii\n      $s2 = \"copy wscript.vbs C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\StartUp\\\\wscript.vbs\" fullword ascii\n      $s3 = \"!! Your computer''s important files have been encrypted! Your computer''s important files have been encrypted!\" fullword ascii\n      $s4 = \"echo CreateObject(\\\"SAPI.SpVoice\\\").Speak \\\"Your computer''s important files have been encrypted! \" fullword ascii    \n      $s5 = \"! Your computer''s important files have been encrypted! \" fullword ascii\n      $s7 = \"This program is not supported on your operating system.\" fullword ascii\n      $s8 = \"echo Your computer''s files have been encrypted to Locdoor Ransomware! To make a recovery go to localbitcoins.com and create a wa\" ascii\n      $s9 = \"Please enter the password.\" fullword ascii\n\n   ",
        "rule_name": "locdoor_ransomware",
        "start_line": 1,
        "stop_line": 23,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "copy \\\"Locdoor.exe\\\" \\\"C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\StartUp\\\\temp00000000.exe\\\""
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s2",
                "type": "text",
                "value": "copy wscript.vbs C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\StartUp\\\\wscript.vbs"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s3",
                "type": "text",
                "value": "!! Your computer''s important files have been encrypted! Your computer''s important files have been encrypted!"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s4",
                "type": "text",
                "value": "echo CreateObject(\\\"SAPI.SpVoice\\\").Speak \\\"Your computer''s important files have been encrypted! "
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s5",
                "type": "text",
                "value": "! Your computer''s important files have been encrypted! "
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s7",
                "type": "text",
                "value": "This program is not supported on your operating system."
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$s8",
                "type": "text",
                "value": "echo Your computer''s files have been encrypted to Locdoor Ransomware! To make a recovery go to localbitcoins.com and create a wa"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s9",
                "type": "text",
                "value": "Please enter the password."
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'NionSpy', '{win32}', '{"reference": "https://blogs.mcafee.com/mcafee-labs/taking-a-close-look-at-data-stealing-nionspy-file-infector", "description": "Triggers on old and new variants of W32/NionSpy file infector"}', '[
    {
        "condition_terms": [
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5A4D",
            "and",
            "uint32",
            "(",
            "uint32",
            "(",
            "0x3C",
            ")",
            ")",
            "==",
            "0x00004550",
            "and",
            "1",
            "of",
            "(",
            "$variant*",
            ")"
        ],
        "metadata": [
            {
                "description": "Triggers on old and new variants of W32/NionSpy file infector"
            },
            {
                "reference": "https://blogs.mcafee.com/mcafee-labs/taking-a-close-look-at-data-stealing-nionspy-file-infector"
            }
        ],
        "raw_condition": "condition:\nuint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and 1 of ($variant*)\n",
        "raw_meta": "meta:\ndescription = \"Triggers on old and new variants of W32/NionSpy file infector\"\nreference = \"https://blogs.mcafee.com/mcafee-labs/taking-a-close-look-at-data-stealing-nionspy-file-infector\"\n",
        "raw_strings": "strings:\n$variant2015_infmarker = \"aCfG92KXpcSo4Y94BnUrFmnNk27EhW6CqP5EnT\"\n$variant2013_infmarker = \"ad6af8bd5835d19cc7fdc4c62fdf02a1\"\n$variant2013_string = \"%s?cstorage=shell&comp=%s\"\n",
        "rule_name": "NionSpy",
        "start_line": 5,
        "stop_line": 16,
        "strings": [
            {
                "name": "$variant2015_infmarker",
                "type": "text",
                "value": "aCfG92KXpcSo4Y94BnUrFmnNk27EhW6CqP5EnT"
            },
            {
                "name": "$variant2013_infmarker",
                "type": "text",
                "value": "ad6af8bd5835d19cc7fdc4c62fdf02a1"
            },
            {
                "name": "$variant2013_string",
                "type": "text",
                "value": "%s?cstorage=shell&comp=%s"
            }
        ],
        "tags": [
            "win32"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'DDosTf', NULL, '{"author": "benkow_ - MalwareMustDie", "reference": "http://blog.malwaremustdie.org/2016/01/mmd-0048-2016-ddostf-new-elf-windows.html", "description": "Rule to detect ELF.DDosTf infection"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "benkow_ - MalwareMustDie"
            },
            {
                "reference": "http://blog.malwaremustdie.org/2016/01/mmd-0048-2016-ddostf-new-elf-windows.html"
            },
            {
                "description": "Rule to detect ELF.DDosTf infection"
            }
        ],
        "raw_condition": "condition:\n    all of them\n",
        "raw_meta": "meta:\n    author = \"benkow_ - MalwareMustDie\"\n    reference = \"http://blog.malwaremustdie.org/2016/01/mmd-0048-2016-ddostf-new-elf-windows.html\"\n    description = \"Rule to detect ELF.DDosTf infection\"\n\n",
        "raw_strings": "strings:\n    $st0 = \"ddos.tf\"\n    $st1 = {E8 AE BE E7 BD AE 54 43  50 5F 4B 45 45 50 49 4E 54 56 4C E9 94 99 E8 AF AF EF BC 9A 00} /*TCP_KEEPINTVL*/\n    $st2 = {E8 AE BE E7 BD AE 54 43  50 5F 4B 45 45 50 43 4E 54 E9 94 99 E8 AF AF EF BC 9A 00} /*TCP_KEEPCNT*/\n    $st3 = \"Accept-Language: zh\"\n    $st4 = \"%d Kb/bps|%d%%\"\n   \n",
        "rule_name": "DDosTf",
        "start_line": 6,
        "stop_line": 23,
        "strings": [
            {
                "name": "$st0",
                "type": "text",
                "value": "ddos.tf"
            },
            {
                "name": "$st1",
                "type": "byte",
                "value": "{E8 AE BE E7 BD AE 54 43  50 5F 4B 45 45 50 49 4E 54 56 4C E9 94 99 E8 AF AF EF BC 9A 00}"
            },
            {
                "name": "$st2",
                "type": "byte",
                "value": "{E8 AE BE E7 BD AE 54 43  50 5F 4B 45 45 50 43 4E 54 E9 94 99 E8 AF AF EF BC 9A 00}"
            },
            {
                "name": "$st3",
                "type": "text",
                "value": "Accept-Language: zh"
            },
            {
                "name": "$st4",
                "type": "text",
                "value": "%d Kb/bps|%d%%"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Arkei', '{Arkei}', '{"Date": "2018/07/10", "Hash": "5632c89fe4c7c2c87b69d787bbf0a5b4cc535f1aa02699792888c60e0ef88fc5", "Author": "Fumik0_", "Description": "Arkei Stealer"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "(",
            "$s*",
            ")"
        ],
        "metadata": [
            {
                "Author": "Fumik0_"
            },
            {
                "Description": "Arkei Stealer"
            },
            {
                "Date": "2018/07/10"
            },
            {
                "Hash": "5632c89fe4c7c2c87b69d787bbf0a5b4cc535f1aa02699792888c60e0ef88fc5"
            }
        ],
        "raw_condition": "condition:\n        all of ($s*)\t\n",
        "raw_meta": "meta:\n        Author = \"Fumik0_\" \n        Description = \"Arkei Stealer\"\n        Date = \"2018/07/10\"\n        Hash = \"5632c89fe4c7c2c87b69d787bbf0a5b4cc535f1aa02699792888c60e0ef88fc5\"\n\n    ",
        "raw_strings": "strings:\n        $s1 = \"Arkei\" wide ascii\n        $s2 = \"/server/gate\" wide ascii\n        $s3 = \"/server/grubConfig\" wide ascii\n        $s4 = \"\\\\files\\\\\" wide ascii\n        $s5 = \"SQLite\" wide ascii\n\n    ",
        "rule_name": "Arkei",
        "start_line": 5,
        "stop_line": 22,
        "strings": [
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "Arkei"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s2",
                "type": "text",
                "value": "/server/gate"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s3",
                "type": "text",
                "value": "/server/grubConfig"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s4",
                "type": "text",
                "value": "\\\\files\\\\"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s5",
                "type": "text",
                "value": "SQLite"
            }
        ],
        "tags": [
            "Arkei"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'MSILStealer', NULL, '{"author": "https://github.com/hwvs", "reference": "https://github.com/quasar/QuasarRAT", "description": "Detects strings from C#/VB Stealers and QuasarRat", "last_modified": "2019-11-21"}', '[
    {
        "condition_terms": [
            "1",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Detects strings from C#/VB Stealers and QuasarRat"
            },
            {
                "reference": "https://github.com/quasar/QuasarRAT"
            },
            {
                "author": "https://github.com/hwvs"
            },
            {
                "last_modified": "2019-11-21"
            }
        ],
        "raw_condition": "condition:\n        1 of them\n",
        "raw_meta": "meta:\n        description = \"Detects strings from C#/VB Stealers and QuasarRat\"\n        reference = \"https://github.com/quasar/QuasarRAT\"\n        author = \"https://github.com/hwvs\"\n        last_modified = \"2019-11-21\"\n\n    ",
        "raw_strings": "strings:\n        $ = \"Firefox does not have any profiles, has it ever been launched?\" wide ascii\n        $ = \"Firefox is not installed, or the install path could not be located\" wide ascii\n        $ = \"No installs of firefox recorded in its key.\" wide ascii\n        $ = \"{0}\\\\\\\\FileZilla\\\\\\\\recentservers.xml\" wide ascii\n        $ = \"{1}{0}Cookie Name: {2}{0}Value: {3}{0}Path\" wide ascii\n        $ = \"[PRIVATE KEY LOCATION: \\\\\\\"{0}\\\\\\\"]\" wide ascii\n\n    ",
        "rule_name": "MSILStealer",
        "start_line": 5,
        "stop_line": 23,
        "strings": [
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "Firefox does not have any profiles, has it ever been launched?"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "Firefox is not installed, or the install path could not be located"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "No installs of firefox recorded in its key."
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "{0}\\\\\\\\FileZilla\\\\\\\\recentservers.xml"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "{1}{0}Cookie Name: {2}{0}Value: {3}{0}Path"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "[PRIVATE KEY LOCATION: \\\\\\\"{0}\\\\\\\"]"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'APT_Uppercut', NULL, '{"date": "2018-09-13", "author": "Colin Cowie", "reference": "https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html", "description": "Detects APT10 MenuPass Uppercut"}', '[
    {
        "condition_terms": [
            "any",
            "of",
            "them",
            "or",
            "hash.md5",
            "(",
            "0",
            ",",
            "filesize",
            ")",
            "==",
            "\"aa3f303c3319b14b4829fe2faa5999c1\"",
            "or",
            "hash.md5",
            "(",
            "0",
            ",",
            "filesize",
            ")",
            "==",
            "\"126067d634d94c45084cbe1d9873d895\"",
            "or",
            "hash.md5",
            "(",
            "0",
            ",",
            "filesize",
            ")",
            "==",
            "\"fce54b4886cac5c61eda1e7605483ca3\""
        ],
        "imports": [
            "hash"
        ],
        "metadata": [
            {
                "description": "Detects APT10 MenuPass Uppercut"
            },
            {
                "author": "Colin Cowie"
            },
            {
                "reference": "https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html"
            },
            {
                "date": "2018-09-13"
            }
        ],
        "raw_condition": "condition:\n     any of them or\n     hash.md5(0, filesize) == \"aa3f303c3319b14b4829fe2faa5999c1\" or\n     hash.md5(0, filesize) == \"126067d634d94c45084cbe1d9873d895\" or\n     hash.md5(0, filesize) == \"fce54b4886cac5c61eda1e7605483ca3\"\n",
        "raw_meta": "meta:\n     description = \"Detects APT10 MenuPass Uppercut\"\n     author = \"Colin Cowie\"\n     reference = \"https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html\"\n     date = \"2018-09-13\"\n  ",
        "raw_strings": "strings:\n     $ip1 = \"51.106.53.147\"\n     $ip2 = \"153.92.210.208\"\n     $ip3 = \"eservake.jetos.com\"\n     $c1 = \"0x97A168D9697D40DD\" wide\n     $c2 = \"0x7CF812296CCC68D5\" wide\n     $c3 = \"0x652CB1CEFF1C0A00\" wide\n     $c4 = \"0x27595F1F74B55278\" wide\n     $c5 = \"0xD290626C85FB1CE3\" wide\n     $c6 = \"0x409C7A89CFF0A727\" wide\n  ",
        "rule_name": "APT_Uppercut",
        "start_line": 3,
        "stop_line": 24,
        "strings": [
            {
                "name": "$ip1",
                "type": "text",
                "value": "51.106.53.147"
            },
            {
                "name": "$ip2",
                "type": "text",
                "value": "153.92.210.208"
            },
            {
                "name": "$ip3",
                "type": "text",
                "value": "eservake.jetos.com"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$c1",
                "type": "text",
                "value": "0x97A168D9697D40DD"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$c2",
                "type": "text",
                "value": "0x7CF812296CCC68D5"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$c3",
                "type": "text",
                "value": "0x652CB1CEFF1C0A00"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$c4",
                "type": "text",
                "value": "0x27595F1F74B55278"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$c5",
                "type": "text",
                "value": "0xD290626C85FB1CE3"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$c6",
                "type": "text",
                "value": "0x409C7A89CFF0A727"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'BernhardPOS', NULL, '{"md5": "e49820ef02ba5308ff84e4c8c12e7c3d", "score": 70, "author": "Nick Hoffman / Jeremy Humble", "source": "Morphick Inc.", "reference": "http://morphick.com/blog/2015/7/14/bernhardpos-new-pos-malware-discovered-by-morphick", "description": "BernhardPOS Credit Card dumping tool", "last_update": "2015-07-14"}', '[
    {
        "condition_terms": [
            "any",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Nick Hoffman / Jeremy Humble"
            },
            {
                "last_update": "2015-07-14"
            },
            {
                "source": "Morphick Inc."
            },
            {
                "description": "BernhardPOS Credit Card dumping tool"
            },
            {
                "reference": "http://morphick.com/blog/2015/7/14/bernhardpos-new-pos-malware-discovered-by-morphick"
            },
            {
                "md5": "e49820ef02ba5308ff84e4c8c12e7c3d"
            },
            {
                "score": 70
            }
        ],
        "raw_condition": "condition:\n          any of them\n ",
        "raw_meta": "meta:\n          author = \"Nick Hoffman / Jeremy Humble\"\n          last_update = \"2015-07-14\"\n          source = \"Morphick Inc.\"\n          description = \"BernhardPOS Credit Card dumping tool\"\n          reference = \"http://morphick.com/blog/2015/7/14/bernhardpos-new-pos-malware-discovered-by-morphick\"\n          md5 = \"e49820ef02ba5308ff84e4c8c12e7c3d\"\n          score = 70\n     ",
        "raw_strings": "strings:\n          $shellcode_kernel32_with_junk_code = { 33 c0 83 ?? ?? 83 ?? ?? 64 a1 30 00 00 00 83 ?? ?? 83 ?? ?? 8b 40 0c 83 ?? ?? 83 ?? ?? 8b 40 14 83 ?? ?? 83 ?? ?? 8b 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 00 83 ?? ?? 83 ?? ?? 8b 40 10 83 ?? ?? }\n          $mutex_name = \"OPSEC_BERNHARD\" \n          $build_path = \"C:\\\\bernhard\\\\Debug\\\\bernhard.pdb\" \n          $string_decode_routine = { 55 8b ec 83 ec 50 53 56 57 a1 ?? ?? ?? ?? 89 45 f8 66 8b 0d ?? ?? ?? ?? 66 89 4d fc 8a 15 ?? ?? ?? ?? 88 55 fe 8d 45 f8 50 ff ?? ?? ?? ?? ?? 89 45 f0 c7 45 f4 00 00 00 00 ?? ?? 8b 45 f4 83 c0 01 89 45 f4 8b 45 08 50 ff ?? ?? ?? ?? ?? 39 45 f4 ?? ?? 8b 45 08 03 45 f4 0f be 08 8b 45 f4 99 f7 7d f0 0f be 54 15 f8 33 ca 8b 45 08 03 45 f4 88 08 ?? ?? 5f 5e 5b 8b e5 5d }\n     ",
        "rule_name": "BernhardPOS",
        "start_line": 5,
        "stop_line": 21,
        "strings": [
            {
                "name": "$shellcode_kernel32_with_junk_code",
                "type": "byte",
                "value": "{ 33 c0 83 ?? ?? 83 ?? ?? 64 a1 30 00 00 00 83 ?? ?? 83 ?? ?? 8b 40 0c 83 ?? ?? 83 ?? ?? 8b 40 14 83 ?? ?? 83 ?? ?? 8b 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 00 83 ?? ?? 83 ?? ?? 8b 40 10 83 ?? ?? }"
            },
            {
                "name": "$mutex_name",
                "type": "text",
                "value": "OPSEC_BERNHARD"
            },
            {
                "name": "$build_path",
                "type": "text",
                "value": "C:\\\\bernhard\\\\Debug\\\\bernhard.pdb"
            },
            {
                "name": "$string_decode_routine",
                "type": "byte",
                "value": "{ 55 8b ec 83 ec 50 53 56 57 a1 ?? ?? ?? ?? 89 45 f8 66 8b 0d ?? ?? ?? ?? 66 89 4d fc 8a 15 ?? ?? ?? ?? 88 55 fe 8d 45 f8 50 ff ?? ?? ?? ?? ?? 89 45 f0 c7 45 f4 00 00 00 00 ?? ?? 8b 45 f4 83 c0 01 89 45 f4 8b 45 08 50 ff ?? ?? ?? ?? ?? 39 45 f4 ?? ?? 8b 45 08 03 45 f4 0f be 08 8b 45 f4 99 f7 7d f0 0f be 54 15 f8 33 ca 8b 45 08 03 45 f4 88 08 ?? ?? 5f 5e 5b 8b e5 5d }"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'almashreq_agent_dotnet', '{almashreq_agent_dotnet}', '{"date": "2019-05-12", "author": "J from THL <j@techhelplist.com> with thx to @malwrhunterteam !!1!", "maltype": "agent", "filetype": "memory", "reference1": "https://twitter.com/JayTHL/status/1127334608142503936", "reference2": "https://www.virustotal.com/#/file/f6e1e425650abc6c0465758edf3c089a1dde5b9f58d26a50d3b8682cc38f12c8/details", "reference3": "https://www.virustotal.com/#/file/7e4231dc2bdab53f494b84bc13c6cb99478a6405405004c649478323ed5a9071/detection", "reference4": "https://www.virustotal.com/#/file/3cbaf6ddba3869ab68baf458afb25d2c8ba623153c43708bad2f312c4663161b/detection", "reference5": "https://www.virustotal.com/#/file/0f5424614b3519a340198dd82ad0abc9711a23c3283dc25b519affe5d2959a92/detection", "description": "Memory rule for a .net RAT/Agent first found with .pdb referencing almashreq"}', '[
    {
        "condition_terms": [
            "7",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Memory rule for a .net RAT/Agent first found with .pdb referencing almashreq"
            },
            {
                "author": "J from THL <j@techhelplist.com> with thx to @malwrhunterteam !!1!"
            },
            {
                "date": "2019-05-12"
            },
            {
                "reference1": "https://twitter.com/JayTHL/status/1127334608142503936"
            },
            {
                "reference2": "https://www.virustotal.com/#/file/f6e1e425650abc6c0465758edf3c089a1dde5b9f58d26a50d3b8682cc38f12c8/details"
            },
            {
                "reference3": "https://www.virustotal.com/#/file/7e4231dc2bdab53f494b84bc13c6cb99478a6405405004c649478323ed5a9071/detection"
            },
            {
                "reference4": "https://www.virustotal.com/#/file/3cbaf6ddba3869ab68baf458afb25d2c8ba623153c43708bad2f312c4663161b/detection"
            },
            {
                "reference5": "https://www.virustotal.com/#/file/0f5424614b3519a340198dd82ad0abc9711a23c3283dc25b519affe5d2959a92/detection"
            },
            {
                "maltype": "agent"
            },
            {
                "filetype": "memory"
            }
        ],
        "raw_condition": "condition: \n \t\t7 of them\n",
        "raw_meta": "meta:\n        description = \"Memory rule for a .net RAT/Agent first found with .pdb referencing almashreq\"\n\tauthor = \"J from THL <j@techhelplist.com> with thx to @malwrhunterteam !!1!\"\n        date = \"2019-05-12\"\n        reference1 = \"https://twitter.com/JayTHL/status/1127334608142503936\"\n        reference2 = \"https://www.virustotal.com/#/file/f6e1e425650abc6c0465758edf3c089a1dde5b9f58d26a50d3b8682cc38f12c8/details\"\n        reference3 = \"https://www.virustotal.com/#/file/7e4231dc2bdab53f494b84bc13c6cb99478a6405405004c649478323ed5a9071/detection\"\n        reference4 = \"https://www.virustotal.com/#/file/3cbaf6ddba3869ab68baf458afb25d2c8ba623153c43708bad2f312c4663161b/detection\"\n        reference5 = \"https://www.virustotal.com/#/file/0f5424614b3519a340198dd82ad0abc9711a23c3283dc25b519affe5d2959a92/detection\" \n        maltype = \"agent\"\n\tfiletype = \"memory\"\n\n    ",
        "raw_strings": "strings:\n        $s01 = \"WriteElementString(@\\\"PCName\\\",\" wide\n        $s02 = \"WriteElementString(@\\\"Command\\\",\" wide\n        $s03 = \"WriteElementStringRaw(@\\\"commandID\\\",\" wide\n\t$s04 = /^Try Run$/ wide\n        $s05 = \" is running in PC :\" wide\n        $s06 = \"SOAPAction: \\\"http://tempuri.org/Set\\\"\" wide\n        $s07 = \"Try Run</obj><name>\" wide\n        $s08 = \"Disable</obj><name>\" wide\n        $s09 = \"http://tempuri.org/\" wide\n\n \t",
        "rule_name": "almashreq_agent_dotnet",
        "start_line": 3,
        "stop_line": 30,
        "strings": [
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s01",
                "type": "text",
                "value": "WriteElementString(@\\\"PCName\\\","
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s02",
                "type": "text",
                "value": "WriteElementString(@\\\"Command\\\","
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s03",
                "type": "text",
                "value": "WriteElementStringRaw(@\\\"commandID\\\","
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s04",
                "type": "regex",
                "value": "/^Try Run$/"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s05",
                "type": "text",
                "value": " is running in PC :"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s06",
                "type": "text",
                "value": "SOAPAction: \\\"http://tempuri.org/Set\\\""
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s07",
                "type": "text",
                "value": "Try Run</obj><name>"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s08",
                "type": "text",
                "value": "Disable</obj><name>"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s09",
                "type": "text",
                "value": "http://tempuri.org/"
            }
        ],
        "tags": [
            "almashreq_agent_dotnet"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Erebus', '{ransom}', '{"MD5": "27d857e12b9be5d43f935b8cc86eaabf", "date": "2017-06-23", "ref1": "http://blog.trendmicro.com/trendlabs-security-intelligence/erebus-resurfaces-as-linux-ransomware/", "SHA256": "0b7996bca486575be15e68dba7cbd802b1e5f90436ba23f802da66292c8a055f", "author": "Joan Soriano / @joanbtl", "version": "1.0", "description": "Erebus Ransomware"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Erebus Ransomware"
            },
            {
                "author": "Joan Soriano / @joanbtl"
            },
            {
                "date": "2017-06-23"
            },
            {
                "version": "1.0"
            },
            {
                "MD5": "27d857e12b9be5d43f935b8cc86eaabf"
            },
            {
                "SHA256": "0b7996bca486575be15e68dba7cbd802b1e5f90436ba23f802da66292c8a055f"
            },
            {
                "ref1": "http://blog.trendmicro.com/trendlabs-security-intelligence/erebus-resurfaces-as-linux-ransomware/"
            }
        ],
        "raw_condition": "condition:\n\t\tall of them\n",
        "raw_meta": "meta:\n\t\tdescription = \"Erebus Ransomware\"\n\t\tauthor = \"Joan Soriano / @joanbtl\"\n\t\tdate = \"2017-06-23\"\n\t\tversion = \"1.0\"\n\t\tMD5 = \"27d857e12b9be5d43f935b8cc86eaabf\"\n\t\tSHA256 = \"0b7996bca486575be15e68dba7cbd802b1e5f90436ba23f802da66292c8a055f\"\n\t\tref1 = \"http://blog.trendmicro.com/trendlabs-security-intelligence/erebus-resurfaces-as-linux-ransomware/\"\n\t",
        "raw_strings": "strings:\n\t\t$a = \"/{5f58d6f0-bb9c-46e2-a4da-8ebc746f24a5}//log.log\"\n\t\t$b = \"EREBUS IS BEST.\"\n\t",
        "rule_name": "Erebus",
        "start_line": 1,
        "stop_line": 16,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "/{5f58d6f0-bb9c-46e2-a4da-8ebc746f24a5}//log.log"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "EREBUS IS BEST."
            }
        ],
        "tags": [
            "ransom"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'TreasureHunt', NULL, '{"ref": "http://www.minerva-labs.com/#!Cybercriminals-Adopt-the-Mossad-Emblem/c7a5/573da2d60cf2f90ca6f6e3ed", "date": "2016/06", "author": "Minerva Labs", "maltype": "Point of Sale (POS) Malware", "filetype": "exe"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Minerva Labs"
            },
            {
                "ref": "http://www.minerva-labs.com/#!Cybercriminals-Adopt-the-Mossad-Emblem/c7a5/573da2d60cf2f90ca6f6e3ed"
            },
            {
                "date": "2016/06"
            },
            {
                "maltype": "Point of Sale (POS) Malware"
            },
            {
                "filetype": "exe"
            }
        ],
        "raw_condition": "condition:\n      all of them\n",
        "raw_meta": "meta:\n      author = \"Minerva Labs\"\n      ref =\"http://www.minerva-labs.com/#!Cybercriminals-Adopt-the-Mossad-Emblem/c7a5/573da2d60cf2f90ca6f6e3ed\"\n      date = \"2016/06\"\n      maltype = \"Point of Sale (POS) Malware\"\n      filetype = \"exe\"\n\n    ",
        "raw_strings": "strings:\n      $a = \"treasureHunter.pdb\"\n      $b = \"jucheck\"\n      $c = \"cmdLineDecrypted\"\n\n    ",
        "rule_name": "TreasureHunt",
        "start_line": 6,
        "stop_line": 22,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "treasureHunter.pdb"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "jucheck"
            },
            {
                "name": "$c",
                "type": "text",
                "value": "cmdLineDecrypted"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Backdoored_ssh', NULL, '{"actor": "Energetic Bear/Crouching Yeti", "author": "Kaspersky", "reference": "https://securelist.com/energetic-bear-crouching-yeti/85345/"}', '[
    {
        "condition_terms": [
            "uint32",
            "(",
            "0",
            ")",
            "==",
            "0x464c457f",
            "and",
            "filesize",
            "<",
            "1000000",
            "and",
            "all",
            "of",
            "(",
            "$a*",
            ")"
        ],
        "metadata": [
            {
                "author": "Kaspersky"
            },
            {
                "reference": "https://securelist.com/energetic-bear-crouching-yeti/85345/"
            },
            {
                "actor": "Energetic Bear/Crouching Yeti"
            }
        ],
        "raw_condition": "condition:\nuint32(0) == 0x464c457f and filesize<1000000 and all of ($a*)\n",
        "raw_meta": "meta:\nauthor = \"Kaspersky\"\nreference = \"https://securelist.com/energetic-bear-crouching-yeti/85345/\"\nactor = \"Energetic Bear/Crouching Yeti\"\n",
        "raw_strings": "strings:\n$a1 = \"OpenSSH\"\n$a2 = \"usage: ssh\"\n$a3 = \"HISTFILE\"\n",
        "rule_name": "Backdoored_ssh",
        "start_line": 1,
        "stop_line": 12,
        "strings": [
            {
                "name": "$a1",
                "type": "text",
                "value": "OpenSSH"
            },
            {
                "name": "$a2",
                "type": "text",
                "value": "usage: ssh"
            },
            {
                "name": "$a3",
                "type": "text",
                "value": "HISTFILE"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Cobalt_functions', NULL, '{"url": "https://www.securityartwork.es/2017/06/16/analisis-del-powershell-usado-fin7/", "author": "@j0sm1", "description": "Detect functions coded with ROR edi,D; Detect CobaltStrike used by differents groups APT"}', '[
    {
        "condition_terms": [
            "2",
            "of",
            "(",
            "$h*",
            ")"
        ],
        "metadata": [
            {
                "author": "@j0sm1"
            },
            {
                "url": "https://www.securityartwork.es/2017/06/16/analisis-del-powershell-usado-fin7/"
            },
            {
                "description": "Detect functions coded with ROR edi,D; Detect CobaltStrike used by differents groups APT"
            }
        ],
        "raw_condition": "condition:\n        2 of ( $h* )\n",
        "raw_meta": "meta:\n\n        author=\"@j0sm1\"\n        url=\"https://www.securityartwork.es/2017/06/16/analisis-del-powershell-usado-fin7/\"\n        description=\"Detect functions coded with ROR edi,D; Detect CobaltStrike used by differents groups APT\"\n\n    ",
        "raw_strings": "strings:\n\n        $h1={58 A4 53 E5} // VirtualAllocEx\n        $h2={4C 77 26 07} // LoadLibraryEx\n        $h3={6A C9 9C C9} // DNSQuery_UTF8\n        $h4={44 F0 35 E0} // Sleep\n        $h5={F4 00 8E CC} // lstrlen\n\n    ",
        "rule_name": "Cobalt_functions",
        "start_line": 5,
        "stop_line": 24,
        "strings": [
            {
                "name": "$h1",
                "type": "byte",
                "value": "{58 A4 53 E5}"
            },
            {
                "name": "$h2",
                "type": "byte",
                "value": "{4C 77 26 07}"
            },
            {
                "name": "$h3",
                "type": "byte",
                "value": "{6A C9 9C C9}"
            },
            {
                "name": "$h4",
                "type": "byte",
                "value": "{44 F0 35 E0}"
            },
            {
                "name": "$h5",
                "type": "byte",
                "value": "{F4 00 8E CC}"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Adzok', '{binary,RAT,Adzok}', '{"ref": "http://malwareconfig.com/stats/Adzok", "date": "2015/05", "author": " Kevin Breen <kevin@techanarchy.net>", "maltype": "Remote Access Trojan", "Versions": "Free 1.0.0.3,", "filetype": "jar", "Description": "Adzok Rat"}', '[
    {
        "condition_terms": [
            "7",
            "of",
            "(",
            "$a*",
            ")"
        ],
        "metadata": [
            {
                "author": " Kevin Breen <kevin@techanarchy.net>"
            },
            {
                "Description": "Adzok Rat"
            },
            {
                "Versions": "Free 1.0.0.3,"
            },
            {
                "date": "2015/05"
            },
            {
                "ref": "http://malwareconfig.com/stats/Adzok"
            },
            {
                "maltype": "Remote Access Trojan"
            },
            {
                "filetype": "jar"
            }
        ],
        "raw_condition": "condition:\n    7 of ($a*)\n",
        "raw_meta": "meta:\n\t\tauthor = \" Kevin Breen <kevin@techanarchy.net>\"\n\t\tDescription = \"Adzok Rat\"\n\t\tVersions = \"Free 1.0.0.3,\"\n\t\tdate = \"2015/05\"\n\t\tref = \"http://malwareconfig.com/stats/Adzok\"\n\t\tmaltype = \"Remote Access Trojan\"\n\t\tfiletype = \"jar\"\n\n\t",
        "raw_strings": "strings:\n\t\t$a1 = \"config.xmlPK\"\n\t\t$a2 = \"key.classPK\"\n\t\t$a3 = \"svd$1.classPK\"\n\t\t$a4 = \"svd$2.classPK\"\n    \t$a5 = \"Mensaje.classPK\"\n\t\t$a6 = \"inic$ShutdownHook.class\"\n\t\t$a7 = \"Uninstall.jarPK\"\n\t\t$a8 = \"resources/icono.pngPK\"\n        \n\t",
        "rule_name": "Adzok",
        "start_line": 5,
        "stop_line": 28,
        "strings": [
            {
                "name": "$a1",
                "type": "text",
                "value": "config.xmlPK"
            },
            {
                "name": "$a2",
                "type": "text",
                "value": "key.classPK"
            },
            {
                "name": "$a3",
                "type": "text",
                "value": "svd$1.classPK"
            },
            {
                "name": "$a4",
                "type": "text",
                "value": "svd$2.classPK"
            },
            {
                "name": "$a5",
                "type": "text",
                "value": "Mensaje.classPK"
            },
            {
                "name": "$a6",
                "type": "text",
                "value": "inic$ShutdownHook.class"
            },
            {
                "name": "$a7",
                "type": "text",
                "value": "Uninstall.jarPK"
            },
            {
                "name": "$a8",
                "type": "text",
                "value": "resources/icono.pngPK"
            }
        ],
        "tags": [
            "binary",
            "RAT",
            "Adzok"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'sigma_ransomware', NULL, '{"date": "20180509", "author": "J from THL <j@techhelplist.com>", "maltype": "Ransomware", "version": 1, "filetype": "memory", "reference1": "https://www.virustotal.com/#/file/705ad78bf5503e6022f08da4c347afb47d4e740cfe6c39c08550c740c3be96ba", "reference2": "https://www.virustotal.com/#/file/bb3533440c27a115878ae541aba3bda02d441f3ea1864b868862255aabb0c8ff"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "J from THL <j@techhelplist.com>"
            },
            {
                "date": "20180509"
            },
            {
                "reference1": "https://www.virustotal.com/#/file/705ad78bf5503e6022f08da4c347afb47d4e740cfe6c39c08550c740c3be96ba"
            },
            {
                "reference2": "https://www.virustotal.com/#/file/bb3533440c27a115878ae541aba3bda02d441f3ea1864b868862255aabb0c8ff"
            },
            {
                "version": 1
            },
            {
                "maltype": "Ransomware"
            },
            {
                "filetype": "memory"
            }
        ],
        "raw_condition": "condition:\n    all of them\n",
        "raw_meta": "meta:\n    author = \"J from THL <j@techhelplist.com>\"\n    date = \"20180509\"\n    reference1 = \"https://www.virustotal.com/#/file/705ad78bf5503e6022f08da4c347afb47d4e740cfe6c39c08550c740c3be96ba\"\n    reference2 = \"https://www.virustotal.com/#/file/bb3533440c27a115878ae541aba3bda02d441f3ea1864b868862255aabb0c8ff\"\n    version = 1\n    maltype = \"Ransomware\"\n    filetype = \"memory\"\n\n  ",
        "raw_strings": "strings:\n    $a = \".php?\"\n    $b = \"uid=\"\n    $c = \"&uname=\"\n    $d = \"&os=\"\n    $e = \"&pcname=\"\n    $f = \"&total=\"\n    $g = \"&country=\"\n    $h = \"&network=\"\n    $i = \"&subid=\"\n\n  ",
        "rule_name": "sigma_ransomware",
        "start_line": 2,
        "stop_line": 26,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": ".php?"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "uid="
            },
            {
                "name": "$c",
                "type": "text",
                "value": "&uname="
            },
            {
                "name": "$d",
                "type": "text",
                "value": "&os="
            },
            {
                "name": "$e",
                "type": "text",
                "value": "&pcname="
            },
            {
                "name": "$f",
                "type": "text",
                "value": "&total="
            },
            {
                "name": "$g",
                "type": "text",
                "value": "&country="
            },
            {
                "name": "$h",
                "type": "text",
                "value": "&network="
            },
            {
                "name": "$i",
                "type": "text",
                "value": "&subid="
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'LinuxHelios', '{MALW}', '{"MD5": "1a35193f3761662a9a1bd38b66327f49", "date": "2017-10-19", "SHA256": "72c2e804f185bef777e854fe86cff3e86f00290f32ae8b3cb56deedf201f1719", "author": "Joan Soriano / @w0lfvan", "version": "1.0", "description": "Linux.Helios"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Linux.Helios"
            },
            {
                "author": "Joan Soriano / @w0lfvan"
            },
            {
                "date": "2017-10-19"
            },
            {
                "version": "1.0"
            },
            {
                "MD5": "1a35193f3761662a9a1bd38b66327f49"
            },
            {
                "SHA256": "72c2e804f185bef777e854fe86cff3e86f00290f32ae8b3cb56deedf201f1719"
            }
        ],
        "raw_condition": "condition:\n\t\tall of them\n",
        "raw_meta": "meta:\n\t\tdescription = \"Linux.Helios\"\n\t\tauthor = \"Joan Soriano / @w0lfvan\"\n\t\tdate = \"2017-10-19\"\n\t\tversion = \"1.0\"\n\t\tMD5 = \"1a35193f3761662a9a1bd38b66327f49\"\n\t\tSHA256 = \"72c2e804f185bef777e854fe86cff3e86f00290f32ae8b3cb56deedf201f1719\"\n\t",
        "raw_strings": "strings:\n\t\t$a = \"LIKE A GOD!!! IP:%s User:%s Pass:%s\"\n\t\t$b = \"smack\"\n\t\t$c = \"PEACE OUT IMMA DUP\\n\"\n\t",
        "rule_name": "LinuxHelios",
        "start_line": 1,
        "stop_line": 16,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "LIKE A GOD!!! IP:%s User:%s Pass:%s"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "smack"
            },
            {
                "name": "$c",
                "type": "text",
                "value": "PEACE OUT IMMA DUP\\n"
            }
        ],
        "tags": [
            "MALW"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'TROJAN_Notepad', NULL, '{"MD5": "106E63DBDA3A76BEEB53A8BBD8F98927", "Date": "4Jun13", "File": "notepad.exe v 1.1", "Author": "RSA_IR"}', '[
    {
        "condition_terms": [
            "$s1",
            "or",
            "$s2"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "Author": "RSA_IR"
            },
            {
                "Date": "4Jun13"
            },
            {
                "File": "notepad.exe v 1.1"
            },
            {
                "MD5": "106E63DBDA3A76BEEB53A8BBD8F98927"
            }
        ],
        "raw_condition": "condition:\n        $s1 or $s2\n",
        "raw_meta": "meta:\n        Author = \"RSA_IR\"\n        Date     = \"4Jun13\"\n        File     = \"notepad.exe v 1.1\"\n        MD5      = \"106E63DBDA3A76BEEB53A8BBD8F98927\"\n    ",
        "raw_strings": "strings:\n        $s1 = \"75BAA77C842BE168B0F66C42C7885997\"\n        $s2 = \"B523F63566F407F3834BCC54AAA32524\"\n    ",
        "rule_name": "TROJAN_Notepad",
        "start_line": 8,
        "stop_line": 19,
        "strings": [
            {
                "name": "$s1",
                "type": "text",
                "value": "75BAA77C842BE168B0F66C42C7885997"
            },
            {
                "name": "$s2",
                "type": "text",
                "value": "B523F63566F407F3834BCC54AAA32524"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Windows_Malware', '{Azorult_V2}', '{"date": "2017-09-30", "author": "Xylitol xylitol@temari.fr", "reference": "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=4819&p=30867", "description": "Match first two bytes, strings, and parts of routines present in Azorult"}', '[
    {
        "comments": [
            "// May only the challenge guide you"
        ],
        "condition_terms": [
            "(",
            "$mz",
            "at",
            "0",
            "and",
            "all",
            "of",
            "(",
            "$string*",
            ")",
            "and",
            "(",
            "$constant1",
            "or",
            "$constant2",
            ")",
            "or",
            "cuckoo.sync.mutex",
            "(",
            "/Ad48qw4d6wq84d56as|Adkhvhhydhasdasashbc/",
            ")",
            ")"
        ],
        "imports": [
            "cuckoo"
        ],
        "metadata": [
            {
                "author": "Xylitol xylitol@temari.fr"
            },
            {
                "date": "2017-09-30"
            },
            {
                "description": "Match first two bytes, strings, and parts of routines present in Azorult"
            },
            {
                "reference": "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=4819&p=30867"
            }
        ],
        "raw_condition": "condition:\n                    ($mz at 0 and all of ($string*) and ($constant1 or $constant2) or cuckoo.sync.mutex(/Ad48qw4d6wq84d56as|Adkhvhhydhasdasashbc/))\n    ",
        "raw_meta": "meta:\n                    author = \"Xylitol xylitol@temari.fr\"\n                    date = \"2017-09-30\"\n                    description = \"Match first two bytes, strings, and parts of routines present in Azorult\"\n                    reference = \"http://www.kernelmode.info/forum/viewtopic.php?f=16&t=4819&p=30867\"\n                    // May only the challenge guide you\n            ",
        "raw_strings": "strings:\n                    $mz = {4D 5A}\n                    $string1 = \"ST234LMUV56CklAopq78Brstuvwxyz01NOPQRmGHIJKWXYZabcdefgDEFhijn9+/\" wide ascii // Azorult custom base64-like alphabet\n                    $string2 = \"SYSInfo.txt\"\n                    $string3 = \"CookieList.txt\"\n                    $string4 = \"Passwords.txt\"\n                    $constant1 = {85 C0 74 40 85 D2 74 31 53 56 57 89 C6 89 D7 8B 4F FC 57} // Azorult grabs .txt and .dat files from Desktop\n                    $constant2 = {68 ?? ?? ?? ?? FF 75 FC 68 ?? ?? ?? ?? 8D 45 F8 BA 03 00} // Portion of code from Azorult self-delete function\n            ",
        "rule_name": "Windows_Malware",
        "start_line": 6,
        "stop_line": 24,
        "strings": [
            {
                "name": "$mz",
                "type": "byte",
                "value": "{4D 5A}"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$string1",
                "type": "text",
                "value": "ST234LMUV56CklAopq78Brstuvwxyz01NOPQRmGHIJKWXYZabcdefgDEFhijn9+/"
            },
            {
                "name": "$string2",
                "type": "text",
                "value": "SYSInfo.txt"
            },
            {
                "name": "$string3",
                "type": "text",
                "value": "CookieList.txt"
            },
            {
                "name": "$string4",
                "type": "text",
                "value": "Passwords.txt"
            },
            {
                "name": "$constant1",
                "type": "byte",
                "value": "{85 C0 74 40 85 D2 74 31 53 56 57 89 C6 89 D7 8B 4F FC 57}"
            },
            {
                "name": "$constant2",
                "type": "byte",
                "value": "{68 ?? ?? ?? ?? FF 75 FC 68 ?? ?? ?? ?? 8D 45 F8 BA 03 00}"
            }
        ],
        "tags": [
            "Azorult_V2"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'xRAT20', '{RAT}', '{"date": "2015-08-20", "hash0": "cda610f9cba6b6242ebce9f31faf5d9c", "hash1": "60d7b0d2dfe937ac6478807aa7043525", "hash2": "d1b577fbfd25cc5b873b202cfe61b5b8", "hash3": "1820fa722906569e3f209d1dab3d1360", "hash4": "8993b85f5c138b0afacc3ff04a2d7871", "hash5": "0c231ed8a800b0f17f897241f1d5f4e3", "hash8": "2c198e3e0e299a51e5d955bb83c62a5e", "author": "Rottweiler", "maltype": "Remote Access Trojan", "description": "Identifies xRAT 2.0 samples", "yaragenerator": "https://github.com/Xen0ph0n/YaraGenerator", "sample_filetype": "exe"}', '[
    {
        "condition_terms": [
            "18",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Rottweiler"
            },
            {
                "date": "2015-08-20"
            },
            {
                "description": "Identifies xRAT 2.0 samples"
            },
            {
                "maltype": "Remote Access Trojan"
            },
            {
                "hash0": "cda610f9cba6b6242ebce9f31faf5d9c"
            },
            {
                "hash1": "60d7b0d2dfe937ac6478807aa7043525"
            },
            {
                "hash2": "d1b577fbfd25cc5b873b202cfe61b5b8"
            },
            {
                "hash3": "1820fa722906569e3f209d1dab3d1360"
            },
            {
                "hash4": "8993b85f5c138b0afacc3ff04a2d7871"
            },
            {
                "hash5": "0c231ed8a800b0f17f897241f1d5f4e3"
            },
            {
                "hash1": "60d7b0d2dfe937ac6478807aa7043525"
            },
            {
                "hash8": "2c198e3e0e299a51e5d955bb83c62a5e"
            },
            {
                "sample_filetype": "exe"
            },
            {
                "yaragenerator": "https://github.com/Xen0ph0n/YaraGenerator"
            }
        ],
        "raw_condition": "condition:\n\t18 of them\n",
        "raw_meta": "meta:\n\tauthor = \"Rottweiler\"\n\tdate = \"2015-08-20\"\n\tdescription = \"Identifies xRAT 2.0 samples\"\n\tmaltype = \"Remote Access Trojan\"\n\thash0 = \"cda610f9cba6b6242ebce9f31faf5d9c\"\n\thash1 = \"60d7b0d2dfe937ac6478807aa7043525\"\n\thash2 = \"d1b577fbfd25cc5b873b202cfe61b5b8\"\n\thash3 = \"1820fa722906569e3f209d1dab3d1360\"\n\thash4 = \"8993b85f5c138b0afacc3ff04a2d7871\"\n\thash5 = \"0c231ed8a800b0f17f897241f1d5f4e3\"\n\thash1 = \"60d7b0d2dfe937ac6478807aa7043525\"\n\thash8 = \"2c198e3e0e299a51e5d955bb83c62a5e\"\n\tsample_filetype = \"exe\"\n\tyaragenerator = \"https://github.com/Xen0ph0n/YaraGenerator\"\n",
        "raw_strings": "strings:\n\t$string0 = \"GetDirectory: File not found\" wide\n\t$string1 = \"<>m__Finally8\"\n\t$string2 = \"Secure\"\n\t$string3 = \"ReverseProxyClient\"\n\t$string4 = \"DriveDisplayName\"\n\t$string5 = \"<IsError>k__BackingField\"\n\t$string6 = \"set_InstallPath\"\n\t$string7 = \"memcmp\"\n\t$string8 = \"urlHistory\"\n\t$string9 = \"set_AllowAutoRedirect\"\n\t$string10 = \"lpInitData\"\n\t$string11 = \"reader\"\n\t$string12 = \"<FromRawDataGlobal>d__f\"\n\t$string13 = \"mq.png\" wide\n\t$string14 = \"remove_KeyDown\"\n\t$string15 = \"ProtectedData\"\n\t$string16 = \"m_hotkeys\"\n\t$string17 = \"get_Hour\"\n\t$string18 = \"\\\\mozglue.dll\" wide\n",
        "rule_name": "xRAT20",
        "start_line": 5,
        "stop_line": 44,
        "strings": [
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$string0",
                "type": "text",
                "value": "GetDirectory: File not found"
            },
            {
                "name": "$string1",
                "type": "text",
                "value": "<>m__Finally8"
            },
            {
                "name": "$string2",
                "type": "text",
                "value": "Secure"
            },
            {
                "name": "$string3",
                "type": "text",
                "value": "ReverseProxyClient"
            },
            {
                "name": "$string4",
                "type": "text",
                "value": "DriveDisplayName"
            },
            {
                "name": "$string5",
                "type": "text",
                "value": "<IsError>k__BackingField"
            },
            {
                "name": "$string6",
                "type": "text",
                "value": "set_InstallPath"
            },
            {
                "name": "$string7",
                "type": "text",
                "value": "memcmp"
            },
            {
                "name": "$string8",
                "type": "text",
                "value": "urlHistory"
            },
            {
                "name": "$string9",
                "type": "text",
                "value": "set_AllowAutoRedirect"
            },
            {
                "name": "$string10",
                "type": "text",
                "value": "lpInitData"
            },
            {
                "name": "$string11",
                "type": "text",
                "value": "reader"
            },
            {
                "name": "$string12",
                "type": "text",
                "value": "<FromRawDataGlobal>d__f"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$string13",
                "type": "text",
                "value": "mq.png"
            },
            {
                "name": "$string14",
                "type": "text",
                "value": "remove_KeyDown"
            },
            {
                "name": "$string15",
                "type": "text",
                "value": "ProtectedData"
            },
            {
                "name": "$string16",
                "type": "text",
                "value": "m_hotkeys"
            },
            {
                "name": "$string17",
                "type": "text",
                "value": "get_Hour"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$string18",
                "type": "text",
                "value": "\\\\mozglue.dll"
            }
        ],
        "tags": [
            "RAT"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'TeslaCrypt', NULL, '{"author": "CCN-CERT", "version": "1.0", "description": "Regla para detectar Tesla con md5"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Regla para detectar Tesla con md5"
            },
            {
                "author": "CCN-CERT"
            },
            {
                "version": "1.0"
            }
        ],
        "raw_condition": "condition:\n    all of them\n",
        "raw_meta": "meta:\n    description = \"Regla para detectar Tesla con md5\"\n    author = \"CCN-CERT\"\n    version = \"1.0\"\n",
        "raw_strings": "strings:\n    $ = { 4E 6F 77 20 69 74 27 73 20 25 49 3A 25 4D 25 70 2E 00 00 00 76 61 6C 20 69 73 20 25 64 0A 00 00 }\n",
        "rule_name": "TeslaCrypt",
        "start_line": 6,
        "stop_line": 15,
        "strings": [
            {
                "name": "$",
                "type": "byte",
                "value": "{ 4E 6F 77 20 69 74 27 73 20 25 49 3A 25 4D 25 70 2E 00 00 00 76 61 6C 20 69 73 20 25 64 0A 00 00 }"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Backdoor_Jolob', NULL, '{"ref": "https://github.com/reed1713", "maltype": "Backdoor.Jolob", "reference": "http://www.symantec.com/connect/blogs/new-flash-zero-day-linked-yet-more-watering-hole-attacks", "description": "the backdoor registers an auto start service with the display name \\\"Network Access Management Agent\\\" pointing to the dll netfilter.dll. This is accomplished without notifying the user via the sysprep UAC bypass method."}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "maltype": "Backdoor.Jolob"
            },
            {
                "ref": "https://github.com/reed1713"
            },
            {
                "reference": "http://www.symantec.com/connect/blogs/new-flash-zero-day-linked-yet-more-watering-hole-attacks"
            },
            {
                "description": "the backdoor registers an auto start service with the display name \\\"Network Access Management Agent\\\" pointing to the dll netfilter.dll. This is accomplished without notifying the user via the sysprep UAC bypass method."
            }
        ],
        "raw_condition": "condition:\n    \tall of them\n",
        "raw_meta": "meta:\n\t\tmaltype = \"Backdoor.Jolob\"\n    ref = \"https://github.com/reed1713\"\n\t\treference = \"http://www.symantec.com/connect/blogs/new-flash-zero-day-linked-yet-more-watering-hole-attacks\"\n\t\tdescription = \"the backdoor registers an auto start service with the display name \\\"Network Access Management Agent\\\" pointing to the dll netfilter.dll. This is accomplished without notifying the user via the sysprep UAC bypass method.\"\n\t",
        "raw_strings": "strings:   \n\t\t$type = \"Microsoft-Windows-Security-Auditing\"\n\t\t$eventid = \"4673\"\n\t\t$data1 = \"Security\"\n\t\t$data2 = \"SeCreateGlobalPrivilege\"\n\t\t$data3 = \"Windows\\\\System32\\\\sysprep\\\\sysprep.exe\" nocase\n        \n\t\t$type1 = \"Microsoft-Windows-Security-Auditing\"\n\t\t$eventid1 = \"4688\"\n\t\t$data4 = \"Windows\\\\System32\\\\sysprep\\\\sysprep.exe\" nocase\n        \n\t\t$type2 = \"Service Control Manager\"\n\t\t$eventid2 = \"7036\"\n\t\t$data5 = \"Network Access Management Agent\"\n\t\t$data6 = \"running\"\n        \n\t\t$type3 = \"Service Control Manager\"\n\t\t$eventid3 = \"7045\"\n\t\t$data7 = \"Network Access Management Agent\"\n\t\t$data8 = \"user mode service\"\n\t\t$data9 = \"auto start\"      \n    ",
        "rule_name": "Backdoor_Jolob",
        "start_line": 1,
        "stop_line": 31,
        "strings": [
            {
                "name": "$type",
                "type": "text",
                "value": "Microsoft-Windows-Security-Auditing"
            },
            {
                "name": "$eventid",
                "type": "text",
                "value": "4673"
            },
            {
                "name": "$data1",
                "type": "text",
                "value": "Security"
            },
            {
                "name": "$data2",
                "type": "text",
                "value": "SeCreateGlobalPrivilege"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$data3",
                "type": "text",
                "value": "Windows\\\\System32\\\\sysprep\\\\sysprep.exe"
            },
            {
                "name": "$type1",
                "type": "text",
                "value": "Microsoft-Windows-Security-Auditing"
            },
            {
                "name": "$eventid1",
                "type": "text",
                "value": "4688"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$data4",
                "type": "text",
                "value": "Windows\\\\System32\\\\sysprep\\\\sysprep.exe"
            },
            {
                "name": "$type2",
                "type": "text",
                "value": "Service Control Manager"
            },
            {
                "name": "$eventid2",
                "type": "text",
                "value": "7036"
            },
            {
                "name": "$data5",
                "type": "text",
                "value": "Network Access Management Agent"
            },
            {
                "name": "$data6",
                "type": "text",
                "value": "running"
            },
            {
                "name": "$type3",
                "type": "text",
                "value": "Service Control Manager"
            },
            {
                "name": "$eventid3",
                "type": "text",
                "value": "7045"
            },
            {
                "name": "$data7",
                "type": "text",
                "value": "Network Access Management Agent"
            },
            {
                "name": "$data8",
                "type": "text",
                "value": "user mode service"
            },
            {
                "name": "$data9",
                "type": "text",
                "value": "auto start"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'SNOWGLOBE_Babar_Malware', NULL, '{"date": "2015/02/18", "hash": "27a0a98053f3eed82a51cdefbdfec7bb948e1f36", "score": 80, "author": "Florian Roth", "reference": "http://motherboard.vice.com/read/meet-babar-a-new-malware-almost-certainly-created-by-france", "description": "Detects the Babar Malware used in the SNOWGLOBE attacks - file babar.exe"}', '[
    {
        "condition_terms": [
            "(",
            "$mz",
            "at",
            "0",
            ")",
            "and",
            "filesize",
            "<",
            "1MB",
            "and",
            "(",
            "(",
            "1",
            "of",
            "(",
            "$z*",
            ")",
            "and",
            "1",
            "of",
            "(",
            "$x*",
            ")",
            ")",
            "or",
            "(",
            "3",
            "of",
            "(",
            "$s*",
            ")",
            "and",
            "4",
            "of",
            "(",
            "$x*",
            ")",
            ")",
            ")"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "description": "Detects the Babar Malware used in the SNOWGLOBE attacks - file babar.exe"
            },
            {
                "author": "Florian Roth"
            },
            {
                "reference": "http://motherboard.vice.com/read/meet-babar-a-new-malware-almost-certainly-created-by-france"
            },
            {
                "date": "2015/02/18"
            },
            {
                "hash": "27a0a98053f3eed82a51cdefbdfec7bb948e1f36"
            },
            {
                "score": 80
            }
        ],
        "raw_condition": "condition:\n        ( $mz at 0 ) and filesize < 1MB and (( 1 of ($z*) and 1 of ($x*) ) or ( 3 of ($s*) and 4 of ($x*) ) )\n",
        "raw_meta": "meta:\n        description = \"Detects the Babar Malware used in the SNOWGLOBE attacks - file babar.exe\"\n        author = \"Florian Roth\"\n        reference = \"http://motherboard.vice.com/read/meet-babar-a-new-malware-almost-certainly-created-by-france\"\n        date = \"2015/02/18\"\n        hash = \"27a0a98053f3eed82a51cdefbdfec7bb948e1f36\"\n        score = 80\n\n    ",
        "raw_strings": "strings:\n        $mz = { 4d 5a }\n        $z0 = \"admin\\\\Desktop\\\\Babar64\\\\Babar64\\\\obj\\\\DllWrapper\" ascii fullword\n        $z1 = \"User-Agent: Mozilla/4.0 (compatible; MSI 6.0;\" ascii fullword\n        $z2 = \"ExecQueryFailled!\" fullword ascii\n        $z3 = \"NBOT_COMMAND_LINE\" fullword\n        $z4 = \"!!!EXTRACT ERROR!!!File Does Not Exists-->[%s]\" fullword\n        $s1 = \"/s /n %s \\\"%s\\\"\" fullword ascii\n        $s2 = \"%%WINDIR%%\\\\%s\\\\%s\" fullword ascii\n        $s3 = \"/c start /wait \" fullword ascii\n        $s4 = \"(D;OICI;FA;;;AN)(A;OICI;FA;;;BG)(A;OICI;FA;;;SY)(A;OICI;FA;;;LS)\" ascii\n        $x1 = \"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System\\\\\" fullword ascii\n        $x2 = \"%COMMON_APPDATA%\" fullword ascii\n        $x4 = \"CONOUT$\" fullword ascii\n        $x5 = \"cmd.exe\" fullword ascii\n        $x6 = \"DLLPATH\" fullword ascii\n    \n    ",
        "rule_name": "SNOWGLOBE_Babar_Malware",
        "start_line": 8,
        "stop_line": 38,
        "strings": [
            {
                "name": "$mz",
                "type": "byte",
                "value": "{ 4d 5a }"
            },
            {
                "modifiers": [
                    "ascii",
                    "fullword"
                ],
                "name": "$z0",
                "type": "text",
                "value": "admin\\\\Desktop\\\\Babar64\\\\Babar64\\\\obj\\\\DllWrapper"
            },
            {
                "modifiers": [
                    "ascii",
                    "fullword"
                ],
                "name": "$z1",
                "type": "text",
                "value": "User-Agent: Mozilla/4.0 (compatible; MSI 6.0;"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$z2",
                "type": "text",
                "value": "ExecQueryFailled!"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$z3",
                "type": "text",
                "value": "NBOT_COMMAND_LINE"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$z4",
                "type": "text",
                "value": "!!!EXTRACT ERROR!!!File Does Not Exists-->[%s]"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "/s /n %s \\\"%s\\\""
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s2",
                "type": "text",
                "value": "%%WINDIR%%\\\\%s\\\\%s"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s3",
                "type": "text",
                "value": "/c start /wait "
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$s4",
                "type": "text",
                "value": "(D;OICI;FA;;;AN)(A;OICI;FA;;;BG)(A;OICI;FA;;;SY)(A;OICI;FA;;;LS)"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$x1",
                "type": "text",
                "value": "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System\\\\"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$x2",
                "type": "text",
                "value": "%COMMON_APPDATA%"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$x4",
                "type": "text",
                "value": "CONOUT$"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$x5",
                "type": "text",
                "value": "cmd.exe"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$x6",
                "type": "text",
                "value": "DLLPATH"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Win32_Buzus_Softpulse', NULL, '{"date": "2015-05-13", "hash": "2f6df200e63a86768471399a74180466d2e99ea9", "score": 75, "author": "Florian Roth", "description": "Trojan Buzus / Softpulse"}', '[
    {
        "condition_terms": [
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "(",
            "(",
            "$x1",
            "and",
            "2",
            "of",
            "(",
            "$s*",
            ")",
            ")",
            "or",
            "all",
            "of",
            "(",
            "$s*",
            ")",
            ")"
        ],
        "metadata": [
            {
                "description": "Trojan Buzus / Softpulse"
            },
            {
                "author": "Florian Roth"
            },
            {
                "date": "2015-05-13"
            },
            {
                "hash": "2f6df200e63a86768471399a74180466d2e99ea9"
            },
            {
                "score": 75
            }
        ],
        "raw_condition": "condition:\n        uint16(0) == 0x5a4d and ( ( $x1 and 2 of ($s*) ) or all of ($s*) )\n",
        "raw_meta": "meta:\n        description = \"Trojan Buzus / Softpulse\"\n        author = \"Florian Roth\"\n        date = \"2015-05-13\"\n        hash = \"2f6df200e63a86768471399a74180466d2e99ea9\"\n        score = 75\n\n    ",
        "raw_strings": "strings:\n        $x1 = \"pi4izd6vp0.com\" fullword ascii\n        $s1 = \"SELECT * FROM Win32_Process\" fullword wide\n        $s4 = \"CurrentVersion\\\\Uninstall\\\\avast\" fullword wide\n        $s5 = \"Find_RepeatProcess\" fullword ascii\n        $s6 = \"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\\" fullword wide\n        $s7 = \"myapp.exe\" fullword ascii\n        $s14 = \"/c ping -n 1 www.google\" wide\n    \n    ",
        "rule_name": "Win32_Buzus_Softpulse",
        "start_line": 6,
        "stop_line": 27,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$x1",
                "type": "text",
                "value": "pi4izd6vp0.com"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s1",
                "type": "text",
                "value": "SELECT * FROM Win32_Process"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s4",
                "type": "text",
                "value": "CurrentVersion\\\\Uninstall\\\\avast"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s5",
                "type": "text",
                "value": "Find_RepeatProcess"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s6",
                "type": "text",
                "value": "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s7",
                "type": "text",
                "value": "myapp.exe"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s14",
                "type": "text",
                "value": "/c ping -n 1 www.google"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'IotReaper', '{MALW}', '{"MD5": "95b448bdf6b6c97a33e1d1dbe41678eb", "date": "2017-10-30", "SHA256": "b463ca6c3ec7fa19cd318afdd2fa2365fa9e947771c21c4bd6a3bc2120ba7f28", "author": "Joan Soriano / @w0lfvan", "version": "1.0", "description": "Linux.IotReaper"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Linux.IotReaper"
            },
            {
                "author": "Joan Soriano / @w0lfvan"
            },
            {
                "date": "2017-10-30"
            },
            {
                "version": "1.0"
            },
            {
                "MD5": "95b448bdf6b6c97a33e1d1dbe41678eb"
            },
            {
                "SHA256": "b463ca6c3ec7fa19cd318afdd2fa2365fa9e947771c21c4bd6a3bc2120ba7f28"
            }
        ],
        "raw_condition": "condition:\n\t\tall of them\n",
        "raw_meta": "meta:\n\t\tdescription = \"Linux.IotReaper\"\n\t\tauthor = \"Joan Soriano / @w0lfvan\"\n\t\tdate = \"2017-10-30\"\n\t\tversion = \"1.0\"\n\t\tMD5 = \"95b448bdf6b6c97a33e1d1dbe41678eb\"\n\t\tSHA256 = \"b463ca6c3ec7fa19cd318afdd2fa2365fa9e947771c21c4bd6a3bc2120ba7f28\"\n\t",
        "raw_strings": "strings:\n\t\t$a = \"weruuoqweiur.com\"\n\t\t$b = \"rm -f /tmp/ftpupload.sh \\n\"\n\t\t$c = \"%02x-%02x-%02x-%02x-%02x-%02x\"\n\t",
        "rule_name": "IotReaper",
        "start_line": 1,
        "stop_line": 16,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "weruuoqweiur.com"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "rm -f /tmp/ftpupload.sh \\n"
            },
            {
                "name": "$c",
                "type": "text",
                "value": "%02x-%02x-%02x-%02x-%02x-%02x"
            }
        ],
        "tags": [
            "MALW"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'pico_ransomware', NULL, '{"author": "Marc Rivero | @seifreed", "reference": "https://twitter.com/siri_urz/status/1035138577934557184", "description": "Rule to detect Pico Ransomware"}', '[
    {
        "condition_terms": [
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "filesize",
            "<",
            "700KB",
            ")",
            "and",
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Rule to detect Pico Ransomware"
            },
            {
                "author": "Marc Rivero | @seifreed"
            },
            {
                "reference": "https://twitter.com/siri_urz/status/1035138577934557184"
            }
        ],
        "raw_condition": "condition:\n      ( uint16(0) == 0x5a4d and filesize < 700KB ) and all of them\n",
        "raw_meta": "meta:\n   \n      description = \"Rule to detect Pico Ransomware\"\n      author = \"Marc Rivero | @seifreed\"\n      reference = \"https://twitter.com/siri_urz/status/1035138577934557184\"\n      \n   ",
        "raw_strings": "strings:\n\n      $s1 = \"C:\\\\Users\\\\rikfe\\\\Desktop\\\\Ransomware\\\\ThanatosSource\\\\Release\\\\Ransomware.pdb\" fullword ascii\n      $s2 = \"\\\\Downloads\\\\README.txt\" fullword ascii\n      $s3 = \"\\\\Music\\\\README.txt\" fullword ascii\n      $s4 = \"\\\\Videos\\\\README.txt\" fullword ascii\n      $s5 = \"\\\\Pictures\\\\README.txt\" fullword ascii\n      $s6 = \"\\\\Desktop\\\\README.txt\" fullword ascii\n      $s7 = \"\\\\Documents\\\\README.txt\" fullword ascii\n      $s8 = \"/c taskkill /im \" fullword ascii\n      $s9 = \"\\\\AppData\\\\Roaming\\\\\" fullword ascii\n      $s10 = \"gMozilla/5.0 (Windows NT 6.1) Thanatos/1.1\" fullword wide\n      $s11 = \"AppData\\\\Roaming\" fullword ascii\n      $s12 = \"\\\\Downloads\" fullword ascii\n      $s13 = \"operator co_await\" fullword ascii\n   \n   ",
        "rule_name": "pico_ransomware",
        "start_line": 1,
        "stop_line": 27,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "C:\\\\Users\\\\rikfe\\\\Desktop\\\\Ransomware\\\\ThanatosSource\\\\Release\\\\Ransomware.pdb"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s2",
                "type": "text",
                "value": "\\\\Downloads\\\\README.txt"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s3",
                "type": "text",
                "value": "\\\\Music\\\\README.txt"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s4",
                "type": "text",
                "value": "\\\\Videos\\\\README.txt"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s5",
                "type": "text",
                "value": "\\\\Pictures\\\\README.txt"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s6",
                "type": "text",
                "value": "\\\\Desktop\\\\README.txt"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s7",
                "type": "text",
                "value": "\\\\Documents\\\\README.txt"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s8",
                "type": "text",
                "value": "/c taskkill /im "
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s9",
                "type": "text",
                "value": "\\\\AppData\\\\Roaming\\\\"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s10",
                "type": "text",
                "value": "gMozilla/5.0 (Windows NT 6.1) Thanatos/1.1"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s11",
                "type": "text",
                "value": "AppData\\\\Roaming"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s12",
                "type": "text",
                "value": "\\\\Downloads"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s13",
                "type": "text",
                "value": "operator co_await"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Emotets', NULL, '{"date": "2017-10-18", "author": "pekeinfo", "description": "Emotets"}', '[
    {
        "condition_terms": [
            "(",
            "$mz",
            "at",
            "0",
            "and",
            "$_eax",
            "in",
            "(",
            "0x2854",
            "..",
            "0x4000",
            ")",
            ")",
            "and",
            "(",
            "$cmovnz",
            "or",
            "$mov_esp_0",
            ")"
        ],
        "metadata": [
            {
                "author": "pekeinfo"
            },
            {
                "date": "2017-10-18"
            },
            {
                "description": "Emotets"
            }
        ],
        "raw_condition": "condition:\n  ($mz at 0 and $_eax in( 0x2854..0x4000)) and ($cmovnz or $mov_esp_0)\n",
        "raw_meta": "meta:\n  author = \"pekeinfo\"\n  date = \"2017-10-18\"\n  description = \"Emotets\"\n",
        "raw_strings": "strings:\n  $mz = { 4d 5a }\n  $cmovnz={ 0f 45 fb 0f 45 de }\n  $mov_esp_0={ C7 04 24 00 00 00 00 89 44 24 0? }\n  $_eax={ 89 E? 8D ?? 24 ?? 89 ?? FF D0 83 EC 04 }\n",
        "rule_name": "Emotets",
        "start_line": 6,
        "stop_line": 18,
        "strings": [
            {
                "name": "$mz",
                "type": "byte",
                "value": "{ 4d 5a }"
            },
            {
                "name": "$cmovnz",
                "type": "byte",
                "value": "{ 0f 45 fb 0f 45 de }"
            },
            {
                "name": "$mov_esp_0",
                "type": "byte",
                "value": "{ C7 04 24 00 00 00 00 89 44 24 0? }"
            },
            {
                "name": "$_eax",
                "type": "byte",
                "value": "{ 89 E? 8D ?? 24 ?? 89 ?? FF D0 83 EC 04 }"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'glassrat', '{RAT}', '{"author": "Brian Wallace @botnet_hunter"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Brian Wallace @botnet_hunter"
            }
        ],
        "raw_condition": "condition:\n    \tall of them\n\n",
        "raw_meta": "meta:\n        author = \"Brian Wallace @botnet_hunter\"\n   ",
        "raw_strings": "strings:\n    \t$a = \"PostQuitMessage\"\n        $b = \"pwlfnn10,gzg\"\n        $c = \"update.dll\"\n        $d = \"_winver\"\n   ",
        "rule_name": "glassrat",
        "start_line": 5,
        "stop_line": 17,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "PostQuitMessage"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "pwlfnn10,gzg"
            },
            {
                "name": "$c",
                "type": "text",
                "value": "update.dll"
            },
            {
                "name": "$d",
                "type": "text",
                "value": "_winver"
            }
        ],
        "tags": [
            "RAT"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Maze', NULL, '{"tlp": "White", "date": "2019-11", "author": "@bartblaze", "description": "Identifies Maze ransomware in memory or unpacked."}', '[
    {
        "condition_terms": [
            "5",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Identifies Maze ransomware in memory or unpacked."
            },
            {
                "author": "@bartblaze"
            },
            {
                "date": "2019-11"
            },
            {
                "tlp": "White"
            }
        ],
        "raw_condition": "condition:\n\t5 of them\n",
        "raw_meta": "meta:\n\tdescription = \"Identifies Maze ransomware in memory or unpacked.\"\n\tauthor = \"@bartblaze\"\n\tdate = \"2019-11\"\n\ttlp = \"White\"\n\n",
        "raw_strings": "strings:\t\n\t$ = \"Enc: %s\" ascii wide\n\t$ = \"Encrypting whole system\" ascii wide\n\t$ = \"Encrypting specified folder in --path parameter...\" ascii wide\n\t$ = \"!Finished in %d ms!\" ascii wide\n\t$ = \"--logging\" ascii wide\n\t$ = \"--nomutex\" ascii wide\n\t$ = \"--noshares\" ascii wide\n\t$ = \"--path\" ascii wide\n\t$ = \"Logging enabled | Maze\" ascii wide\n\t$ = \"NO SHARES | \" ascii wide\n\t$ = \"NO MUTEX | \" ascii wide\n\t$ = \"Encrypting:\" ascii wide\n\t$ = \"You need to buy decryptor in order to restore the files.\" ascii wide\n\t$ = \"Dear %s, your files have been encrypted by RSA-2048 and ChaCha algorithms\" ascii wide\n\t$ = \"%s! Alert! %s! Alert! Dear %s Your files have been encrypted by %s! Attention! %s\" ascii wide\n\t$ = \"DECRYPT-FILES.txt\" ascii wide fullword\n\n",
        "rule_name": "Maze",
        "start_line": 1,
        "stop_line": 29,
        "strings": [
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$",
                "type": "text",
                "value": "Enc: %s"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$",
                "type": "text",
                "value": "Encrypting whole system"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$",
                "type": "text",
                "value": "Encrypting specified folder in --path parameter..."
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$",
                "type": "text",
                "value": "!Finished in %d ms!"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$",
                "type": "text",
                "value": "--logging"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$",
                "type": "text",
                "value": "--nomutex"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$",
                "type": "text",
                "value": "--noshares"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$",
                "type": "text",
                "value": "--path"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$",
                "type": "text",
                "value": "Logging enabled | Maze"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$",
                "type": "text",
                "value": "NO SHARES | "
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$",
                "type": "text",
                "value": "NO MUTEX | "
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$",
                "type": "text",
                "value": "Encrypting:"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$",
                "type": "text",
                "value": "You need to buy decryptor in order to restore the files."
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$",
                "type": "text",
                "value": "Dear %s, your files have been encrypted by RSA-2048 and ChaCha algorithms"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$",
                "type": "text",
                "value": "%s! Alert! %s! Alert! Dear %s Your files have been encrypted by %s! Attention! %s"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide",
                    "fullword"
                ],
                "name": "$",
                "type": "text",
                "value": "DECRYPT-FILES.txt"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'PE_File_pyinstaller', NULL, '{"author": "Didier Stevens (https://DidierStevens.com)", "reference": "https://isc.sans.edu/diary/21057", "description": "Detect PE file produced by pyinstaller"}', '[
    {
        "condition_terms": [
            "pe.number_of_resources",
            ">",
            "0",
            "and",
            "$a"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "Didier Stevens (https://DidierStevens.com)"
            },
            {
                "description": "Detect PE file produced by pyinstaller"
            },
            {
                "reference": "https://isc.sans.edu/diary/21057"
            }
        ],
        "raw_condition": "condition:\n        pe.number_of_resources > 0 and $a\n",
        "raw_meta": "meta:\n        author = \"Didier Stevens (https://DidierStevens.com)\"\n        description = \"Detect PE file produced by pyinstaller\"\n        reference = \"https://isc.sans.edu/diary/21057\"\n    ",
        "raw_strings": "strings:\n        $a = \"pyi-windows-manifest-filename\"\n    ",
        "rule_name": "PE_File_pyinstaller",
        "start_line": 7,
        "stop_line": 17,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "pyi-windows-manifest-filename"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'screenlocker_5h311_1nj3c706', NULL, '{"author": "Marc Rivero | @seifreed", "reference": "https://twitter.com/demonslay335/status/1038060120461266944", "description": "Rule to detect the screenlocker 5h311_1nj3c706"}', '[
    {
        "condition_terms": [
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "filesize",
            "<",
            "200KB",
            ")",
            "and",
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Rule to detect the screenlocker 5h311_1nj3c706"
            },
            {
                "author": "Marc Rivero | @seifreed"
            },
            {
                "reference": "https://twitter.com/demonslay335/status/1038060120461266944"
            }
        ],
        "raw_condition": "condition:\n\n      ( uint16(0) == 0x5a4d and filesize < 200KB ) and all of them \n",
        "raw_meta": "meta:\n\n      description = \"Rule to detect the screenlocker 5h311_1nj3c706\"\n      author = \"Marc Rivero | @seifreed\"\n      reference = \"https://twitter.com/demonslay335/status/1038060120461266944\"\n\n   ",
        "raw_strings": "strings:\n\n      $s1 = \"C:\\\\Users\\\\Hoang Nam\\\\source\\\\repos\\\\WindowsApp22\\\\WindowsApp22\\\\obj\\\\Debug\\\\WindowsApp22.pdb\" fullword ascii\n      $s2 = \"cmd.exe /cREG add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\ActiveDesktop /v NoChangingWallPaper /t REG_DWOR\" wide\n      $s3 = \"C:\\\\Users\\\\file1.txt\" fullword wide\n      $s4 = \"C:\\\\Users\\\\file2.txt\" fullword wide\n      $s5 = \"C:\\\\Users\\\\file.txt\" fullword wide\n      $s6 = \" /v Wallpaper /t REG_SZ /d %temp%\\\\IMG.jpg /f\" fullword wide\n      $s7 = \" /v DisableAntiSpyware /t REG_DWORD /d 1 /f\" fullword wide\n      $s8 = \"All your file has been locked. You must pay money to have a key.\" fullword wide\n      $s9 = \"After we receive Bitcoin from you. We will send key to your email.\" fullword wide\n   \n   ",
        "rule_name": "screenlocker_5h311_1nj3c706",
        "start_line": 1,
        "stop_line": 24,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "C:\\\\Users\\\\Hoang Nam\\\\source\\\\repos\\\\WindowsApp22\\\\WindowsApp22\\\\obj\\\\Debug\\\\WindowsApp22.pdb"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s2",
                "type": "text",
                "value": "cmd.exe /cREG add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\ActiveDesktop /v NoChangingWallPaper /t REG_DWOR"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s3",
                "type": "text",
                "value": "C:\\\\Users\\\\file1.txt"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s4",
                "type": "text",
                "value": "C:\\\\Users\\\\file2.txt"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s5",
                "type": "text",
                "value": "C:\\\\Users\\\\file.txt"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s6",
                "type": "text",
                "value": " /v Wallpaper /t REG_SZ /d %temp%\\\\IMG.jpg /f"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s7",
                "type": "text",
                "value": " /v DisableAntiSpyware /t REG_DWORD /d 1 /f"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s8",
                "type": "text",
                "value": "All your file has been locked. You must pay money to have a key."
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s9",
                "type": "text",
                "value": "After we receive Bitcoin from you. We will send key to your email."
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'CorkowDLL', NULL, '{"reference": "IB-Group | http://www.group-ib.ru/brochures/Group-IB-Corkow-Report-EN.pdf", "description": "Rule to detect the Corkow DLL files"}', '[
    {
        "condition_terms": [
            "(",
            "$mz",
            "at",
            "0",
            ")",
            "and",
            "(",
            "$binary1",
            "and",
            "$binary2",
            ")",
            "and",
            "any",
            "of",
            "(",
            "$export*",
            ")"
        ],
        "metadata": [
            {
                "description": "Rule to detect the Corkow DLL files"
            },
            {
                "reference": "IB-Group | http://www.group-ib.ru/brochures/Group-IB-Corkow-Report-EN.pdf"
            }
        ],
        "raw_condition": "condition:\n        ($mz at 0) and ($binary1 and $binary2) and any of ($export*)\n",
        "raw_meta": "meta:\n        description = \"Rule to detect the Corkow DLL files\"\n        reference = \"IB-Group | http://www.group-ib.ru/brochures/Group-IB-Corkow-Report-EN.pdf\"\n\n    ",
        "raw_strings": "strings:\n        $mz = { 4d 5a }\n        $binary1 = {60 [0-8] 9C [0-8] BB ?? ?? ?? ?? [0-8] 81 EB ?? ?? ?? ?? [0-8] E8 ?? 00 00 00 [0-8] 58 [0-8] 2B C3}\n        $binary2 = {(FF75??|53)FF7510FF750CFF7508E8????????[3-9]C9C20C 00}\n        $export1 = \"Control_RunDLL\"\n        $export2 = \"ServiceMain\"\n        $export3 = \"DllGetClassObject\"\n\n    ",
        "rule_name": "CorkowDLL",
        "start_line": 6,
        "stop_line": 23,
        "strings": [
            {
                "name": "$mz",
                "type": "byte",
                "value": "{ 4d 5a }"
            },
            {
                "name": "$binary1",
                "type": "byte",
                "value": "{60 [0-8] 9C [0-8] BB ?? ?? ?? ?? [0-8] 81 EB ?? ?? ?? ?? [0-8] E8 ?? 00 00 00 [0-8] 58 [0-8] 2B C3}"
            },
            {
                "name": "$binary2",
                "type": "byte",
                "value": "{(FF75??|53)FF7510FF750CFF7508E8????????[3-9]C9C20C 00}"
            },
            {
                "name": "$export1",
                "type": "text",
                "value": "Control_RunDLL"
            },
            {
                "name": "$export2",
                "type": "text",
                "value": "ServiceMain"
            },
            {
                "name": "$export3",
                "type": "text",
                "value": "DllGetClassObject"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'OpClandestineWolf', NULL, '{"log": "false", "date": "2015-06-23", "alert": true, "hash0": "1a4b710621ef2e69b1f7790ae9b7a288", "hash1": "917c92e8662faf96fffb8ffe7b7c80fb", "hash2": "975b458cb80395fa32c9dda759cb3f7b", "hash3": "3ed34de8609cd274e49bbd795f21acc4", "hash4": "b1a55ec420dd6d24ff9e762c7b753868", "hash5": "afd753a42036000ad476dcd81b56b754", "hash6": "fad20abf8aa4eda0802504d806280dd7", "hash7": "ab621059de2d1c92c3e7514e4b51751a", "hash8": "510b77a4b075f09202209f989582dbea", "hash9": "d1b1abfcc2d547e1ea1a4bb82294b9a3", "author": "NDF", "hash10": "4692337bf7584f6bda464b9a76d268c1", "hash11": "7cae5757f3ba9fef0a22ca0d56188439", "hash12": "1a7ba923c6aa39cc9cb289a17599fce0", "hash13": "f86db1905b3f4447eb5728859f9057b5", "hash14": "37c6d1d3054e554e13d40ea42458ebed", "hash15": "3e7430a09a44c0d1000f76c3adc6f4fa", "hash16": "98eb249e4ddc4897b8be6fe838051af7", "hash17": "1b57a7fad852b1d686c72e96f7837b44", "hash18": "ffb84b8561e49a8db60e0001f630831f", "hash19": "98eb249e4ddc4897b8be6fe838051af7", "hash20": "dfb4025352a80c2d81b84b37ef00bcd0", "hash21": "4457e89f4aec692d8507378694e0a3ba", "hash22": "48de562acb62b469480b8e29821f33b8", "hash23": "7a7eed9f2d1807f55a9308e21d81cccd", "hash24": "6817b29e9832d8fd85dcbe4af176efb6", "source": " https://www.fireeye.com/blog/threat-research/2015/06/operation-clandestine-wolf-adobe-flash-zero-day.html", "weight": 10, "version": 1, "description": "Operation Clandestine Wolf signature based on OSINT from 06.23.15", "alert_severity": "HIGH"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "alert_severity": "HIGH"
            },
            {
                "log": "false"
            },
            {
                "author": "NDF"
            },
            {
                "weight": 10
            },
            {
                "alert": true
            },
            {
                "source": " https://www.fireeye.com/blog/threat-research/2015/06/operation-clandestine-wolf-adobe-flash-zero-day.html"
            },
            {
                "version": 1
            },
            {
                "date": "2015-06-23"
            },
            {
                "description": "Operation Clandestine Wolf signature based on OSINT from 06.23.15"
            },
            {
                "hash0": "1a4b710621ef2e69b1f7790ae9b7a288"
            },
            {
                "hash1": "917c92e8662faf96fffb8ffe7b7c80fb"
            },
            {
                "hash2": "975b458cb80395fa32c9dda759cb3f7b"
            },
            {
                "hash3": "3ed34de8609cd274e49bbd795f21acc4"
            },
            {
                "hash4": "b1a55ec420dd6d24ff9e762c7b753868"
            },
            {
                "hash5": "afd753a42036000ad476dcd81b56b754"
            },
            {
                "hash6": "fad20abf8aa4eda0802504d806280dd7"
            },
            {
                "hash7": "ab621059de2d1c92c3e7514e4b51751a"
            },
            {
                "hash8": "510b77a4b075f09202209f989582dbea"
            },
            {
                "hash9": "d1b1abfcc2d547e1ea1a4bb82294b9a3"
            },
            {
                "hash10": "4692337bf7584f6bda464b9a76d268c1"
            },
            {
                "hash11": "7cae5757f3ba9fef0a22ca0d56188439"
            },
            {
                "hash12": "1a7ba923c6aa39cc9cb289a17599fce0"
            },
            {
                "hash13": "f86db1905b3f4447eb5728859f9057b5"
            },
            {
                "hash14": "37c6d1d3054e554e13d40ea42458ebed"
            },
            {
                "hash15": "3e7430a09a44c0d1000f76c3adc6f4fa"
            },
            {
                "hash16": "98eb249e4ddc4897b8be6fe838051af7"
            },
            {
                "hash17": "1b57a7fad852b1d686c72e96f7837b44"
            },
            {
                "hash18": "ffb84b8561e49a8db60e0001f630831f"
            },
            {
                "hash19": "98eb249e4ddc4897b8be6fe838051af7"
            },
            {
                "hash20": "dfb4025352a80c2d81b84b37ef00bcd0"
            },
            {
                "hash21": "4457e89f4aec692d8507378694e0a3ba"
            },
            {
                "hash22": "48de562acb62b469480b8e29821f33b8"
            },
            {
                "hash23": "7a7eed9f2d1807f55a9308e21d81cccd"
            },
            {
                "hash24": "6817b29e9832d8fd85dcbe4af176efb6"
            }
        ],
        "raw_condition": "condition:\n        all of them\n",
        "raw_meta": "meta:\n        alert_severity = \"HIGH\"\n        log = \"false\"\n        author = \"NDF\"\n        weight = 10\n        alert = true\n        source = \" https://www.fireeye.com/blog/threat-research/2015/06/operation-clandestine-wolf-adobe-flash-zero-day.html\"\n        version = 1\n        date = \"2015-06-23\"\n        description = \"Operation Clandestine Wolf signature based on OSINT from 06.23.15\"\n        hash0 = \"1a4b710621ef2e69b1f7790ae9b7a288\"\n        hash1 = \"917c92e8662faf96fffb8ffe7b7c80fb\"\n        hash2 = \"975b458cb80395fa32c9dda759cb3f7b\"\n        hash3 = \"3ed34de8609cd274e49bbd795f21acc4\"\n        hash4 = \"b1a55ec420dd6d24ff9e762c7b753868\"\n        hash5 = \"afd753a42036000ad476dcd81b56b754\"\n        hash6 = \"fad20abf8aa4eda0802504d806280dd7\"\n        hash7 = \"ab621059de2d1c92c3e7514e4b51751a\"\n        hash8 = \"510b77a4b075f09202209f989582dbea\"\n        hash9 = \"d1b1abfcc2d547e1ea1a4bb82294b9a3\"\n        hash10 = \"4692337bf7584f6bda464b9a76d268c1\"\n        hash11 = \"7cae5757f3ba9fef0a22ca0d56188439\"\n        hash12 = \"1a7ba923c6aa39cc9cb289a17599fce0\"\n        hash13 = \"f86db1905b3f4447eb5728859f9057b5\"\n        hash14 = \"37c6d1d3054e554e13d40ea42458ebed\"\n        hash15 = \"3e7430a09a44c0d1000f76c3adc6f4fa\"\n        hash16 = \"98eb249e4ddc4897b8be6fe838051af7\"\n        hash17 = \"1b57a7fad852b1d686c72e96f7837b44\"\n        hash18 = \"ffb84b8561e49a8db60e0001f630831f\"\n        hash19 = \"98eb249e4ddc4897b8be6fe838051af7\"\n        hash20 = \"dfb4025352a80c2d81b84b37ef00bcd0\"\n        hash21 = \"4457e89f4aec692d8507378694e0a3ba\"\n        hash22 = \"48de562acb62b469480b8e29821f33b8\"\n        hash23 = \"7a7eed9f2d1807f55a9308e21d81cccd\"\n        hash24 = \"6817b29e9832d8fd85dcbe4af176efb6\"\n\n   ",
        "raw_strings": "strings:\n        $s0 = \"flash.Media.Sound()\"\n        $s1 = \"call Kernel32!VirtualAlloc(0x1f140000hash$=0x10000hash$=0x1000hash$=0x40)\"\n        $s2 = \"{4D36E972-E325-11CE-BFC1-08002BE10318}\"\n        $s3 = \"NetStream\"\n\n    ",
        "rule_name": "OpClandestineWolf",
        "start_line": 6,
        "stop_line": 53,
        "strings": [
            {
                "name": "$s0",
                "type": "text",
                "value": "flash.Media.Sound()"
            },
            {
                "name": "$s1",
                "type": "text",
                "value": "call Kernel32!VirtualAlloc(0x1f140000hash$=0x10000hash$=0x1000hash$=0x40)"
            },
            {
                "name": "$s2",
                "type": "text",
                "value": "{4D36E972-E325-11CE-BFC1-08002BE10318}"
            },
            {
                "name": "$s3",
                "type": "text",
                "value": "NetStream"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'dubrute', '{bruteforcer,toolkit}', '{"date": "2015-09-05", "author": "Christian Rebischke (@sh1bumi)", "family": "Hackingtool/Bruteforcer", "description": "Rules for DuBrute Bruteforcer", "in_the_wild": true}', '[
    {
        "comments": [
            "//check for dubrute specific strings",
            "//check for MZ Signature at offset 0"
        ],
        "condition_terms": [
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5A4D",
            "and",
            "$a",
            "and",
            "$b",
            "and",
            "$c",
            "and",
            "$d",
            "and",
            "$e",
            "and",
            "$f"
        ],
        "metadata": [
            {
                "author": "Christian Rebischke (@sh1bumi)"
            },
            {
                "date": "2015-09-05"
            },
            {
                "description": "Rules for DuBrute Bruteforcer"
            },
            {
                "in_the_wild": true
            },
            {
                "family": "Hackingtool/Bruteforcer"
            }
        ],
        "raw_condition": "condition:\n        //check for MZ Signature at offset 0\n        uint16(0) == 0x5A4D \n\n        and \n\n        //check for dubrute specific strings\n        $a and $b and $c and $d and $e and $f \n",
        "raw_meta": "meta:\n        author = \"Christian Rebischke (@sh1bumi)\"\n        date = \"2015-09-05\"\n        description = \"Rules for DuBrute Bruteforcer\"\n        in_the_wild = true\n        family = \"Hackingtool/Bruteforcer\"\n    \n    ",
        "raw_strings": "strings:\n        $a = \"WBrute\"\n        $b = \"error.txt\"\n        $c = \"good.txt\"\n        $d = \"source.txt\"\n        $e = \"bad.txt\"\n        $f = \"Generator IP@Login;Password\"\n\n    ",
        "rule_name": "dubrute",
        "start_line": 1,
        "stop_line": 26,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "WBrute"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "error.txt"
            },
            {
                "name": "$c",
                "type": "text",
                "value": "good.txt"
            },
            {
                "name": "$d",
                "type": "text",
                "value": "source.txt"
            },
            {
                "name": "$e",
                "type": "text",
                "value": "bad.txt"
            },
            {
                "name": "$f",
                "type": "text",
                "value": "Generator IP@Login;Password"
            }
        ],
        "tags": [
            "bruteforcer",
            "toolkit"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'kpot', NULL, '{"date": "2018-08-29", "author": " J from THL <j@techhelplist.com>", "maltype": "Stealer", "version": 1, "filetype": "memory", "reference1": "https://www.virustotal.com/#/file/4e87a0794bf73d06ac1ce4a37e33eb832ff4c89fb9e4266490c7cef9229d27a7/detection", "reference2": "ETPRO TROJAN KPOT Stealer Check-In [2832358]", "reference3": "ETPRO TROJAN KPOT Stealer Exfiltration [2832359]"}', '[
    {
        "condition_terms": [
            "16",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": " J from THL <j@techhelplist.com>"
            },
            {
                "date": "2018-08-29"
            },
            {
                "reference1": "https://www.virustotal.com/#/file/4e87a0794bf73d06ac1ce4a37e33eb832ff4c89fb9e4266490c7cef9229d27a7/detection"
            },
            {
                "reference2": "ETPRO TROJAN KPOT Stealer Check-In [2832358]"
            },
            {
                "reference3": "ETPRO TROJAN KPOT Stealer Exfiltration [2832359]"
            },
            {
                "version": 1
            },
            {
                "maltype": "Stealer"
            },
            {
                "filetype": "memory"
            }
        ],
        "raw_condition": "condition:\n        16 of them\n",
        "raw_meta": "meta:\n        author = \" J from THL <j@techhelplist.com>\"\n        date = \"2018-08-29\"\n        reference1 = \"https://www.virustotal.com/#/file/4e87a0794bf73d06ac1ce4a37e33eb832ff4c89fb9e4266490c7cef9229d27a7/detection\"\n        reference2 = \"ETPRO TROJAN KPOT Stealer Check-In [2832358]\"\n        reference3 = \"ETPRO TROJAN KPOT Stealer Exfiltration [2832359]\"\n        version = 1\n        maltype = \"Stealer\"\n        filetype = \"memory\"\n\n    ",
        "raw_strings": "strings:\n        $text01 = \"bot_id=%s\"\n        $text02 = \"x64=%d\"\n        $text03 = \"is_admin=%d\"\n        $text04 = \"IL=%d\"\n        $text05 = \"os_version=%d\"\n        $text06 = \"IP: %S\"\n        $text07 = \"MachineGuid: %s\"\n        $text08 = \"CPU: %S (%d cores)\"\n        $text09 = \"RAM: %S MB\"\n        $text10 = \"Screen: %dx%d\"\n        $text11 = \"PC: %s\"\n        $text12 = \"User: %s\"\n        $text13 = \"LT: %S (UTC+%d:%d)\"\n        $text14 = \"%s/%s.php\"\n        $text15 = \"Host: %s\"\n        $text16 = \"username_value\"\n        $text17 = \"password_value\"\n        $text18 = \"name_on_card\"\n        $text19 = \"last_four\"\n        $text20 = \"exp_month\"\n        $text21 = \"exp_year\"\n        $text22 = \"bank_name\"\n\n\n    ",
        "rule_name": "kpot",
        "start_line": 2,
        "stop_line": 42,
        "strings": [
            {
                "name": "$text01",
                "type": "text",
                "value": "bot_id=%s"
            },
            {
                "name": "$text02",
                "type": "text",
                "value": "x64=%d"
            },
            {
                "name": "$text03",
                "type": "text",
                "value": "is_admin=%d"
            },
            {
                "name": "$text04",
                "type": "text",
                "value": "IL=%d"
            },
            {
                "name": "$text05",
                "type": "text",
                "value": "os_version=%d"
            },
            {
                "name": "$text06",
                "type": "text",
                "value": "IP: %S"
            },
            {
                "name": "$text07",
                "type": "text",
                "value": "MachineGuid: %s"
            },
            {
                "name": "$text08",
                "type": "text",
                "value": "CPU: %S (%d cores)"
            },
            {
                "name": "$text09",
                "type": "text",
                "value": "RAM: %S MB"
            },
            {
                "name": "$text10",
                "type": "text",
                "value": "Screen: %dx%d"
            },
            {
                "name": "$text11",
                "type": "text",
                "value": "PC: %s"
            },
            {
                "name": "$text12",
                "type": "text",
                "value": "User: %s"
            },
            {
                "name": "$text13",
                "type": "text",
                "value": "LT: %S (UTC+%d:%d)"
            },
            {
                "name": "$text14",
                "type": "text",
                "value": "%s/%s.php"
            },
            {
                "name": "$text15",
                "type": "text",
                "value": "Host: %s"
            },
            {
                "name": "$text16",
                "type": "text",
                "value": "username_value"
            },
            {
                "name": "$text17",
                "type": "text",
                "value": "password_value"
            },
            {
                "name": "$text18",
                "type": "text",
                "value": "name_on_card"
            },
            {
                "name": "$text19",
                "type": "text",
                "value": "last_four"
            },
            {
                "name": "$text20",
                "type": "text",
                "value": "exp_month"
            },
            {
                "name": "$text21",
                "type": "text",
                "value": "exp_year"
            },
            {
                "name": "$text22",
                "type": "text",
                "value": "bank_name"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Agenttesla', NULL, '{"author": "Stormshield", "version": "1.0", "reference": "https://thisissecurity.stormshield.com/2018/01/12/agent-tesla-campaign/", "description": "Detecting HTML strings used by Agent Tesla malware"}', '[
    {
        "condition_terms": [
            "3",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Detecting HTML strings used by Agent Tesla malware"
            },
            {
                "author": "Stormshield"
            },
            {
                "reference": "https://thisissecurity.stormshield.com/2018/01/12/agent-tesla-campaign/"
            },
            {
                "version": "1.0"
            }
        ],
        "raw_condition": "condition:\n        3 of them\n",
        "raw_meta": "meta:\n        description = \"Detecting HTML strings used by Agent Tesla malware\"\n        author = \"Stormshield\"\n        reference = \"https://thisissecurity.stormshield.com/2018/01/12/agent-tesla-campaign/\"\n        version = \"1.0\"\n\n    ",
        "raw_strings": "strings:\n        $html_username    = \"<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: \" wide ascii\n        $html_pc_name     = \"<br>PC&nbsp;Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: \" wide ascii\n        $html_os_name     = \"<br>OS&nbsp;Full&nbsp;Name&nbsp;&nbsp;: \" wide ascii\n        $html_os_platform = \"<br>OS&nbsp;Platform&nbsp;&nbsp;&nbsp;: \" wide ascii\n        $html_clipboard   = \"<br><span style=font-style:normal;text-decoration:none;text-transform:none;color:#FF0000;><strong>[clipboard]</strong></span>\" wide ascii\n\n    ",
        "rule_name": "Agenttesla",
        "start_line": 2,
        "stop_line": 19,
        "strings": [
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$html_username",
                "type": "text",
                "value": "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: "
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$html_pc_name",
                "type": "text",
                "value": "<br>PC&nbsp;Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: "
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$html_os_name",
                "type": "text",
                "value": "<br>OS&nbsp;Full&nbsp;Name&nbsp;&nbsp;: "
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$html_os_platform",
                "type": "text",
                "value": "<br>OS&nbsp;Platform&nbsp;&nbsp;&nbsp;: "
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$html_clipboard",
                "type": "text",
                "value": "<br><span style=font-style:normal;text-decoration:none;text-transform:none;color:#FF0000;><strong>[clipboard]</strong></span>"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'MALW_FakePyPI', NULL, '{"tlp": "white", "date": "2017-09", "author": "@bartblaze", "reference": "http://www.nbu.gov.sk/skcsirt-sa-20170909-pypi/", "description": "Identifies fake PyPI Packages."}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Identifies fake PyPI Packages."
            },
            {
                "author": "@bartblaze"
            },
            {
                "reference": "http://www.nbu.gov.sk/skcsirt-sa-20170909-pypi/"
            },
            {
                "date": "2017-09"
            },
            {
                "tlp": "white"
            }
        ],
        "raw_condition": "condition:\n\tall of them\n",
        "raw_meta": "meta:\n\tdescription = \"Identifies fake PyPI Packages.\"\n\tauthor = \"@bartblaze\"\n\treference = \"http://www.nbu.gov.sk/skcsirt-sa-20170909-pypi/\"\n\tdate = \"2017-09\"\n\ttlp = \"white\"\n\n",
        "raw_strings": "strings:\t\n\t$ = \"# Welcome Here! :)\"\n\t$ = \"# just toy, no harm :)\"\n\t$ = \"[0x76,0x21,0xfe,0xcc,0xee]\"\n\n",
        "rule_name": "MALW_FakePyPI",
        "start_line": 1,
        "stop_line": 17,
        "strings": [
            {
                "name": "$",
                "type": "text",
                "value": "# Welcome Here! :)"
            },
            {
                "name": "$",
                "type": "text",
                "value": "# just toy, no harm :)"
            },
            {
                "name": "$",
                "type": "text",
                "value": "[0x76,0x21,0xfe,0xcc,0xee]"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'MALW_KeyBase', NULL, '{"tlp": "White", "date": "2019-02", "author": "@bartblaze", "description": "Identifies KeyBase aka Kibex."}', '[
    {
        "condition_terms": [
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "(",
            "5",
            "of",
            "(",
            "$s*",
            ")",
            "or",
            "6",
            "of",
            "(",
            "$x*",
            ")",
            "or",
            "(",
            "4",
            "of",
            "(",
            "$s*",
            ")",
            "and",
            "4",
            "of",
            "(",
            "$x*",
            ")",
            ")",
            ")"
        ],
        "metadata": [
            {
                "description": "Identifies KeyBase aka Kibex."
            },
            {
                "author": "@bartblaze"
            },
            {
                "date": "2019-02"
            },
            {
                "tlp": "White"
            }
        ],
        "raw_condition": "condition:\n\tuint16(0) == 0x5a4d and (\n\t\t5 of ($s*) or 6 of ($x*) or\n\t\t( 4 of ($s*) and 4 of ($x*) )\n\t)\n",
        "raw_meta": "meta:\n\tdescription = \"Identifies KeyBase aka Kibex.\"\n\tauthor = \"@bartblaze\"\n\tdate = \"2019-02\"\n\ttlp = \"White\"\n\n",
        "raw_strings": "strings:\t\n\t$s1 = \" End:]\" ascii wide\n\t$s2 = \"Keystrokes typed:\" ascii wide\n\t$s3 = \"Machine Time:\" ascii wide\n\t$s4 = \"Text:\" ascii wide\n\t$s5 = \"Time:\" ascii wide\n\t$s6 = \"Window title:\" ascii wide\n\t\n\t$x1 = \"&application=\" ascii wide\n\t$x2 = \"&clipboardtext=\" ascii wide\n\t$x3 = \"&keystrokestyped=\" ascii wide\n\t$x4 = \"&link=\" ascii wide\n\t$x5 = \"&username=\" ascii wide\n\t$x6 = \"&windowtitle=\" ascii wide\n\t$x7 = \"=drowssap&\" ascii wide\n\t$x8 = \"=emitenihcam&\" ascii wide\n\n",
        "rule_name": "MALW_KeyBase",
        "start_line": 1,
        "stop_line": 31,
        "strings": [
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$s1",
                "type": "text",
                "value": " End:]"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$s2",
                "type": "text",
                "value": "Keystrokes typed:"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$s3",
                "type": "text",
                "value": "Machine Time:"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$s4",
                "type": "text",
                "value": "Text:"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$s5",
                "type": "text",
                "value": "Time:"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$s6",
                "type": "text",
                "value": "Window title:"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$x1",
                "type": "text",
                "value": "&application="
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$x2",
                "type": "text",
                "value": "&clipboardtext="
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$x3",
                "type": "text",
                "value": "&keystrokestyped="
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$x4",
                "type": "text",
                "value": "&link="
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$x5",
                "type": "text",
                "value": "&username="
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$x6",
                "type": "text",
                "value": "&windowtitle="
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$x7",
                "type": "text",
                "value": "=drowssap&"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$x8",
                "type": "text",
                "value": "=emitenihcam&"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'zoxPNG_RAT', NULL, '{"Date": "2014/11/14", "Author": "Novetta Advanced Research Group", "Reference": "http://www.novetta.com/wp-content/uploads/2014/11/ZoxPNG.pdf", "Description": "ZoxPNG RAT, url inside"}', '[
    {
        "condition_terms": [
            "$url"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "Author": "Novetta Advanced Research Group"
            },
            {
                "Date": "2014/11/14"
            },
            {
                "Description": "ZoxPNG RAT, url inside"
            },
            {
                "Reference": "http://www.novetta.com/wp-content/uploads/2014/11/ZoxPNG.pdf"
            }
        ],
        "raw_condition": "condition: \n        $url\n",
        "raw_meta": "meta:\n        Author      = \"Novetta Advanced Research Group\"\n        Date        = \"2014/11/14\"\n        Description = \"ZoxPNG RAT, url inside\"\n        Reference   = \"http://www.novetta.com/wp-content/uploads/2014/11/ZoxPNG.pdf\"\n\n    ",
        "raw_strings": "strings: \n        $url = \"png&w=800&h=600&ei=CnJcUcSBL4rFkQX444HYCw&zoom=1&ved=1t:3588,r:1,s:0,i:92&iact=rc&dur=368&page=1&tbnh=184&tbnw=259&start=0&ndsp=20&tx=114&ty=58\"\n\n    ",
        "rule_name": "zoxPNG_RAT",
        "start_line": 8,
        "stop_line": 21,
        "strings": [
            {
                "name": "$url",
                "type": "text",
                "value": "png&w=800&h=600&ei=CnJcUcSBL4rFkQX444HYCw&zoom=1&ved=1t:3588,r:1,s:0,i:92&iact=rc&dur=368&page=1&tbnh=184&tbnw=259&start=0&ndsp=20&tx=114&ty=58"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'EliseLotusBlossom', NULL, '{"ref": "https://www.paloaltonetworks.com/resources/research/unit42-operation-lotus-blossom.html", "date": "2015-06-23", "author": "Jose Ramon Palanco", "description": "Elise Backdoor Trojan"}', '[
    {
        "condition_terms": [
            "$magic",
            "at",
            "0",
            "and",
            "all",
            "of",
            "(",
            "$s*",
            ")"
        ],
        "metadata": [
            {
                "author": "Jose Ramon Palanco"
            },
            {
                "date": "2015-06-23"
            },
            {
                "description": "Elise Backdoor Trojan"
            },
            {
                "ref": "https://www.paloaltonetworks.com/resources/research/unit42-operation-lotus-blossom.html"
            }
        ],
        "raw_condition": "condition:\n    $magic at 0 and all of ($s*)    \n",
        "raw_meta": "meta:\n    author = \"Jose Ramon Palanco\"\n    date = \"2015-06-23\"\n    description = \"Elise Backdoor Trojan\"\n    ref = \"https://www.paloaltonetworks.com/resources/research/unit42-operation-lotus-blossom.html\"\n\n",
        "raw_strings": "strings:\n    $magic = { 4d 5a }\n    $s1 = \"\\\",Update\" wide\n    $s2 = \"LoaderDLL.dll\"\n    $s3 = \"Kernel32.dll\"\n    $s4 = \"{5947BACD-63BF-4e73-95D7-0C8A98AB95F2}\"\n    $s5 = \"\\\\Network\\\\\" wide\n    $s6 = \"0SSSSS\"\n    $s7 = \"441202100205\"\n    $s8 = \"0WWWWW\"\n\n",
        "rule_name": "EliseLotusBlossom",
        "start_line": 1,
        "stop_line": 23,
        "strings": [
            {
                "name": "$magic",
                "type": "byte",
                "value": "{ 4d 5a }"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s1",
                "type": "text",
                "value": "\\\",Update"
            },
            {
                "name": "$s2",
                "type": "text",
                "value": "LoaderDLL.dll"
            },
            {
                "name": "$s3",
                "type": "text",
                "value": "Kernel32.dll"
            },
            {
                "name": "$s4",
                "type": "text",
                "value": "{5947BACD-63BF-4e73-95D7-0C8A98AB95F2}"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s5",
                "type": "text",
                "value": "\\\\Network\\\\"
            },
            {
                "name": "$s6",
                "type": "text",
                "value": "0SSSSS"
            },
            {
                "name": "$s7",
                "type": "text",
                "value": "441202100205"
            },
            {
                "name": "$s8",
                "type": "text",
                "value": "0WWWWW"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'RAT_Orcus', NULL, '{"date": "2017/01", "author": " J from THL <j@techhelplist.com> with thx to MalwareHunterTeam", "maltype": "RAT", "version": 1, "filetype": "memory", "reference": "https://virustotal.com/en/file/0ef747363828342c184303f2d6fbead054200e9c223e5cfc4777cda03006e317/analysis/"}', '[
    {
        "condition_terms": [
            "13",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": " J from THL <j@techhelplist.com> with thx to MalwareHunterTeam"
            },
            {
                "date": "2017/01"
            },
            {
                "reference": "https://virustotal.com/en/file/0ef747363828342c184303f2d6fbead054200e9c223e5cfc4777cda03006e317/analysis/"
            },
            {
                "version": 1
            },
            {
                "maltype": "RAT"
            },
            {
                "filetype": "memory"
            }
        ],
        "raw_condition": "condition:\n        13 of them\n",
        "raw_meta": "meta:\n        author = \" J from THL <j@techhelplist.com> with thx to MalwareHunterTeam\"\n        date = \"2017/01\"\n        reference = \"https://virustotal.com/en/file/0ef747363828342c184303f2d6fbead054200e9c223e5cfc4777cda03006e317/analysis/\"\n        version = 1\n        maltype = \"RAT\"\n        filetype = \"memory\"\n\n    ",
        "raw_strings": "strings:\n        $text01 = \"Orcus.CommandManagement\"\n        $text02 = \"Orcus.Commands.\"\n        $text03 = \"Orcus.Config.\"\n        $text04 = \"Orcus.Connection.\"\n        $text05 = \"Orcus.Core.\"\n        $text06 = \"Orcus.exe\"\n        $text07 = \"Orcus.Extensions.\"\n        $text08 = \"Orcus.InstallationPromptForm\"\n        $text09 = \"Orcus.MainForm.\"\n        $text10 = \"Orcus.Native.\"\n        $text11 = \"Orcus.Plugins.\"\n        $text12 = \"orcus.plugins.dll\"\n        $text13 = \"Orcus.Properties.\"\n        $text14 = \"Orcus.Protection.\"\n        $text15 = \"Orcus.Share.\"\n        $text16 = \"Orcus.Shared\"\n        $text17 = \"Orcus.StaticCommands\"\n        $text18 = \"Orcus.Utilities.\"\n        $text19 = \"\\\\Projects\\\\Orcus\\\\Source\\\\Orcus.\"\n        $text20 = \".orcus.plugins.dll.zip\"\n        $text21 = \".orcus.shared.dll.zip\"\n        $text22 = \".orcus.shared.utilities.dll.zip\"\n        $text23 = \".orcus.staticcommands.dll.zip\"\n        $text24 = \"HvncCommunication\"\n        $text25 = \"HvncAction\"\n        $text26 = \"hvncDesktop\"\n        $text27 = \".InstallationPromptForm\"\n        $text28 = \"RequestKeyLogCommand\"\n        $text29 = \"get_KeyLogFile\"\n        $text30 = \"LiveKeyloggerCommand\"\n        $text31 = \"ORCUS.STATICCOMMANDS, VERSION=\"\n        $text32 = \"PrepareOrcusFileToRemove\"\n        $text33 = \"ConvertFromOrcusValueKind\"\n\n    ",
        "rule_name": "RAT_Orcus",
        "start_line": 1,
        "stop_line": 49,
        "strings": [
            {
                "name": "$text01",
                "type": "text",
                "value": "Orcus.CommandManagement"
            },
            {
                "name": "$text02",
                "type": "text",
                "value": "Orcus.Commands."
            },
            {
                "name": "$text03",
                "type": "text",
                "value": "Orcus.Config."
            },
            {
                "name": "$text04",
                "type": "text",
                "value": "Orcus.Connection."
            },
            {
                "name": "$text05",
                "type": "text",
                "value": "Orcus.Core."
            },
            {
                "name": "$text06",
                "type": "text",
                "value": "Orcus.exe"
            },
            {
                "name": "$text07",
                "type": "text",
                "value": "Orcus.Extensions."
            },
            {
                "name": "$text08",
                "type": "text",
                "value": "Orcus.InstallationPromptForm"
            },
            {
                "name": "$text09",
                "type": "text",
                "value": "Orcus.MainForm."
            },
            {
                "name": "$text10",
                "type": "text",
                "value": "Orcus.Native."
            },
            {
                "name": "$text11",
                "type": "text",
                "value": "Orcus.Plugins."
            },
            {
                "name": "$text12",
                "type": "text",
                "value": "orcus.plugins.dll"
            },
            {
                "name": "$text13",
                "type": "text",
                "value": "Orcus.Properties."
            },
            {
                "name": "$text14",
                "type": "text",
                "value": "Orcus.Protection."
            },
            {
                "name": "$text15",
                "type": "text",
                "value": "Orcus.Share."
            },
            {
                "name": "$text16",
                "type": "text",
                "value": "Orcus.Shared"
            },
            {
                "name": "$text17",
                "type": "text",
                "value": "Orcus.StaticCommands"
            },
            {
                "name": "$text18",
                "type": "text",
                "value": "Orcus.Utilities."
            },
            {
                "name": "$text19",
                "type": "text",
                "value": "\\\\Projects\\\\Orcus\\\\Source\\\\Orcus."
            },
            {
                "name": "$text20",
                "type": "text",
                "value": ".orcus.plugins.dll.zip"
            },
            {
                "name": "$text21",
                "type": "text",
                "value": ".orcus.shared.dll.zip"
            },
            {
                "name": "$text22",
                "type": "text",
                "value": ".orcus.shared.utilities.dll.zip"
            },
            {
                "name": "$text23",
                "type": "text",
                "value": ".orcus.staticcommands.dll.zip"
            },
            {
                "name": "$text24",
                "type": "text",
                "value": "HvncCommunication"
            },
            {
                "name": "$text25",
                "type": "text",
                "value": "HvncAction"
            },
            {
                "name": "$text26",
                "type": "text",
                "value": "hvncDesktop"
            },
            {
                "name": "$text27",
                "type": "text",
                "value": ".InstallationPromptForm"
            },
            {
                "name": "$text28",
                "type": "text",
                "value": "RequestKeyLogCommand"
            },
            {
                "name": "$text29",
                "type": "text",
                "value": "get_KeyLogFile"
            },
            {
                "name": "$text30",
                "type": "text",
                "value": "LiveKeyloggerCommand"
            },
            {
                "name": "$text31",
                "type": "text",
                "value": "ORCUS.STATICCOMMANDS, VERSION="
            },
            {
                "name": "$text32",
                "type": "text",
                "value": "PrepareOrcusFileToRemove"
            },
            {
                "name": "$text33",
                "type": "text",
                "value": "ConvertFromOrcusValueKind"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Kraken_Bot_Sample', '{bot}', '{"date": "2015-05-07", "hash": "798e9f43fc199269a3ec68980eb4d91eb195436d", "score": 90, "author": "Florian Roth", "reference": "https://blog.gdatasoftware.com/blog/article/dissecting-the-kraken.html", "description": "Kraken Bot Sample - file inf.bin"}', '[
    {
        "condition_terms": [
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Kraken Bot Sample - file inf.bin"
            },
            {
                "author": "Florian Roth"
            },
            {
                "reference": "https://blog.gdatasoftware.com/blog/article/dissecting-the-kraken.html"
            },
            {
                "date": "2015-05-07"
            },
            {
                "hash": "798e9f43fc199269a3ec68980eb4d91eb195436d"
            },
            {
                "score": 90
            }
        ],
        "raw_condition": "condition:\n\t\tuint16(0) == 0x5a4d and all of them\n",
        "raw_meta": "meta:\n\t\tdescription = \"Kraken Bot Sample - file inf.bin\"\n\t\tauthor = \"Florian Roth\"\n\t\treference = \"https://blog.gdatasoftware.com/blog/article/dissecting-the-kraken.html\"\n\t\tdate = \"2015-05-07\"\n\t\thash = \"798e9f43fc199269a3ec68980eb4d91eb195436d\"\n\t\tscore = 90\n\t",
        "raw_strings": "strings:\n\t\t$s2 = \"%s=?getname\" fullword ascii\n\t\t$s4 = \"&COMPUTER=^\" fullword ascii\n\t\t$s5 = \"xJWFwcGRhdGElAA=\" fullword ascii /* base64 encoded string ''%appdata%'' */\n\t\t$s8 = \"JVdJTkRJUi\" fullword ascii /* base64 encoded string ''%WINDIR'' */\n\t\t$s20 = \"btcplug\" fullword ascii\n\t",
        "rule_name": "Kraken_Bot_Sample",
        "start_line": 6,
        "stop_line": 22,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s2",
                "type": "text",
                "value": "%s=?getname"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s4",
                "type": "text",
                "value": "&COMPUTER=^"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s5",
                "type": "text",
                "value": "xJWFwcGRhdGElAA="
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s8",
                "type": "text",
                "value": "JVdJTkRJUi"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s20",
                "type": "text",
                "value": "btcplug"
            }
        ],
        "tags": [
            "bot"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'stampado_overlay', NULL, '{"md5": "6337f0938e4a9c0ef44ab99deb0ef466", "date": "2016-07", "author": "Fernando Merces, FTR, Trend Micro", "reference": "", "description": "Catches Stampado samples looking for \\\\r at the beginning of PE overlay section"}', '[
    {
        "condition_terms": [
            "pe.characteristics",
            "==",
            "0x122",
            "and",
            "pe.number_of_sections",
            "==",
            "5",
            "and",
            "pe.imports",
            "(",
            "\"VERSION.dll\"",
            ",",
            "\"VerQueryValueW\"",
            ")",
            "and",
            "uint8",
            "(",
            "pe.sections",
            "[",
            "4",
            "]",
            ".",
            "raw_data_offset",
            "+",
            "pe.sections",
            "[",
            "4",
            "]",
            ".",
            "raw_data_size",
            ")",
            "==",
            "0x0d"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "description": "Catches Stampado samples looking for \\\\r at the beginning of PE overlay section"
            },
            {
                "reference": ""
            },
            {
                "author": "Fernando Merces, FTR, Trend Micro"
            },
            {
                "date": "2016-07"
            },
            {
                "md5": "a393b9536a1caa34914636d3da7378b5"
            },
            {
                "md5": "dbf3707a9cd090853a11dda9cfa78ff0"
            },
            {
                "md5": "dd5686ca7ec28815c3cf3ed3dbebdff2"
            },
            {
                "md5": "6337f0938e4a9c0ef44ab99deb0ef466"
            }
        ],
        "raw_condition": "condition:\npe.characteristics == 0x122 and\npe.number_of_sections == 5 and\npe.imports(\"VERSION.dll\", \"VerQueryValueW\") and uint8(pe.sections[4].raw_data_offset + pe.sections[4].raw_data_size) == 0x0d\n\n",
        "raw_meta": "meta:\ndescription = \"Catches Stampado samples looking for \\\\r at the beginning of PE overlay section\"\nreference = \"\"\nauthor = \"Fernando Merces, FTR, Trend Micro\"\ndate = \"2016-07\"\nmd5 = \"a393b9536a1caa34914636d3da7378b5\"\nmd5 = \"dbf3707a9cd090853a11dda9cfa78ff0\"\nmd5 = \"dd5686ca7ec28815c3cf3ed3dbebdff2\"\nmd5 = \"6337f0938e4a9c0ef44ab99deb0ef466\"\n\n",
        "rule_name": "stampado_overlay",
        "start_line": 8,
        "stop_line": 25
    }
]
');
INSERT INTO public.rule VALUES (default, 'agenttesla_smtp_variant', NULL, '{"date": "2018/2", "author": "J from THL <j@techhelplist.com> with thx to @Fumik0_ !!1!", "maltype": "Stealer", "version": 1, "filetype": "memory", "reference1": "https://www.virustotal.com/#/file/1198865bc928a7a4f7977aaa36af5a2b9d5a949328b89dd87c541758516ad417/detection", "reference2": "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/tspy_negasteal.a", "reference3": "Agent Tesla == negasteal -- @coldshell"}', '[
    {
        "condition_terms": [
            "6",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "J from THL <j@techhelplist.com> with thx to @Fumik0_ !!1!"
            },
            {
                "date": "2018/2"
            },
            {
                "reference1": "https://www.virustotal.com/#/file/1198865bc928a7a4f7977aaa36af5a2b9d5a949328b89dd87c541758516ad417/detection"
            },
            {
                "reference2": "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/tspy_negasteal.a"
            },
            {
                "reference3": "Agent Tesla == negasteal -- @coldshell"
            },
            {
                "version": 1
            },
            {
                "maltype": "Stealer"
            },
            {
                "filetype": "memory"
            }
        ],
        "raw_condition": "condition:\n        6 of them\n",
        "raw_meta": "meta:\n        author = \"J from THL <j@techhelplist.com> with thx to @Fumik0_ !!1!\"\n        date = \"2018/2\"\n\treference1 = \"https://www.virustotal.com/#/file/1198865bc928a7a4f7977aaa36af5a2b9d5a949328b89dd87c541758516ad417/detection\"\n\treference2 = \"https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/tspy_negasteal.a\"\n\treference3 = \"Agent Tesla == negasteal -- @coldshell\"\n\tversion = 1\n        maltype = \"Stealer\"\n        filetype = \"memory\"\n\n    ",
        "raw_strings": "strings:\n\t\t$a = \"type={\"\n\t\t$b = \"hwid={\"\n\t\t$c = \"time={\"\n\t\t$d = \"pcname={\"\n\t\t$e = \"logdata={\"\n\t\t$f = \"screen={\"\n\t\t$g = \"ipadd={\"\n\t\t$h = \"webcam_link={\"\n\t\t$i = \"screen_link={\"\n\t\t$j = \"site_username={\"\n\t\t$k = \"[passwords]\"\n\n    ",
        "rule_name": "agenttesla_smtp_variant",
        "start_line": 1,
        "stop_line": 28,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "type={"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "hwid={"
            },
            {
                "name": "$c",
                "type": "text",
                "value": "time={"
            },
            {
                "name": "$d",
                "type": "text",
                "value": "pcname={"
            },
            {
                "name": "$e",
                "type": "text",
                "value": "logdata={"
            },
            {
                "name": "$f",
                "type": "text",
                "value": "screen={"
            },
            {
                "name": "$g",
                "type": "text",
                "value": "ipadd={"
            },
            {
                "name": "$h",
                "type": "text",
                "value": "webcam_link={"
            },
            {
                "name": "$i",
                "type": "text",
                "value": "screen_link={"
            },
            {
                "name": "$j",
                "type": "text",
                "value": "site_username={"
            },
            {
                "name": "$k",
                "type": "text",
                "value": "[passwords]"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'MiniAsp3_mem', '{memory}', '{"author": "chort (@chort0)", "description": "Detect MiniASP3 in memory"}', '[
    {
        "condition_terms": [
            "(",
            "$pdb",
            "and",
            "(",
            "all",
            "of",
            "(",
            "$http*",
            ")",
            ")",
            "and",
            "any",
            "of",
            "(",
            "$msg*",
            ")",
            ")"
        ],
        "metadata": [
            {
                "author": "chort (@chort0)"
            },
            {
                "description": "Detect MiniASP3 in memory"
            }
        ],
        "raw_condition": "condition:\n  ($pdb and (all of ($http*)) and any of ($msg*))\n  ",
        "raw_meta": "meta: author = \"chort (@chort0)\"\n  description = \"Detect MiniASP3 in memory\"\n  ",
        "raw_strings": "strings: \n    $pdb = \"MiniAsp3\\\\Release\\\\MiniAsp.pdb\" fullword \n    $httpAbout = \"http://%s/about.htm\" fullword \n    $httpResult = \"http://%s/result_%s.htm\" fullword \n    $msgInetFail = \"open internet failed\u2026\" fullword \n    $msgRunErr = \"run error!\" fullword \n    $msgRunOk = \"run ok!\" fullword\n    $msgTimeOutM0 = \"time out,change to mode 0\" fullword \n    $msgCmdNull = \"command is null!\" fullword \n",
        "rule_name": "MiniAsp3_mem",
        "start_line": 1,
        "stop_line": 15,
        "strings": [
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$pdb",
                "type": "text",
                "value": "MiniAsp3\\\\Release\\\\MiniAsp.pdb"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$httpAbout",
                "type": "text",
                "value": "http://%s/about.htm"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$httpResult",
                "type": "text",
                "value": "http://%s/result_%s.htm"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$msgInetFail",
                "type": "text",
                "value": "open internet failed\u2026"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$msgRunErr",
                "type": "text",
                "value": "run error!"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$msgRunOk",
                "type": "text",
                "value": "run ok!"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$msgTimeOutM0",
                "type": "text",
                "value": "time out,change to mode 0"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$msgCmdNull",
                "type": "text",
                "value": "command is null!"
            }
        ],
        "tags": [
            "memory"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Powerkatz_DLL_Generic', NULL, '{"date": "2016-02-05", "hash1": "c20f30326fcebad25446cf2e267c341ac34664efad5c50ff07f0738ae2390eae", "hash2": "1e67476281c1ec1cf40e17d7fc28a3ab3250b474ef41cb10a72130990f0be6a0", "hash3": "49e7bac7e0db87bf3f0185e9cf51f2539dbc11384fefced465230c4e5bce0872", "score": 80, "author": "Florian Roth", "reference": "PowerKatz Analysis", "super_rule": 1, "description": "Detects Powerkatz - a Mimikatz version prepared to run in memory via Powershell (overlap with other Mimikatz versions is possible)"}', '[
    {
        "condition_terms": [
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "filesize",
            "<",
            "1000KB",
            "and",
            "1",
            "of",
            "them",
            ")",
            "or",
            "2",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Detects Powerkatz - a Mimikatz version prepared to run in memory via Powershell (overlap with other Mimikatz versions is possible)"
            },
            {
                "author": "Florian Roth"
            },
            {
                "reference": "PowerKatz Analysis"
            },
            {
                "date": "2016-02-05"
            },
            {
                "super_rule": 1
            },
            {
                "score": 80
            },
            {
                "hash1": "c20f30326fcebad25446cf2e267c341ac34664efad5c50ff07f0738ae2390eae"
            },
            {
                "hash2": "1e67476281c1ec1cf40e17d7fc28a3ab3250b474ef41cb10a72130990f0be6a0"
            },
            {
                "hash3": "49e7bac7e0db87bf3f0185e9cf51f2539dbc11384fefced465230c4e5bce0872"
            }
        ],
        "raw_condition": "condition:\n\t\t( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them ) or 2 of them\n",
        "raw_meta": "meta:\n\t\tdescription = \"Detects Powerkatz - a Mimikatz version prepared to run in memory via Powershell (overlap with other Mimikatz versions is possible)\"\n\t\tauthor = \"Florian Roth\"\n\t\treference = \"PowerKatz Analysis\"\n\t\tdate = \"2016-02-05\"\n\t\tsuper_rule = 1\n\t\tscore = 80\n\t\thash1 = \"c20f30326fcebad25446cf2e267c341ac34664efad5c50ff07f0738ae2390eae\"\n\t\thash2 = \"1e67476281c1ec1cf40e17d7fc28a3ab3250b474ef41cb10a72130990f0be6a0\"\n\t\thash3 = \"49e7bac7e0db87bf3f0185e9cf51f2539dbc11384fefced465230c4e5bce0872\"\n\t",
        "raw_strings": "strings:\n\t\t$s1 = \"%3u - Directory ''%s'' (*.kirbi)\" fullword wide\n\t\t$s2 = \"%*s  pPublicKey         : \" fullword wide\n\t\t$s3 = \"ad_hoc_network_formed\" fullword wide\n\t\t$s4 = \"<3 eo.oe ~ ANSSI E>\" fullword wide\n\t\t$s5 = \"\\\\*.kirbi\" fullword wide\n\n\t\t$c1 = \"kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)\" fullword wide\n\t\t$c2 = \"kuhl_m_lsadump_getComputerAndSyskey ; kuhl_m_lsadump_getSyskey KO\" fullword wide\n\t",
        "rule_name": "Powerkatz_DLL_Generic",
        "start_line": 12,
        "stop_line": 34,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s1",
                "type": "text",
                "value": "%3u - Directory ''%s'' (*.kirbi)"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s2",
                "type": "text",
                "value": "%*s  pPublicKey         : "
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s3",
                "type": "text",
                "value": "ad_hoc_network_formed"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s4",
                "type": "text",
                "value": "<3 eo.oe ~ ANSSI E>"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s5",
                "type": "text",
                "value": "\\\\*.kirbi"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$c1",
                "type": "text",
                "value": "kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$c2",
                "type": "text",
                "value": "kuhl_m_lsadump_getComputerAndSyskey ; kuhl_m_lsadump_getSyskey KO"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'wineggdrop', '{portscanner,toolkit}', '{"date": "2015-09-05", "author": "Christian Rebischke (@sh1bumi)", "family": "Hackingtool/Portscanner", "description": "Rules for TCP Portscanner VX.X by WinEggDrop", "in_the_wild": true}', '[
    {
        "comments": [
            "//check for wineggdrop specific strings",
            "//check for MZ Signature at offset 0"
        ],
        "condition_terms": [
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5A4D",
            "and",
            "$a",
            "and",
            "$b",
            "and",
            "$c"
        ],
        "metadata": [
            {
                "author": "Christian Rebischke (@sh1bumi)"
            },
            {
                "date": "2015-09-05"
            },
            {
                "description": "Rules for TCP Portscanner VX.X by WinEggDrop"
            },
            {
                "in_the_wild": true
            },
            {
                "family": "Hackingtool/Portscanner"
            }
        ],
        "raw_condition": "condition:\n        //check for MZ Signature at offset 0\n        uint16(0) == 0x5A4D\n\n        and\n\n        //check for wineggdrop specific strings\n        $a and $b and $c \n",
        "raw_meta": "meta:\n        author = \"Christian Rebischke (@sh1bumi)\"\n        date = \"2015-09-05\"\n        description = \"Rules for TCP Portscanner VX.X by WinEggDrop\"\n        in_the_wild = true\n        family = \"Hackingtool/Portscanner\"\n\n    ",
        "raw_strings": "strings:\n        $a = { 54 43 50 20 50 6f 72 74 20 53 63 61 6e 6e 65 72 \n               20 56 3? 2e 3? 20 42 79 20 57 69 6e 45 67 67 44 \n               72 6f 70 0a } \n        $b = \"Result.txt\"\n        $c = \"Usage:   %s TCP/SYN StartIP [EndIP] Ports [Threads] [/T(N)] [/(H)Banner] [/Save]\\n\"\n\n    ",
        "rule_name": "wineggdrop",
        "start_line": 1,
        "stop_line": 25,
        "strings": [
            {
                "name": "$a",
                "type": "byte",
                "value": "{ 54 43 50 20 50 6f 72 74 20 53 63 61 6e 6e 65 72 \n               20 56 3? 2e 3? 20 42 79 20 57 69 6e 45 67 67 44 \n               72 6f 70 0a }"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "Result.txt"
            },
            {
                "name": "$c",
                "type": "text",
                "value": "Usage:   %s TCP/SYN StartIP [EndIP] Ports [Threads] [/T(N)] [/(H)Banner] [/Save]\\n"
            }
        ],
        "tags": [
            "portscanner",
            "toolkit"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Retefe', NULL, '{"author": "bartblaze", "description": "Retefe"}', '[
    {
        "condition_terms": [
            "5",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "bartblaze"
            },
            {
                "description": "Retefe"
            }
        ],
        "raw_condition": "condition:\n\t5 of them\n",
        "raw_meta": "meta:\n\tauthor = \"bartblaze\"\n\tdescription = \"Retefe\"\n",
        "raw_strings": "strings:\n\t$string0 = \"01050000\"\n\t$string1 = \"00000000\"\n\t$string2 = \"5061636b61676500\"\n\t$string3 = \"000000000000000000000000000000000000000000000000000000000000000000000000000000\"\n\t$string4 = \"{\\\\stylesheet{ Normal;}{\\\\s1 heading 1;}{\\\\s2 heading 2;}}\"\n\t$string5 = \"02000000\"\n",
        "rule_name": "Retefe",
        "start_line": 7,
        "stop_line": 21,
        "strings": [
            {
                "name": "$string0",
                "type": "text",
                "value": "01050000"
            },
            {
                "name": "$string1",
                "type": "text",
                "value": "00000000"
            },
            {
                "name": "$string2",
                "type": "text",
                "value": "5061636b61676500"
            },
            {
                "name": "$string3",
                "type": "text",
                "value": "000000000000000000000000000000000000000000000000000000000000000000000000000000"
            },
            {
                "name": "$string4",
                "type": "text",
                "value": "{\\\\stylesheet{ Normal;}{\\\\s1 heading 1;}{\\\\s2 heading 2;}}"
            },
            {
                "name": "$string5",
                "type": "text",
                "value": "02000000"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'legion_777', NULL, '{"ref": "https://github.com/Daxda/malware-analysis/tree/master/malware_samples/legion", "date": "2016/6/6", "author": "Daxda (https://github.com/Daxda)", "sample": "SHA256: 14d22359e76cf63bf17268cad24bac03663c8b2b8028b869f5cec10fe3f75548", "category": "Ransomware", "description": "Detects an UPX-unpacked .777 ransomware binary."}', '[
    {
        "condition_terms": [
            "4",
            "of",
            "(",
            "$s*",
            ")"
        ],
        "metadata": [
            {
                "author": "Daxda (https://github.com/Daxda)"
            },
            {
                "date": "2016/6/6"
            },
            {
                "description": "Detects an UPX-unpacked .777 ransomware binary."
            },
            {
                "ref": "https://github.com/Daxda/malware-analysis/tree/master/malware_samples/legion"
            },
            {
                "category": "Ransomware"
            },
            {
                "sample": "SHA256: 14d22359e76cf63bf17268cad24bac03663c8b2b8028b869f5cec10fe3f75548"
            }
        ],
        "raw_condition": "condition:\n        4 of ($s*)\n",
        "raw_meta": "meta:\n        author = \"Daxda (https://github.com/Daxda)\"\n        date = \"2016/6/6\"\n        description = \"Detects an UPX-unpacked .777 ransomware binary.\"\n        ref = \"https://github.com/Daxda/malware-analysis/tree/master/malware_samples/legion\"\n        category = \"Ransomware\"\n        sample = \"SHA256: 14d22359e76cf63bf17268cad24bac03663c8b2b8028b869f5cec10fe3f75548\"\n\n    ",
        "raw_strings": "strings:\n        $s1 = \"http://tuginsaat.com/wp-content/themes/twentythirteen/stats.php\"\n        $s2 = \"read_this_file.txt\" wide // Ransom note filename.\n        $s3 = \"seven_legion@india.com\" // Part of the format string used to rename files.\n        $s4 = {46 4f 52 20 44 45 43 52 59 50 54 20 46 49 4c 45 53 0d 0a 53 45 4e 44 20 4f\n               4e 45 20 46 49 4c 45 20 49 4e 20 45 2d 4d 41 49 4c 0d 0a 73 65 76 65 6e 5f\n               6c 65 67 69 6f 6e 40 69 6e 64 69 61 2e 63 6f 6d } // Ransom note content.\n        $s5 = \"%s._%02i-%02i-%02i-%02i-%02i-%02i_$%s$.777\" // Renaming format string.\n\n    ",
        "rule_name": "legion_777",
        "start_line": 1,
        "stop_line": 22,
        "strings": [
            {
                "name": "$s1",
                "type": "text",
                "value": "http://tuginsaat.com/wp-content/themes/twentythirteen/stats.php"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s2",
                "type": "text",
                "value": "read_this_file.txt"
            },
            {
                "name": "$s3",
                "type": "text",
                "value": "seven_legion@india.com"
            },
            {
                "name": "$s4",
                "type": "byte",
                "value": "{46 4f 52 20 44 45 43 52 59 50 54 20 46 49 4c 45 53 0d 0a 53 45 4e 44 20 4f\n               4e 45 20 46 49 4c 45 20 49 4e 20 45 2d 4d 41 49 4c 0d 0a 73 65 76 65 6e 5f\n               6c 65 67 69 6f 6e 40 69 6e 64 69 61 2e 63 6f 6d }"
            },
            {
                "name": "$s5",
                "type": "text",
                "value": "%s._%02i-%02i-%02i-%02i-%02i-%02i_$%s$.777"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Fareit_Trojan_Oct15', NULL, '{"date": "2015-10-18", "hash1": "230ca0beba8ae712cfe578d2b8ec9581ce149a62486bef209b04eb11d8c088c3", "hash2": "3477d6bfd8313d37fedbd3d6ba74681dd7cb59040cabc2991655bdce95a2a997", "hash3": "408fa0bd4d44de2940605986b554e8dab42f5d28a6a525b4bc41285e37ab488d", "hash4": "76669cbe6a6aac4aa52dbe9d2e027ba184bf3f0b425f478e8c049637624b5dae", "hash5": "9486b73eac92497e703615479d52c85cfb772b4ca6c846ef317729910e7c545f", "hash6": "c3300c648aebac7bf1d90f58ea75660c78604410ca0fa705d3b8ec1e0a45cdd9", "hash7": "ff83e9fcfdec4ffc748e0095391f84a8064ac958a274b9684a771058c04cb0fa", "score": 80, "author": "Florian Roth", "reference": "http://goo.gl/5VYtlU", "super_rule": 1, "description": "Detects Fareit Trojan from Sep/Oct 2015 Wave"}', '[
    {
        "condition_terms": [
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "$s1",
            "in",
            "(",
            "0",
            "..",
            "30000",
            ")",
            "and",
            "$s2",
            "in",
            "(",
            "0",
            "..",
            "30000",
            ")"
        ],
        "metadata": [
            {
                "description": "Detects Fareit Trojan from Sep/Oct 2015 Wave"
            },
            {
                "author": "Florian Roth"
            },
            {
                "reference": "http://goo.gl/5VYtlU"
            },
            {
                "date": "2015-10-18"
            },
            {
                "score": 80
            },
            {
                "super_rule": 1
            },
            {
                "hash1": "230ca0beba8ae712cfe578d2b8ec9581ce149a62486bef209b04eb11d8c088c3"
            },
            {
                "hash2": "3477d6bfd8313d37fedbd3d6ba74681dd7cb59040cabc2991655bdce95a2a997"
            },
            {
                "hash3": "408fa0bd4d44de2940605986b554e8dab42f5d28a6a525b4bc41285e37ab488d"
            },
            {
                "hash4": "76669cbe6a6aac4aa52dbe9d2e027ba184bf3f0b425f478e8c049637624b5dae"
            },
            {
                "hash5": "9486b73eac92497e703615479d52c85cfb772b4ca6c846ef317729910e7c545f"
            },
            {
                "hash6": "c3300c648aebac7bf1d90f58ea75660c78604410ca0fa705d3b8ec1e0a45cdd9"
            },
            {
                "hash7": "ff83e9fcfdec4ffc748e0095391f84a8064ac958a274b9684a771058c04cb0fa"
            }
        ],
        "raw_condition": "condition:\n\t\tuint16(0) == 0x5a4d and $s1 in (0..30000) and $s2 in (0..30000)\n",
        "raw_meta": "meta:\n\t\tdescription = \"Detects Fareit Trojan from Sep/Oct 2015 Wave\"\n\t\tauthor = \"Florian Roth\"\n\t\treference = \"http://goo.gl/5VYtlU\"\n\t\tdate = \"2015-10-18\"\n\t\tscore = 80\n\t\tsuper_rule = 1\n\t\thash1 = \"230ca0beba8ae712cfe578d2b8ec9581ce149a62486bef209b04eb11d8c088c3\"\n\t\thash2 = \"3477d6bfd8313d37fedbd3d6ba74681dd7cb59040cabc2991655bdce95a2a997\"\n\t\thash3 = \"408fa0bd4d44de2940605986b554e8dab42f5d28a6a525b4bc41285e37ab488d\"\n\t\thash4 = \"76669cbe6a6aac4aa52dbe9d2e027ba184bf3f0b425f478e8c049637624b5dae\"\n\t\thash5 = \"9486b73eac92497e703615479d52c85cfb772b4ca6c846ef317729910e7c545f\"\n\t\thash6 = \"c3300c648aebac7bf1d90f58ea75660c78604410ca0fa705d3b8ec1e0a45cdd9\"\n\t\thash7 = \"ff83e9fcfdec4ffc748e0095391f84a8064ac958a274b9684a771058c04cb0fa\"\n\t",
        "raw_strings": "strings:\n\t\t$s1 = \"ebai.exe\" fullword wide\n\t\t$s2 = \"Origina\" fullword wide\n\t",
        "rule_name": "Fareit_Trojan_Oct15",
        "start_line": 12,
        "stop_line": 32,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s1",
                "type": "text",
                "value": "ebai.exe"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s2",
                "type": "text",
                "value": "Origina"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'lateral_movement', NULL, '{"date": "3/12/2014", "author": "https://github.com/reed1713", "description": "methodology sig looking for signs of lateral movement"}', '[
    {
        "condition_terms": [
            "(",
            "$type",
            "and",
            "$eventid",
            "and",
            "$data",
            ")",
            "or",
            "(",
            "$type1",
            "and",
            "$eventid1",
            "and",
            "$data1",
            ")",
            "or",
            "(",
            "$type2",
            "and",
            "$eventid2",
            "and",
            "$data2",
            ")"
        ],
        "metadata": [
            {
                "date": "3/12/2014"
            },
            {
                "author": "https://github.com/reed1713"
            },
            {
                "description": "methodology sig looking for signs of lateral movement"
            }
        ],
        "raw_condition": "condition:\n\t\t($type and $eventid and $data) or ($type1 and $eventid1 and $data1) or ($type2 and $eventid2 and $data2)\n",
        "raw_meta": "meta:\n\t\tdate = \"3/12/2014\"\n\t\tauthor = \"https://github.com/reed1713\"\n    description = \"methodology sig looking for signs of lateral movement\"\n\t",
        "raw_strings": "strings:\n\t\t$type=\"Microsoft-Windows-Security-Auditing\"\n\t\t$eventid=\"4688\"\n\t\t$data=\"PsExec.exe\"\n\n\t\t$type1=\"Microsoft-Windows-Security-Auditing\"\n\t\t$eventid1=\"4688\"\n\t\t$data1=\"Windows\\\\System32\\\\net.exe\"\n\n\t\t$type2=\"Microsoft-Windows-Security-Auditing\"\n\t\t$eventid2=\"4688\"\n\t\t$data2=\"Windows\\\\System32\\\\at.exe\"\n\t",
        "rule_name": "lateral_movement",
        "start_line": 6,
        "stop_line": 26,
        "strings": [
            {
                "name": "$type",
                "type": "text",
                "value": "Microsoft-Windows-Security-Auditing"
            },
            {
                "name": "$eventid",
                "type": "text",
                "value": "4688"
            },
            {
                "name": "$data",
                "type": "text",
                "value": "PsExec.exe"
            },
            {
                "name": "$type1",
                "type": "text",
                "value": "Microsoft-Windows-Security-Auditing"
            },
            {
                "name": "$eventid1",
                "type": "text",
                "value": "4688"
            },
            {
                "name": "$data1",
                "type": "text",
                "value": "Windows\\\\System32\\\\net.exe"
            },
            {
                "name": "$type2",
                "type": "text",
                "value": "Microsoft-Windows-Security-Auditing"
            },
            {
                "name": "$eventid2",
                "type": "text",
                "value": "4688"
            },
            {
                "name": "$data2",
                "type": "text",
                "value": "Windows\\\\System32\\\\at.exe"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'PoS_Malware_fastpos', '{FastPOS,POS,keylogger}', '{"date": "2016-05-18", "author": "Trend Micro, Inc.", "reference": "http://documents.trendmicro.com/assets/fastPOS-quick-and-easy-credit-card-theft.pdf", "description": "Used to detect FastPOS keyloggger + scraper", "sample_filetype": "exe"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "(",
            "$string*",
            ")"
        ],
        "metadata": [
            {
                "author": "Trend Micro, Inc."
            },
            {
                "date": "2016-05-18"
            },
            {
                "description": "Used to detect FastPOS keyloggger + scraper"
            },
            {
                "reference": "http://documents.trendmicro.com/assets/fastPOS-quick-and-easy-credit-card-theft.pdf"
            },
            {
                "sample_filetype": "exe"
            }
        ],
        "raw_condition": "condition:\nall of ($string*)\n",
        "raw_meta": "meta:\nauthor = \"Trend Micro, Inc.\"\ndate = \"2016-05-18\"\ndescription = \"Used to detect FastPOS keyloggger + scraper\"\nreference = \"http://documents.trendmicro.com/assets/fastPOS-quick-and-easy-credit-card-theft.pdf\"\nsample_filetype = \"exe\"\n",
        "raw_strings": "strings:\n$string1 = \"uniqyeidclaxemain\"\n$string2 = \"http://%s/cdosys.php\"\n$string3 = \"SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\"\n$string4 = \"\\\\The Hook\\\\Release\\\\The Hook.pdb\" nocase\n",
        "rule_name": "PoS_Malware_fastpos",
        "start_line": 6,
        "stop_line": 21,
        "strings": [
            {
                "name": "$string1",
                "type": "text",
                "value": "uniqyeidclaxemain"
            },
            {
                "name": "$string2",
                "type": "text",
                "value": "http://%s/cdosys.php"
            },
            {
                "name": "$string3",
                "type": "text",
                "value": "SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$string4",
                "type": "text",
                "value": "\\\\The Hook\\\\Release\\\\The Hook.pdb"
            }
        ],
        "tags": [
            "FastPOS",
            "POS",
            "keylogger"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'LogPOS', NULL, '{"md5": "af13e7583ed1b27c4ae219e344a37e2b", "author": "Morphick Security", "description": "Detects Versions of LogPOS"}', '[
    {
        "comments": [
            "//8B4008        mov eax, dword ptr [eax + 8]",
            "//8B401C        mov eax, dword ptr [eax + 0x1c]",
            "//8B400C        mov eax, dword ptr [eax + 0xc]"
        ],
        "condition_terms": [
            "$sc",
            "and",
            "1",
            "of",
            "(",
            "$mailslot",
            ",",
            "$get",
            ")"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "Morphick Security"
            },
            {
                "description": "Detects Versions of LogPOS"
            },
            {
                "md5": "af13e7583ed1b27c4ae219e344a37e2b"
            }
        ],
        "raw_condition": "condition:\n        $sc and 1 of ($mailslot,$get)\n",
        "raw_meta": "meta:\n        author = \"Morphick Security\"\n        description = \"Detects Versions of LogPOS\"\n        md5 = \"af13e7583ed1b27c4ae219e344a37e2b\"\n    ",
        "raw_strings": "strings:\n        $mailslot = \"\\\\\\\\.\\\\mailslot\\\\LogCC\"\n        $get = \"GET /%s?encoding=%c&t=%c&cc=%I64d&process=\"\n        //64A130000000      mov eax, dword ptr fs:[0x30]\n        //8B400C        mov eax, dword ptr [eax + 0xc]\n        //8B401C        mov eax, dword ptr [eax + 0x1c]\n        //8B4008        mov eax, dword ptr [eax + 8]\n        $sc = {64 A1 30 00 00 00 8B 40 0C 8B 40 1C 8B 40 08 }\n    ",
        "rule_name": "LogPOS",
        "start_line": 7,
        "stop_line": 23,
        "strings": [
            {
                "name": "$mailslot",
                "type": "text",
                "value": "\\\\\\\\.\\\\mailslot\\\\LogCC"
            },
            {
                "name": "$get",
                "type": "text",
                "value": "GET /%s?encoding=%c&t=%c&cc=%I64d&process="
            },
            {
                "name": "$sc",
                "type": "byte",
                "value": "{64 A1 30 00 00 00 8B 40 0C 8B 40 1C 8B 40 08 }"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'lost_door', '{Trojan}', '{"date": "23/02/2013", "author": "Kevin Falcoz", "description": "Lost Door"}', '[
    {
        "condition_terms": [
            "$signature1"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "Kevin Falcoz"
            },
            {
                "date": "23/02/2013"
            },
            {
                "description": "Lost Door"
            }
        ],
        "raw_condition": "condition:\n\t\t$signature1\n",
        "raw_meta": "meta:\n\t\tauthor=\"Kevin Falcoz\"\n\t\tdate=\"23/02/2013\"\n\t\tdescription=\"Lost Door\"\n\t\n\t",
        "raw_strings": "strings:\n\t\t$signature1={45 44 49 54 5F 53 45 52 56 45 52} /*EDIT_SERVER*/\n\t\t\n\t",
        "rule_name": "lost_door",
        "start_line": 8,
        "stop_line": 20,
        "strings": [
            {
                "name": "$signature1",
                "type": "byte",
                "value": "{45 44 49 54 5F 53 45 52 56 45 52}"
            }
        ],
        "tags": [
            "Trojan"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'xRAT', '{RAT}', '{"ref": "http://malwareconfig.com/stats/xRat", "date": "2014/04", "author": " Kevin Breen <kevin@techanarchy.net>", "maltype": "Remote Access Trojan", "filetype": "exe"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "(",
            "$v1*",
            ")",
            "or",
            "all",
            "of",
            "(",
            "$v2*",
            ")"
        ],
        "metadata": [
            {
                "author": " Kevin Breen <kevin@techanarchy.net>"
            },
            {
                "date": "2014/04"
            },
            {
                "ref": "http://malwareconfig.com/stats/xRat"
            },
            {
                "maltype": "Remote Access Trojan"
            },
            {
                "filetype": "exe"
            }
        ],
        "raw_condition": "condition:\n        all of ($v1*) or all of ($v2*)\n",
        "raw_meta": "meta:\n        author = \" Kevin Breen <kevin@techanarchy.net>\"\n        date = \"2014/04\"\n        ref = \"http://malwareconfig.com/stats/xRat\"\n        maltype = \"Remote Access Trojan\"\n        filetype = \"exe\"\n\n    ",
        "raw_strings": "strings:\n        $v1a = \"DecodeProductKey\"\n        $v1b = \"StartHTTPFlood\"\n        $v1c = \"CodeKey\"\n        $v1d = \"MESSAGEBOX\"\n        $v1e = \"GetFilezillaPasswords\"\n        $v1f = \"DataIn\"\n        $v1g = \"UDPzSockets\"\n        $v1h = {52 00 54 00 5F 00 52 00 43 00 44 00 41 00 54 00 41}\n\n        $v2a = \"<URL>k__BackingField\"\n        $v2b = \"<RunHidden>k__BackingField\"\n        $v2c = \"DownloadAndExecute\"\n        $v2d = \"-CHECK & PING -n 2 127.0.0.1 & EXIT\" wide\n        $v2e = \"england.png\" wide\n        $v2f = \"Showed Messagebox\" wide\n    ",
        "rule_name": "xRAT",
        "start_line": 1,
        "stop_line": 28,
        "strings": [
            {
                "name": "$v1a",
                "type": "text",
                "value": "DecodeProductKey"
            },
            {
                "name": "$v1b",
                "type": "text",
                "value": "StartHTTPFlood"
            },
            {
                "name": "$v1c",
                "type": "text",
                "value": "CodeKey"
            },
            {
                "name": "$v1d",
                "type": "text",
                "value": "MESSAGEBOX"
            },
            {
                "name": "$v1e",
                "type": "text",
                "value": "GetFilezillaPasswords"
            },
            {
                "name": "$v1f",
                "type": "text",
                "value": "DataIn"
            },
            {
                "name": "$v1g",
                "type": "text",
                "value": "UDPzSockets"
            },
            {
                "name": "$v1h",
                "type": "byte",
                "value": "{52 00 54 00 5F 00 52 00 43 00 44 00 41 00 54 00 41}"
            },
            {
                "name": "$v2a",
                "type": "text",
                "value": "<URL>k__BackingField"
            },
            {
                "name": "$v2b",
                "type": "text",
                "value": "<RunHidden>k__BackingField"
            },
            {
                "name": "$v2c",
                "type": "text",
                "value": "DownloadAndExecute"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$v2d",
                "type": "text",
                "value": "-CHECK & PING -n 2 127.0.0.1 & EXIT"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$v2e",
                "type": "text",
                "value": "england.png"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$v2f",
                "type": "text",
                "value": "Showed Messagebox"
            }
        ],
        "tags": [
            "RAT"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'VirutFileInfector', NULL, '{"data": "2017/08/04", "author": "D00RT <@D00RT_RM>", "reference": "http://reversingminds-blog.logdown.com", "description": "Virut (unknown version) fileinfector detection", "infected_sample1": "5755f09d445a5dcab3ea92d978c7c360", "infected_sample2": "2766e8e78ee10264cf1a3f5f4a16ff00"}', '[
    {
        "condition_terms": [
            "$sign",
            "and",
            "$func"
        ],
        "metadata": [
            {
                "author": "D00RT <@D00RT_RM>"
            },
            {
                "data": "2017/08/04"
            },
            {
                "description": "Virut (unknown version) fileinfector detection"
            },
            {
                "reference": "http://reversingminds-blog.logdown.com"
            },
            {
                "infected_sample1": "5755f09d445a5dcab3ea92d978c7c360"
            },
            {
                "infected_sample2": "68e508108ed94c8c391c70ef1d15e0f8"
            },
            {
                "infected_sample2": "2766e8e78ee10264cf1a3f5f4a16ff00"
            }
        ],
        "raw_condition": "condition:\n    \t$sign and $func\n",
        "raw_meta": "meta:\n    \tauthor = \"D00RT <@D00RT_RM>\"\n    \tdata = \"2017/08/04\"\n\n        description = \"Virut (unknown version) fileinfector detection\"\n        reference = \"http://reversingminds-blog.logdown.com\"\n\n        infected_sample1 = \"5755f09d445a5dcab3ea92d978c7c360\"\n        infected_sample2 = \"68e508108ed94c8c391c70ef1d15e0f8\"\n        infected_sample2 = \"2766e8e78ee10264cf1a3f5f4a16ff00\"\n\n\t",
        "raw_strings": "strings:\n    \t$sign = { F9 E8 22 00 00 00 ?? 31 EB 56 }\n        $func = { 52 C1 E9 1D 68 31 D4 00 00 58 5A 81 C1 94 01 00 00 80 4D 00 F0 89 6C 24 04 F7 D1 81 6C 24 04 }       \n \n    ",
        "rule_name": "VirutFileInfector",
        "start_line": 1,
        "stop_line": 20,
        "strings": [
            {
                "name": "$sign",
                "type": "byte",
                "value": "{ F9 E8 22 00 00 00 ?? 31 EB 56 }"
            },
            {
                "name": "$func",
                "type": "byte",
                "value": "{ 52 C1 E9 1D 68 31 D4 00 00 58 5A 81 C1 94 01 00 00 80 4D 00 F0 89 6C 24 04 F7 D1 81 6C 24 04 }"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'PoetRat_Doc', NULL, '{"Data": "6th May 2020", "Author": "Nishan Maharjan", "Description": "A yara rule to catch PoetRat Word Document"}', '[
    {
        "comments": [
            "// Python file strings in the word documents"
        ],
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "Author": "Nishan Maharjan"
            },
            {
                "Description": "A yara rule to catch PoetRat Word Document"
            },
            {
                "Data": "6th May 2020"
            }
        ],
        "raw_condition": "condition:\n    all of them        \n",
        "raw_meta": "meta:\n        Author = \"Nishan Maharjan\"\n        Description = \"A yara rule to catch PoetRat Word Document\"\n        Data = \"6th May 2020\"\n    ",
        "raw_strings": "strings:\n        $pythonRegEx = /(\\.py$|\\.pyc$|\\.pyd$|Python)/  // checking for python strings\n\n        // Python file strings in the word documents\n        $pythonFile1 = \"launcher.py\"\n        $zipFile = \"smile.zip\"\n        $pythonFile2 = \"smile_funs.py\"\n        $pythonFile3 = \"frown.py\"\n        $pythonFile4 = \"backer.py\"\n        $pythonFile5 = \"smile.py\"\n        $pythonFile6 = \"affine.py\" \n\n        // dlls and cmd strings\n        $dlls = /\\.dll/\n        $cmd = \"cmd\"\n        $exe = \".exe\"   \n    ",
        "rule_name": "PoetRat_Doc",
        "start_line": 1,
        "stop_line": 25,
        "strings": [
            {
                "name": "$pythonRegEx",
                "type": "regex",
                "value": "/(\\.py$|\\.pyc$|\\.pyd$|Python)/"
            },
            {
                "name": "$pythonFile1",
                "type": "text",
                "value": "launcher.py"
            },
            {
                "name": "$zipFile",
                "type": "text",
                "value": "smile.zip"
            },
            {
                "name": "$pythonFile2",
                "type": "text",
                "value": "smile_funs.py"
            },
            {
                "name": "$pythonFile3",
                "type": "text",
                "value": "frown.py"
            },
            {
                "name": "$pythonFile4",
                "type": "text",
                "value": "backer.py"
            },
            {
                "name": "$pythonFile5",
                "type": "text",
                "value": "smile.py"
            },
            {
                "name": "$pythonFile6",
                "type": "text",
                "value": "affine.py"
            },
            {
                "name": "$dlls",
                "type": "regex",
                "value": "/\\.dll/"
            },
            {
                "name": "$cmd",
                "type": "text",
                "value": "cmd"
            },
            {
                "name": "$exe",
                "type": "text",
                "value": ".exe"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'GoziRule', '{Gozi,Family}', '{"ref": "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html", "author": "CCN-CERT", "version": "1.0", "description": "Win32.Gozi"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Win32.Gozi"
            },
            {
                "author": "CCN-CERT"
            },
            {
                "version": "1.0"
            },
            {
                "ref": "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
            }
        ],
        "raw_condition": "condition:\n    all of them\n",
        "raw_meta": "meta:\n    description = \"Win32.Gozi\"\n    author = \"CCN-CERT\"\n    version = \"1.0\"\n    ref = \"https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html\"\n",
        "raw_strings": "strings:\n    $ = {63 00 6F 00 6F 00 6B 00 69 00 65 00 73 00 2E 00 73 00 71 00 6C 00 69 00 74 00 65 00 2D 00 6A 00 6F 00 75 00 72 00 6E 00 61 00 6C 00 00 00 4F 50 45 52 41 2E 45 58 45 00}\n",
        "rule_name": "GoziRule",
        "start_line": 5,
        "stop_line": 15,
        "strings": [
            {
                "name": "$",
                "type": "byte",
                "value": "{63 00 6F 00 6F 00 6B 00 69 00 65 00 73 00 2E 00 73 00 71 00 6C 00 69 00 74 00 65 00 2D 00 6A 00 6F 00 75 00 72 00 6E 00 61 00 6C 00 00 00 4F 50 45 52 41 2E 45 58 45 00}"
            }
        ],
        "tags": [
            "Gozi",
            "Family"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Scieron', NULL, '{"ref": "http://www.symantec.com/connect/tr/blogs/scarab-attackers-took-aim-select-russian-targets-2012", "date": "22.01.15", "author": "Symantec Security Response"}', '[
    {
        "comments": [
            "// .text:10001D8C FF 24 85 55 1F 00+                jmp     ds:off_10001F55[eax*4] ; switch jump",
            "// .text:10001D86 0F 87 DB 00 00 00                 ja      loc_10001E67    ; jumptable 10001D8C default case",
            "// .text:10002079 75 05                             jnz     short loc_10002080",
            "// .text:10002075 66 83 F8 7C                       cmp     ax, ''|''",
            "// .text:10002073 74 06                             jz      short loc_1000207B",
            "// .text:1000206F 66 83 F8 3B                       cmp     ax, '';''",
            "// .text:1000206D 74 0C                             jz      short loc_1000207B",
            "// .text:10002069 66 83 F8 2C                       cmp     ax, '',''"
        ],
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "Symantec Security Response"
            },
            {
                "ref": "http://www.symantec.com/connect/tr/blogs/scarab-attackers-took-aim-select-russian-targets-2012"
            },
            {
                "date": "22.01.15"
            }
        ],
        "raw_condition": "condition:\n        all of them\n",
        "raw_meta": "meta:\n        author = \"Symantec Security Response\"\n        ref = \"http://www.symantec.com/connect/tr/blogs/scarab-attackers-took-aim-select-russian-targets-2012\"\n        date = \"22.01.15\"\n\n    ",
        "raw_strings": "strings:\n        // .text:10002069 66 83 F8 2C                       cmp     ax, '',''\n        // .text:1000206D 74 0C                             jz      short loc_1000207B\n        // .text:1000206F 66 83 F8 3B                       cmp     ax, '';''\n        // .text:10002073 74 06                             jz      short loc_1000207B\n        // .text:10002075 66 83 F8 7C                       cmp     ax, ''|''\n        // .text:10002079 75 05                             jnz     short loc_10002080\n        $code1 = {66 83 F? 2C 74 0C 66 83 F? 3B 74 06 66 83 F? 7C 75 05}\n        \n        // .text:10001D83 83 F8 09                          cmp     eax, 9          ; switch 10 cases\n        // .text:10001D86 0F 87 DB 00 00 00                 ja      loc_10001E67    ; jumptable 10001D8C default case\n        // .text:10001D8C FF 24 85 55 1F 00+                jmp     ds:off_10001F55[eax*4] ; switch jump\n        $code2 = {83 F? 09 0F 87 ?? 0? 00 00 FF 24}\n        \n        $str1  = \"IP_PADDING_DATA\" wide ascii\n        $str2  = \"PORT_NUM\" wide ascii\n        \n    ",
        "rule_name": "Scieron",
        "start_line": 8,
        "stop_line": 34,
        "strings": [
            {
                "name": "$code1",
                "type": "byte",
                "value": "{66 83 F? 2C 74 0C 66 83 F? 3B 74 06 66 83 F? 7C 75 05}"
            },
            {
                "name": "$code2",
                "type": "byte",
                "value": "{83 F? 09 0F 87 ?? 0? 00 00 FF 24}"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$str1",
                "type": "text",
                "value": "IP_PADDING_DATA"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$str2",
                "type": "text",
                "value": "PORT_NUM"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'GEN_PowerShell', NULL, '{"author": "https://github.com/interleaved", "description": "Generic PowerShell Malware Rule"}', '[
    {
        "comments": [
            "/*$s7 = \"-noninteractive\" fullword ascii*/"
        ],
        "condition_terms": [
            "$s1",
            "and",
            "(",
            "(",
            "$s2",
            "or",
            "$s3",
            "or",
            "$s10",
            ")",
            "and",
            "(",
            "$s4",
            "or",
            "$s5",
            "or",
            "$s11",
            ")",
            "and",
            "(",
            "$s8",
            "or",
            "$s9",
            ")",
            ")"
        ],
        "metadata": [
            {
                "description": "Generic PowerShell Malware Rule"
            },
            {
                "author": "https://github.com/interleaved"
            }
        ],
        "raw_condition": "condition:\n        $s1 and (($s2 or $s3 or $s10) and ($s4 or $s5 or $s11) and ($s8 or $s9))\n",
        "raw_meta": "meta:\n        description = \"Generic PowerShell Malware Rule\"\n        author = \"https://github.com/interleaved\"\n    \n    ",
        "raw_strings": "strings:\n        $s1 = \"powershell\"\n        $s2 = \"-ep bypass\" nocase\n        $s3 = \"-nop\" nocase\n        $s10 = \"-executionpolicy bypass\" nocase\n        $s4 = \"-win hidden\" nocase\n        $s5 = \"-windowstyle hidden\" nocase\n        $s11 = \"-w hidden\" nocase\n        /*$s6 = \"-noni\" fullword ascii*/\n        /*$s7 = \"-noninteractive\" fullword ascii*/\n        $s8 = \"-enc\" nocase\n        $s9 = \"-encodedcommand\" nocase\n    \n    ",
        "rule_name": "GEN_PowerShell",
        "start_line": 5,
        "stop_line": 27,
        "strings": [
            {
                "name": "$s1",
                "type": "text",
                "value": "powershell"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$s2",
                "type": "text",
                "value": "-ep bypass"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$s3",
                "type": "text",
                "value": "-nop"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$s10",
                "type": "text",
                "value": "-executionpolicy bypass"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$s4",
                "type": "text",
                "value": "-win hidden"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$s5",
                "type": "text",
                "value": "-windowstyle hidden"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$s11",
                "type": "text",
                "value": "-w hidden"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$s8",
                "type": "text",
                "value": "-enc"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$s9",
                "type": "text",
                "value": "-encodedcommand"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Sakurel_backdoor', NULL, '{"ref": "https://github.com/reed1713", "maltype": "Sakurel backdoor", "reference": "http://www.microsoft.com/security/portal/threat/encyclopedia/entry.aspx?Name=Trojan:Win32/Sakurel.A#tab=2", "description": "malware creates a process in the temp directory and performs the sysprep UAC bypass method."}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "maltype": "Sakurel backdoor"
            },
            {
                "ref": "https://github.com/reed1713"
            },
            {
                "reference": "http://www.microsoft.com/security/portal/threat/encyclopedia/entry.aspx?Name=Trojan:Win32/Sakurel.A#tab=2"
            },
            {
                "description": "malware creates a process in the temp directory and performs the sysprep UAC bypass method."
            }
        ],
        "raw_condition": "condition:\n\t\tall of them\n",
        "raw_meta": "meta:\n\t\tmaltype = \"Sakurel backdoor\"\n    ref = \"https://github.com/reed1713\"\n\t\treference = \"http://www.microsoft.com/security/portal/threat/encyclopedia/entry.aspx?Name=Trojan:Win32/Sakurel.A#tab=2\"\n\t\tdescription = \"malware creates a process in the temp directory and performs the sysprep UAC bypass method.\"\n\t",
        "raw_strings": "strings:\n\t\t$type=\"Microsoft-Windows-Security-Auditing\"\n\t\t$eventid=\"4688\"\n\t\t$data=\"Windows\\\\System32\\\\sysprep\\\\sysprep.exe\" nocase\n\n\t\t$type1=\"Microsoft-Windows-Security-Auditing\"\n\t\t$eventid1=\"4688\"\n\t\t$data1=\"AppData\\\\Local\\\\Temp\\\\MicroMedia\\\\MediaCenter.exe\" nocase\n\t",
        "rule_name": "Sakurel_backdoor",
        "start_line": 5,
        "stop_line": 22,
        "strings": [
            {
                "name": "$type",
                "type": "text",
                "value": "Microsoft-Windows-Security-Auditing"
            },
            {
                "name": "$eventid",
                "type": "text",
                "value": "4688"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$data",
                "type": "text",
                "value": "Windows\\\\System32\\\\sysprep\\\\sysprep.exe"
            },
            {
                "name": "$type1",
                "type": "text",
                "value": "Microsoft-Windows-Security-Auditing"
            },
            {
                "name": "$eventid1",
                "type": "text",
                "value": "4688"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$data1",
                "type": "text",
                "value": "AppData\\\\Local\\\\Temp\\\\MicroMedia\\\\MediaCenter.exe"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Tinba2', '{banking}', '{"date": "2015/11/07", "hash1": "c7f662594f07776ab047b322150f6ed0", "hash2": "dc71ef1e55f1ddb36b3c41b1b95ae586", "hash3": "b788155cb82a7600f2ed1965cffc1e88", "author": "n3sfox <n3sfox@gmail.com>", "filetype": "memory", "reference": "https://securityintelligence.com/tinba-malware-reloaded-and-attacking-banks-around-the-world", "description": "Tinba 2 (DGA) banking trojan"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "(",
            "$str*",
            ")",
            "and",
            "$pubkey",
            "and",
            "$code1"
        ],
        "metadata": [
            {
                "author": "n3sfox <n3sfox@gmail.com>"
            },
            {
                "date": "2015/11/07"
            },
            {
                "description": "Tinba 2 (DGA) banking trojan"
            },
            {
                "reference": "https://securityintelligence.com/tinba-malware-reloaded-and-attacking-banks-around-the-world"
            },
            {
                "filetype": "memory"
            },
            {
                "hash1": "c7f662594f07776ab047b322150f6ed0"
            },
            {
                "hash2": "dc71ef1e55f1ddb36b3c41b1b95ae586"
            },
            {
                "hash3": "b788155cb82a7600f2ed1965cffc1e88"
            }
        ],
        "raw_condition": "condition:\n                all of ($str*) and $pubkey and $code1\n",
        "raw_meta": "meta:\n                author = \"n3sfox <n3sfox@gmail.com>\"\n                date = \"2015/11/07\"\n                description = \"Tinba 2 (DGA) banking trojan\"\n                reference = \"https://securityintelligence.com/tinba-malware-reloaded-and-attacking-banks-around-the-world\"\n                filetype = \"memory\"\n                hash1 = \"c7f662594f07776ab047b322150f6ed0\"\n                hash2 = \"dc71ef1e55f1ddb36b3c41b1b95ae586\"\n                hash3 = \"b788155cb82a7600f2ed1965cffc1e88\"\n\n        ",
        "raw_strings": "strings:\n                $str1 = \"MapViewOfFile\"\n                $str2 = \"OpenFileMapping\"\n                $str3 = \"NtCreateUserProcess\"\n                $str4 = \"NtQueryDirectoryFile\"\n                $str5 = \"RtlCreateUserThread\"\n                $str6 = \"DeleteUrlCacheEntry\"\n                $str7 = \"PR_Read\"\n                $str8 = \"PR_Write\"\n                $pubkey = \"BEGIN PUBLIC KEY\"\n                $code1 = {50 87 44 24 04 6A ?? E8}\n\n        ",
        "rule_name": "Tinba2",
        "start_line": 6,
        "stop_line": 31,
        "strings": [
            {
                "name": "$str1",
                "type": "text",
                "value": "MapViewOfFile"
            },
            {
                "name": "$str2",
                "type": "text",
                "value": "OpenFileMapping"
            },
            {
                "name": "$str3",
                "type": "text",
                "value": "NtCreateUserProcess"
            },
            {
                "name": "$str4",
                "type": "text",
                "value": "NtQueryDirectoryFile"
            },
            {
                "name": "$str5",
                "type": "text",
                "value": "RtlCreateUserThread"
            },
            {
                "name": "$str6",
                "type": "text",
                "value": "DeleteUrlCacheEntry"
            },
            {
                "name": "$str7",
                "type": "text",
                "value": "PR_Read"
            },
            {
                "name": "$str8",
                "type": "text",
                "value": "PR_Write"
            },
            {
                "name": "$pubkey",
                "type": "text",
                "value": "BEGIN PUBLIC KEY"
            },
            {
                "name": "$code1",
                "type": "byte",
                "value": "{50 87 44 24 04 6A ?? E8}"
            }
        ],
        "tags": [
            "banking"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'TidePool_Malware', NULL, '{"date": "2016-05-24", "hash1": "9d0a47bdf00f7bd332ddd4cf8d95dd11ebbb945dda3d72aac512512b48ad93ba", "hash2": "67c4e8ab0f12fae7b4aeb66f7e59e286bd98d3a77e5a291e8d58b3cfbc1514ed", "hash3": "2252dcd1b6afacde3f94d9557811bb769c4f0af3cb7a48ffe068d31bb7c30e18", "hash4": "38f2c86041e0446730479cdb9c530298c0c4936722975c4e7446544fd6dcac9f", "hash5": "9d0a47bdf00f7bd332ddd4cf8d95dd11ebbb945dda3d72aac512512b48ad93ba", "author": "Florian Roth", "reference": "http://goo.gl/m2CXWR", "description": "Detects TidePool malware mentioned in Ke3chang report by Palo Alto Networks"}', '[
    {
        "condition_terms": [
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "filesize",
            "<",
            "200KB",
            "and",
            "(",
            "1",
            "of",
            "(",
            "$x*",
            ")",
            ")",
            ")",
            "or",
            "(",
            "4",
            "of",
            "them",
            ")"
        ],
        "metadata": [
            {
                "description": "Detects TidePool malware mentioned in Ke3chang report by Palo Alto Networks"
            },
            {
                "author": "Florian Roth"
            },
            {
                "reference": "http://goo.gl/m2CXWR"
            },
            {
                "date": "2016-05-24"
            },
            {
                "hash1": "9d0a47bdf00f7bd332ddd4cf8d95dd11ebbb945dda3d72aac512512b48ad93ba"
            },
            {
                "hash2": "67c4e8ab0f12fae7b4aeb66f7e59e286bd98d3a77e5a291e8d58b3cfbc1514ed"
            },
            {
                "hash3": "2252dcd1b6afacde3f94d9557811bb769c4f0af3cb7a48ffe068d31bb7c30e18"
            },
            {
                "hash4": "38f2c86041e0446730479cdb9c530298c0c4936722975c4e7446544fd6dcac9f"
            },
            {
                "hash5": "9d0a47bdf00f7bd332ddd4cf8d95dd11ebbb945dda3d72aac512512b48ad93ba"
            }
        ],
        "raw_condition": "condition:\n        ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) ) ) or ( 4 of them )\n",
        "raw_meta": "meta:\n        description = \"Detects TidePool malware mentioned in Ke3chang report by Palo Alto Networks\"\n        author = \"Florian Roth\"\n        reference = \"http://goo.gl/m2CXWR\"\n        date = \"2016-05-24\"\n        hash1 = \"9d0a47bdf00f7bd332ddd4cf8d95dd11ebbb945dda3d72aac512512b48ad93ba\"\n        hash2 = \"67c4e8ab0f12fae7b4aeb66f7e59e286bd98d3a77e5a291e8d58b3cfbc1514ed\"\n        hash3 = \"2252dcd1b6afacde3f94d9557811bb769c4f0af3cb7a48ffe068d31bb7c30e18\"\n        hash4 = \"38f2c86041e0446730479cdb9c530298c0c4936722975c4e7446544fd6dcac9f\"\n        hash5 = \"9d0a47bdf00f7bd332ddd4cf8d95dd11ebbb945dda3d72aac512512b48ad93ba\"\n\n    ",
        "raw_strings": "strings:\n        $x1 = \"Content-Disposition: form-data; name=\\\"m1.jpg\\\"\" fullword ascii\n        $x2 = \"C:\\\\PROGRA~2\\\\IEHelper\\\\mshtml.dll\" fullword wide\n        $x3 = \"C:\\\\DOCUME~1\\\\ALLUSE~1\\\\IEHelper\\\\mshtml.dll\" fullword wide\n        $x4 = \"IEComDll.dat\" fullword ascii\n        $s1 = \"Content-Type: multipart/form-data; boundary=----=_Part_%x\" fullword wide\n        $s2 = \"C:\\\\Windows\\\\System32\\\\rundll32.exe\" fullword wide\n        $s3 = \"network.proxy.socks_port\\\", \" fullword ascii\n    \n    ",
        "rule_name": "TidePool_Malware",
        "start_line": 15,
        "stop_line": 40,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$x1",
                "type": "text",
                "value": "Content-Disposition: form-data; name=\\\"m1.jpg\\\""
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$x2",
                "type": "text",
                "value": "C:\\\\PROGRA~2\\\\IEHelper\\\\mshtml.dll"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$x3",
                "type": "text",
                "value": "C:\\\\DOCUME~1\\\\ALLUSE~1\\\\IEHelper\\\\mshtml.dll"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$x4",
                "type": "text",
                "value": "IEComDll.dat"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s1",
                "type": "text",
                "value": "Content-Type: multipart/form-data; boundary=----=_Part_%x"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s2",
                "type": "text",
                "value": "C:\\\\Windows\\\\System32\\\\rundll32.exe"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s3",
                "type": "text",
                "value": "network.proxy.socks_port\\\", "
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'pony', NULL, '{"date": "2014-08-16", "author": "Brian Wallace @botnet_hunter", "description": "Identify Pony", "author_email": "bwall@ballastsecurity.net"}', '[
    {
        "comments": [
            "//$useragent2 = \"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/5.0)\""
        ],
        "condition_terms": [
            "$s1",
            "and",
            "$s2",
            "and",
            "$s3",
            "and",
            "$s4"
        ],
        "metadata": [
            {
                "author": "Brian Wallace @botnet_hunter"
            },
            {
                "author_email": "bwall@ballastsecurity.net"
            },
            {
                "date": "2014-08-16"
            },
            {
                "description": "Identify Pony"
            }
        ],
        "raw_condition": "condition:\n        $s1 and $s2 and $s3 and $s4\n",
        "raw_meta": "meta:\n        author = \"Brian Wallace @botnet_hunter\"\n        author_email = \"bwall@ballastsecurity.net\"\n        date = \"2014-08-16\"\n        description = \"Identify Pony\"\n\t",
        "raw_strings": "strings:\n    \t$s1 = \"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\"\n    \t$s2 = \"YUIPWDFILE0YUIPKDFILE0YUICRYPTED0YUI1.0\"\n    \t$s3 = \"POST %s HTTP/1.0\"\n    \t$s4 = \"Accept-Encoding: identity, *;q=0\"\n\n    \t//$useragent1 = \"Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)\"\n    \t//$useragent2 = \"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/5.0)\"\n    ",
        "rule_name": "pony",
        "start_line": 4,
        "stop_line": 20,
        "strings": [
            {
                "name": "$s1",
                "type": "text",
                "value": "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"
            },
            {
                "name": "$s2",
                "type": "text",
                "value": "YUIPWDFILE0YUIPKDFILE0YUICRYPTED0YUI1.0"
            },
            {
                "name": "$s3",
                "type": "text",
                "value": "POST %s HTTP/1.0"
            },
            {
                "name": "$s4",
                "type": "text",
                "value": "Accept-Encoding: identity, *;q=0"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'alina', NULL, '{"date": "2014-08-09", "author": "Brian Wallace @botnet_hunter", "description": "Identify Alina", "author_email": "bwall@ballastsecurity.net"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Brian Wallace @botnet_hunter"
            },
            {
                "author_email": "bwall@ballastsecurity.net"
            },
            {
                "date": "2014-08-09"
            },
            {
                "description": "Identify Alina"
            }
        ],
        "raw_condition": "condition:\n        \tall of them\n",
        "raw_meta": "meta:\n\t\tauthor = \"Brian Wallace @botnet_hunter\"\n\t\tauthor_email = \"bwall@ballastsecurity.net\"\n\t\tdate = \"2014-08-09\"\n\t\tdescription = \"Identify Alina\"\n\t",
        "raw_strings": "strings:\n\t\t$s1 = \"Alina v1.0\"\n\t\t$s2 = \"POST\"\n\t\t$s3 = \"1[0-2])[0-9]\"\n\n\t",
        "rule_name": "alina",
        "start_line": 5,
        "stop_line": 19,
        "strings": [
            {
                "name": "$s1",
                "type": "text",
                "value": "Alina v1.0"
            },
            {
                "name": "$s2",
                "type": "text",
                "value": "POST"
            },
            {
                "name": "$s3",
                "type": "text",
                "value": "1[0-2])[0-9]"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'jRAT_conf', '{RAT}', '{"date": "2013-10-11", "ref1": "https://github.com/MalwareLu/config_extractor/blob/master/config_jRAT.py", "ref2": "http://www.ghettoforensics.com/2013/10/dumping-malware-configuration-data-from.html", "author": "Jean-Philippe Teissier / @Jipe_", "version": "1.0", "filetype": "memory", "description": "jRAT configuration"}', '[
    {
        "condition_terms": [
            "$a"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "description": "jRAT configuration"
            },
            {
                "author": "Jean-Philippe Teissier / @Jipe_"
            },
            {
                "date": "2013-10-11"
            },
            {
                "filetype": "memory"
            },
            {
                "version": "1.0"
            },
            {
                "ref1": "https://github.com/MalwareLu/config_extractor/blob/master/config_jRAT.py"
            },
            {
                "ref2": "http://www.ghettoforensics.com/2013/10/dumping-malware-configuration-data-from.html"
            }
        ],
        "raw_condition": "condition: \n\t\t$a\n",
        "raw_meta": "meta:\n\t\tdescription = \"jRAT configuration\" \n\t\tauthor = \"Jean-Philippe Teissier / @Jipe_\"\n\t\tdate = \"2013-10-11\"\n\t\tfiletype = \"memory\"\n\t\tversion = \"1.0\" \n\t\tref1 = \"https://github.com/MalwareLu/config_extractor/blob/master/config_jRAT.py\" \n\t\tref2 = \"http://www.ghettoforensics.com/2013/10/dumping-malware-configuration-data-from.html\" \n\n\t",
        "raw_strings": "strings:\n\t\t$a = /port=[0-9]{1,5}SPLIT/ \n\n\t",
        "rule_name": "jRAT_conf",
        "start_line": 7,
        "stop_line": 23,
        "strings": [
            {
                "name": "$a",
                "type": "regex",
                "value": "/port=[0-9]{1,5}SPLIT/"
            }
        ],
        "tags": [
            "RAT"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'volgmer', NULL, '{"ref": "https://www.us-cert.gov/ncas/alerts/TA17-318B", "description": "Malformed User Agent"}', '[
    {
        "condition_terms": [
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5A4D",
            "and",
            "uint16",
            "(",
            "uint32",
            "(",
            "0x3c",
            ")",
            ")",
            "==",
            "0x4550",
            ")",
            "and",
            "$s"
        ],
        "metadata": [
            {
                "description": "Malformed User Agent"
            },
            {
                "ref": "https://www.us-cert.gov/ncas/alerts/TA17-318B"
            }
        ],
        "raw_condition": "condition:\n    (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and $s\n",
        "raw_meta": "meta:\n    description = \"Malformed User Agent\"\n    ref = \"https://www.us-cert.gov/ncas/alerts/TA17-318B\"\n",
        "raw_strings": "strings:\n    $s = \"Mozillar/\"\n",
        "rule_name": "volgmer",
        "start_line": 1,
        "stop_line": 10,
        "strings": [
            {
                "name": "$s",
                "type": "text",
                "value": "Mozillar/"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'suspicious_packer_section', '{packer,PE}', '{"date": "2016/10/21", "author": "@j0sm1", "filetype": "binary", "reference": "http://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/", "description": "The packer/protector section names/keywords"}', '[
    {
        "comments": [
            "// DOS stub signature                           PE signature"
        ],
        "condition_terms": [
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "uint32be",
            "(",
            "uint32",
            "(",
            "0x3c",
            ")",
            ")",
            "==",
            "0x50450000",
            "and",
            "(",
            "for",
            "any",
            "of",
            "them",
            ":",
            "(",
            "$",
            "in",
            "(",
            "0",
            "..",
            "1024",
            ")",
            ")",
            ")"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "@j0sm1"
            },
            {
                "date": "2016/10/21"
            },
            {
                "description": "The packer/protector section names/keywords"
            },
            {
                "reference": "http://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/"
            },
            {
                "filetype": "binary"
            }
        ],
        "raw_condition": "condition:\n        // DOS stub signature                           PE signature\n        uint16(0) == 0x5a4d and uint32be(uint32(0x3c)) == 0x50450000 and (\n            for any of them : ( $ in (0..1024) )\n        )\n",
        "raw_meta": "meta:\n\n        author = \"@j0sm1\"\n        date = \"2016/10/21\"\n        description = \"The packer/protector section names/keywords\"\n        reference = \"http://www.hexacorn.com/blog/2012/10/14/random-stats-from-1-2m-samples-pe-section-names/\"\n        filetype = \"binary\"\n\n    ",
        "raw_strings": "strings:\n\n        $s1 = \".aspack\" wide ascii\n        $s2 = \".adata\" wide ascii\n        $s3 = \"ASPack\" wide ascii\n        $s4 = \".ASPack\" wide ascii\n        $s5 = \".ccg\" wide ascii\n        $s6 = \"BitArts\" wide ascii\n        $s7 = \"DAStub\" wide ascii\n        $s8 = \"!EPack\" wide ascii\n        $s9 = \"FSG!\" wide ascii\n        $s10 = \"kkrunchy\" wide ascii\n        $s11 = \".mackt\" wide ascii\n        $s12 = \".MaskPE\" wide ascii\n        $s13 = \"MEW\" wide ascii\n        $s14 = \".MPRESS1\" wide ascii\n        $s15 = \".MPRESS2\" wide ascii\n        $s16 = \".neolite\" wide ascii\n        $s17 = \".neolit\" wide ascii\n        $s18 = \".nsp1\" wide ascii\n        $s19 = \".nsp2\" wide ascii\n        $s20 = \".nsp0\" wide ascii\n        $s21 = \"nsp0\" wide ascii\n        $s22 = \"nsp1\" wide ascii\n        $s23 = \"nsp2\" wide ascii\n        $s24 = \".packed\" wide ascii\n        $s25 = \"pebundle\" wide ascii\n        $s26 = \"PEBundle\" wide ascii\n        $s27 = \"PEC2TO\" wide ascii\n        $s28 = \"PECompact2\" wide ascii\n        $s29 = \"PEC2\" wide ascii\n        $s30 = \"pec1\" wide ascii\n        $s31 = \"pec2\" wide ascii\n        $s32 = \"PEC2MO\" wide ascii\n        $s33 = \"PELOCKnt\" wide ascii\n        $s34 = \".perplex\" wide ascii\n        $s35 = \"PESHiELD\" wide ascii\n        $s36 = \".petite\" wide ascii\n        $s37 = \"ProCrypt\" wide ascii\n        $s38 = \".RLPack\" wide ascii\n        $s39 = \"RCryptor\" wide ascii\n        $s40 = \".RPCrypt\" wide ascii\n        $s41 = \".sforce3\" wide ascii\n        $s42 = \".spack\" wide ascii\n        $s43 = \".svkp\" wide ascii\n        $s44 = \"Themida\" wide ascii\n        $s45 = \".Themida\" wide ascii\n        $s46 = \".packed\" wide ascii\n        $s47 = \".Upack\" wide ascii\n        $s48 = \".ByDwing\" wide ascii\n        $s49 = \"UPX0\" wide ascii\n        $s50 = \"UPX1\" wide ascii\n        $s51 = \"UPX2\" wide ascii\n        $s52 = \".UPX0\" wide ascii\n        $s53 = \".UPX1\" wide ascii\n        $s54 = \".UPX2\" wide ascii\n        $s55 = \".vmp0\" wide ascii\n        $s56 = \".vmp1\" wide ascii\n        $s57 = \".vmp2\" wide ascii\n        $s58 = \"VProtect\" wide ascii\n        $s59 = \"WinLicen\" wide ascii\n        $s60 = \"WWPACK\" wide ascii\n        $s61 = \".yP\" wide ascii\n        $s62 = \".y0da\" wide ascii\n        $s63 = \"UPX!\" wide ascii\n\n    ",
        "rule_name": "suspicious_packer_section",
        "start_line": 8,
        "stop_line": 89,
        "strings": [
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": ".aspack"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s2",
                "type": "text",
                "value": ".adata"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s3",
                "type": "text",
                "value": "ASPack"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s4",
                "type": "text",
                "value": ".ASPack"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s5",
                "type": "text",
                "value": ".ccg"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s6",
                "type": "text",
                "value": "BitArts"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s7",
                "type": "text",
                "value": "DAStub"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s8",
                "type": "text",
                "value": "!EPack"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s9",
                "type": "text",
                "value": "FSG!"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s10",
                "type": "text",
                "value": "kkrunchy"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s11",
                "type": "text",
                "value": ".mackt"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s12",
                "type": "text",
                "value": ".MaskPE"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s13",
                "type": "text",
                "value": "MEW"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s14",
                "type": "text",
                "value": ".MPRESS1"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s15",
                "type": "text",
                "value": ".MPRESS2"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s16",
                "type": "text",
                "value": ".neolite"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s17",
                "type": "text",
                "value": ".neolit"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s18",
                "type": "text",
                "value": ".nsp1"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s19",
                "type": "text",
                "value": ".nsp2"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s20",
                "type": "text",
                "value": ".nsp0"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s21",
                "type": "text",
                "value": "nsp0"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s22",
                "type": "text",
                "value": "nsp1"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s23",
                "type": "text",
                "value": "nsp2"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s24",
                "type": "text",
                "value": ".packed"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s25",
                "type": "text",
                "value": "pebundle"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s26",
                "type": "text",
                "value": "PEBundle"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s27",
                "type": "text",
                "value": "PEC2TO"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s28",
                "type": "text",
                "value": "PECompact2"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s29",
                "type": "text",
                "value": "PEC2"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s30",
                "type": "text",
                "value": "pec1"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s31",
                "type": "text",
                "value": "pec2"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s32",
                "type": "text",
                "value": "PEC2MO"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s33",
                "type": "text",
                "value": "PELOCKnt"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s34",
                "type": "text",
                "value": ".perplex"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s35",
                "type": "text",
                "value": "PESHiELD"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s36",
                "type": "text",
                "value": ".petite"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s37",
                "type": "text",
                "value": "ProCrypt"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s38",
                "type": "text",
                "value": ".RLPack"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s39",
                "type": "text",
                "value": "RCryptor"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s40",
                "type": "text",
                "value": ".RPCrypt"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s41",
                "type": "text",
                "value": ".sforce3"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s42",
                "type": "text",
                "value": ".spack"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s43",
                "type": "text",
                "value": ".svkp"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s44",
                "type": "text",
                "value": "Themida"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s45",
                "type": "text",
                "value": ".Themida"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s46",
                "type": "text",
                "value": ".packed"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s47",
                "type": "text",
                "value": ".Upack"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s48",
                "type": "text",
                "value": ".ByDwing"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s49",
                "type": "text",
                "value": "UPX0"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s50",
                "type": "text",
                "value": "UPX1"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s51",
                "type": "text",
                "value": "UPX2"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s52",
                "type": "text",
                "value": ".UPX0"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s53",
                "type": "text",
                "value": ".UPX1"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s54",
                "type": "text",
                "value": ".UPX2"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s55",
                "type": "text",
                "value": ".vmp0"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s56",
                "type": "text",
                "value": ".vmp1"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s57",
                "type": "text",
                "value": ".vmp2"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s58",
                "type": "text",
                "value": "VProtect"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s59",
                "type": "text",
                "value": "WinLicen"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s60",
                "type": "text",
                "value": "WWPACK"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s61",
                "type": "text",
                "value": ".yP"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s62",
                "type": "text",
                "value": ".y0da"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s63",
                "type": "text",
                "value": "UPX!"
            }
        ],
        "tags": [
            "packer",
            "PE"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'CAP_HookExKeylogger', NULL, '{"author": "Brian C. Bell -- @biebsmalwareguy", "reference": "https://github.com/DFIRnotes/rules/blob/master/CAP_HookExKeylogger.yar"}', '[
    {
        "condition_terms": [
            "2",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Brian C. Bell -- @biebsmalwareguy"
            },
            {
                "reference": "https://github.com/DFIRnotes/rules/blob/master/CAP_HookExKeylogger.yar"
            }
        ],
        "raw_condition": "condition:\n        2 of them\n",
        "raw_meta": "meta:\n    author = \"Brian C. Bell -- @biebsmalwareguy\"\n    reference = \"https://github.com/DFIRnotes/rules/blob/master/CAP_HookExKeylogger.yar\"\n\n    ",
        "raw_strings": "strings:\n    $str_Win32hookapi = \"SetWindowsHookEx\" nocase\n    $str_Win32llkey = \"WH_KEYBOARD_LL\" nocase\n    $str_Win32key = \"WH_KEYBOARD\" nocase\n\n    ",
        "rule_name": "CAP_HookExKeylogger",
        "start_line": 6,
        "stop_line": 20,
        "strings": [
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$str_Win32hookapi",
                "type": "text",
                "value": "SetWindowsHookEx"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$str_Win32llkey",
                "type": "text",
                "value": "WH_KEYBOARD_LL"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$str_Win32key",
                "type": "text",
                "value": "WH_KEYBOARD"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Molerats_certs', NULL, '{"Date": "2013/08/23", "Author": "FireEye Labs", "Reference": "https://www.fireeye.com/blog/threat-research/2013/08/operation-molerats-middle-east-cyber-attacks-using-poison-ivy.html", "Description": "this rule detections code signed with certificates used by the Molerats actor"}', '[
    {
        "condition_terms": [
            "1",
            "of",
            "(",
            "$cert*",
            ")"
        ],
        "metadata": [
            {
                "Author": "FireEye Labs"
            },
            {
                "Date": "2013/08/23"
            },
            {
                "Description": "this rule detections code signed with certificates used by the Molerats actor"
            },
            {
                "Reference": "https://www.fireeye.com/blog/threat-research/2013/08/operation-molerats-middle-east-cyber-attacks-using-poison-ivy.html"
            }
        ],
        "raw_condition": "condition:\n        1 of ($cert*)\n",
        "raw_meta": "meta:\n        Author      = \"FireEye Labs\"\n        Date        = \"2013/08/23\"\n        Description = \"this rule detections code signed with certificates used by the Molerats actor\"\n        Reference   = \"https://www.fireeye.com/blog/threat-research/2013/08/operation-molerats-middle-east-cyber-attacks-using-poison-ivy.html\"\n\n    ",
        "raw_strings": "strings:\n        $cert1 = { 06 50 11 A5 BC BF 83 C0 93 28 16 5E 7E 85 27 75 }\n        $cert2 = { 03 e1 e1 aa a5 bc a1 9f ba 8c 42 05 8b 4a bf 28 }\n        $cert3 = { 0c c0 35 9c 9c 3c da 00 d7 e9 da 2d c6 ba 7b 6d }\n\n    ",
        "rule_name": "Molerats_certs",
        "start_line": 6,
        "stop_line": 22,
        "strings": [
            {
                "name": "$cert1",
                "type": "byte",
                "value": "{ 06 50 11 A5 BC BF 83 C0 93 28 16 5E 7E 85 27 75 }"
            },
            {
                "name": "$cert2",
                "type": "byte",
                "value": "{ 03 e1 e1 aa a5 bc a1 9f ba 8c 42 05 8b 4a bf 28 }"
            },
            {
                "name": "$cert3",
                "type": "byte",
                "value": "{ 0c c0 35 9c 9c 3c da 00 d7 e9 da 2d c6 ba 7b 6d }"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'LuaBot', '{MALW}', '{"MD5": "9df3372f058874fa964548cbb74c74bf", "SHA1": "89226865501ee7d399354656d870b4a9c02db1d3", "date": "2017-06-07", "ref1": "http://blog.malwaremustdie.org/2016/09/mmd-0057-2016-new-elf-botnet-linuxluabot.html", "author": "Joan Soriano / @joanbtl", "version": "1.0", "description": "LuaBot"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "LuaBot"
            },
            {
                "author": "Joan Soriano / @joanbtl"
            },
            {
                "date": "2017-06-07"
            },
            {
                "version": "1.0"
            },
            {
                "MD5": "9df3372f058874fa964548cbb74c74bf"
            },
            {
                "SHA1": "89226865501ee7d399354656d870b4a9c02db1d3"
            },
            {
                "ref1": "http://blog.malwaremustdie.org/2016/09/mmd-0057-2016-new-elf-botnet-linuxluabot.html"
            }
        ],
        "raw_condition": "condition:\n                all of them\n",
        "raw_meta": "meta:\n                description = \"LuaBot\"\n                author = \"Joan Soriano / @joanbtl\"\n                date = \"2017-06-07\"\n                version = \"1.0\"\n                MD5 = \"9df3372f058874fa964548cbb74c74bf\"\n                SHA1 = \"89226865501ee7d399354656d870b4a9c02db1d3\"\n                ref1 = \"http://blog.malwaremustdie.org/2016/09/mmd-0057-2016-new-elf-botnet-linuxluabot.html\"\n\n        ",
        "raw_strings": "strings:\n                $a = \"LUA_PATH\"\n                $b = \"Hi. Happy reversing, you can mail me: luabot@yandex.ru\"\n                $c = \"/tmp/lua_XXXXXX\"\n                $d = \"NOTIFY\"\n                $e = \"UPDATE\"\n\n        ",
        "rule_name": "LuaBot",
        "start_line": 1,
        "stop_line": 21,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "LUA_PATH"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "Hi. Happy reversing, you can mail me: luabot@yandex.ru"
            },
            {
                "name": "$c",
                "type": "text",
                "value": "/tmp/lua_XXXXXX"
            },
            {
                "name": "$d",
                "type": "text",
                "value": "NOTIFY"
            },
            {
                "name": "$e",
                "type": "text",
                "value": "UPDATE"
            }
        ],
        "tags": [
            "MALW"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'yordanyan_activeagent', NULL, '{"date": "2018-10-04", "author": "J from THL <j@techhelplist.com>", "maltype": "Botnet", "filetype": "memory", "reference1": "https://www.virustotal.com/#/file/a2e34bfd5a9789837bc2d580e87ec11b9f29c4a50296ef45b06e3895ff399746/detection", "reference2": "ETPRO TROJAN Win32.ActiveAgent CnC Create", "description": "Memory string yara for Yordanyan ActiveAgent"}', '[
    {
        "comments": [
            "// the wide strings are 16bit bigendian strings in memory. strings -e b memdump.file"
        ],
        "condition_terms": [
            "15",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Memory string yara for Yordanyan ActiveAgent"
            },
            {
                "author": "J from THL <j@techhelplist.com>"
            },
            {
                "reference1": "https://www.virustotal.com/#/file/a2e34bfd5a9789837bc2d580e87ec11b9f29c4a50296ef45b06e3895ff399746/detection"
            },
            {
                "reference2": "ETPRO TROJAN Win32.ActiveAgent CnC Create"
            },
            {
                "date": "2018-10-04"
            },
            {
                "maltype": "Botnet"
            },
            {
                "filetype": "memory"
            }
        ],
        "raw_condition": "condition:\n\t\t15 of them\n\n",
        "raw_meta": "meta:\n\t\tdescription = \"Memory string yara for Yordanyan ActiveAgent\"\n\t\tauthor = \"J from THL <j@techhelplist.com>\"\n\t\treference1 = \"https://www.virustotal.com/#/file/a2e34bfd5a9789837bc2d580e87ec11b9f29c4a50296ef45b06e3895ff399746/detection\"\n\t\treference2 = \"ETPRO TROJAN Win32.ActiveAgent CnC Create\"\n\t\tdate = \"2018-10-04\"\n\t\tmaltype = \"Botnet\"\n\t\tfiletype = \"memory\"\n\n\t",
        "raw_strings": "strings:\n\t\t// the wide strings are 16bit bigendian strings in memory. strings -e b memdump.file\n\t\t$s01 = \"I''m KeepRunner!\" wide\n\t\t$s02 = \"I''m Updater!\" wide\n\t\t$s03 = \"Starting Download...\" wide\n\t\t$s04 = \"Download Complete!\" wide\n\t\t$s05 = \"Running New Agent and terminating updater!\" wide\n\t\t$s06 = \"Can''t Run downloaded file!\" wide\n\t\t$s07 = \"Retrying download and run!\" wide\n\t\t$s08 = \"Can''t init Client.\" wide\n\t\t$s09 = \"Client initialised -\" wide\n\t\t$s10 = \"Client not found!\" wide\n\t\t$s11 = \"Client signed.\" wide\n\t\t$s12 = \"GetClientData\" wide\n\t\t$s13 = \"&counter=\" wide\n\t\t$s14 = \"&agent_file_version=\" wide\n\t\t$s15 = \"&agent_id=\" wide\n\t\t$s16 = \"mac_address=\" wide\n\t\t$s17 = \"Getting Attachments\" wide\n\t\t$s18 = \"public_name\" wide\n\t\t$s19 = \"Yor agent id =\" wide\n\t\t$s20 = \"Yor agent version =\" wide\n\t\t$s21 = \"Last agent version =\" wide\n\t\t$s22 = \"Agent is last version.\" wide\n\t\t$s23 = \"Updating Agent\" wide\n\t\t$s24 = \"Terminating RunKeeper\" wide\n\t\t$s25 = \"Terminating RunKeeper: Done\" wide\n\t\t$s26 = \"ActiveAgent\" ascii\n\t\t$s27 = \"public_name\" ascii\n\n\t",
        "rule_name": "yordanyan_activeagent",
        "start_line": 2,
        "stop_line": 45,
        "strings": [
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s01",
                "type": "text",
                "value": "I''m KeepRunner!"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s02",
                "type": "text",
                "value": "I''m Updater!"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s03",
                "type": "text",
                "value": "Starting Download..."
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s04",
                "type": "text",
                "value": "Download Complete!"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s05",
                "type": "text",
                "value": "Running New Agent and terminating updater!"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s06",
                "type": "text",
                "value": "Can''t Run downloaded file!"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s07",
                "type": "text",
                "value": "Retrying download and run!"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s08",
                "type": "text",
                "value": "Can''t init Client."
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s09",
                "type": "text",
                "value": "Client initialised -"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s10",
                "type": "text",
                "value": "Client not found!"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s11",
                "type": "text",
                "value": "Client signed."
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s12",
                "type": "text",
                "value": "GetClientData"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s13",
                "type": "text",
                "value": "&counter="
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s14",
                "type": "text",
                "value": "&agent_file_version="
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s15",
                "type": "text",
                "value": "&agent_id="
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s16",
                "type": "text",
                "value": "mac_address="
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s17",
                "type": "text",
                "value": "Getting Attachments"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s18",
                "type": "text",
                "value": "public_name"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s19",
                "type": "text",
                "value": "Yor agent id ="
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s20",
                "type": "text",
                "value": "Yor agent version ="
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s21",
                "type": "text",
                "value": "Last agent version ="
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s22",
                "type": "text",
                "value": "Agent is last version."
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s23",
                "type": "text",
                "value": "Updating Agent"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s24",
                "type": "text",
                "value": "Terminating RunKeeper"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s25",
                "type": "text",
                "value": "Terminating RunKeeper: Done"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$s26",
                "type": "text",
                "value": "ActiveAgent"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$s27",
                "type": "text",
                "value": "public_name"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'FVEY_ShadowBrokers_Jan17_Screen_Strings', NULL, '{"date": "2017-01-08", "author": "Florian Roth", "reference": "https://bit.no.com:43110/theshadowbrokers.bit/post/message7/", "description": "Detects strings derived from the ShadowBroker''s leak of Windows tools/exploits"}', '[
    {
        "condition_terms": [
            "filesize",
            "<",
            "2000KB",
            "and",
            "(",
            "1",
            "of",
            "(",
            "$x*",
            ")",
            "or",
            "all",
            "of",
            "(",
            "$a*",
            ")",
            "or",
            "1",
            "of",
            "(",
            "$b*",
            ")",
            "or",
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "1",
            "of",
            "(",
            "$c*",
            ")",
            ")",
            "or",
            "3",
            "of",
            "(",
            "$c*",
            ")",
            "or",
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "3",
            "of",
            "(",
            "$d*",
            ")",
            ")",
            ")"
        ],
        "metadata": [
            {
                "description": "Detects strings derived from the ShadowBroker''s leak of Windows tools/exploits"
            },
            {
                "author": "Florian Roth"
            },
            {
                "reference": "https://bit.no.com:43110/theshadowbrokers.bit/post/message7/"
            },
            {
                "date": "2017-01-08"
            }
        ],
        "raw_condition": "condition:\n      filesize < 2000KB and (1 of ($x*) or all of ($a*) or 1 of ($b*) or ( uint16(0) == 0x5a4d and 1 of ($c*) ) or 3 of ($c*) or ( uint16(0) == 0x5a4d and 3 of ($d*) ))\n",
        "raw_meta": "meta:\n      description = \"Detects strings derived from the ShadowBroker''s leak of Windows tools/exploits\"\n      author = \"Florian Roth\"\n      reference = \"https://bit.no.com:43110/theshadowbrokers.bit/post/message7/\"\n      date = \"2017-01-08\"\n\n   ",
        "raw_strings": "strings:\n      $x1 = \"Danderspritz\" ascii wide fullword\n      $x2 = \"DanderSpritz\" ascii wide fullword\n      $x3 = \"PeddleCheap\" ascii wide fullword\n      $x4 = \"ChimneyPool Addres\" ascii wide fullword\n      $a1 = \"Getting remote time\" fullword ascii\n      $a2 = \"RETRIEVED\" fullword ascii\n      $b1 = \"Added Ops library to Python search path\" fullword ascii\n      $b2 = \"target: z0.0.0.1\" fullword ascii\n      $c1 = \"Psp_Avoidance\" fullword ascii\n      $c2 = \"PasswordDump\" fullword ascii\n      $c3 = \"InjectDll\" fullword ascii\n      $c4 = \"EventLogEdit\" fullword ascii\n      $c5 = \"ProcessModify\" fullword ascii\n      $d1 = \"Mcl_NtElevation\" fullword ascii wide\n      $d2 = \"Mcl_NtNativeApi\" fullword ascii wide\n      $d3 = \"Mcl_ThreatInject\" fullword ascii wide\n      $d4 = \"Mcl_NtMemory\" fullword ascii wide\n\n   ",
        "rule_name": "FVEY_ShadowBrokers_Jan17_Screen_Strings",
        "start_line": 14,
        "stop_line": 44,
        "strings": [
            {
                "modifiers": [
                    "ascii",
                    "wide",
                    "fullword"
                ],
                "name": "$x1",
                "type": "text",
                "value": "Danderspritz"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide",
                    "fullword"
                ],
                "name": "$x2",
                "type": "text",
                "value": "DanderSpritz"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide",
                    "fullword"
                ],
                "name": "$x3",
                "type": "text",
                "value": "PeddleCheap"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide",
                    "fullword"
                ],
                "name": "$x4",
                "type": "text",
                "value": "ChimneyPool Addres"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$a1",
                "type": "text",
                "value": "Getting remote time"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$a2",
                "type": "text",
                "value": "RETRIEVED"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$b1",
                "type": "text",
                "value": "Added Ops library to Python search path"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$b2",
                "type": "text",
                "value": "target: z0.0.0.1"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$c1",
                "type": "text",
                "value": "Psp_Avoidance"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$c2",
                "type": "text",
                "value": "PasswordDump"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$c3",
                "type": "text",
                "value": "InjectDll"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$c4",
                "type": "text",
                "value": "EventLogEdit"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$c5",
                "type": "text",
                "value": "ProcessModify"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii",
                    "wide"
                ],
                "name": "$d1",
                "type": "text",
                "value": "Mcl_NtElevation"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii",
                    "wide"
                ],
                "name": "$d2",
                "type": "text",
                "value": "Mcl_NtNativeApi"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii",
                    "wide"
                ],
                "name": "$d3",
                "type": "text",
                "value": "Mcl_ThreatInject"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii",
                    "wide"
                ],
                "name": "$d4",
                "type": "text",
                "value": "Mcl_NtMemory"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'backdoor_apt_pcclient', NULL, '{"date": "2012-10", "author": "@patrickrolsen", "maltype": "APT.PCCLient", "version": "0.1", "filetype": "DLL", "description": "Detects the dropper: 869fa4dfdbabfabe87d334f85ddda234 AKA dw20.dll/msacm32.drv dropped by 4a85af37de44daf5917f545c6fd03902 (RTF)"}', '[
    {
        "condition_terms": [
            "$magic",
            "at",
            "0",
            "and",
            "4",
            "of",
            "(",
            "$string*",
            ")"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "@patrickrolsen"
            },
            {
                "maltype": "APT.PCCLient"
            },
            {
                "filetype": "DLL"
            },
            {
                "version": "0.1"
            },
            {
                "description": "Detects the dropper: 869fa4dfdbabfabe87d334f85ddda234 AKA dw20.dll/msacm32.drv dropped by 4a85af37de44daf5917f545c6fd03902 (RTF)"
            },
            {
                "date": "2012-10"
            }
        ],
        "raw_condition": "condition:\n        $magic at 0 and 4 of ($string*)\n",
        "raw_meta": "meta:\n        author = \"@patrickrolsen\"\n        maltype = \"APT.PCCLient\"\n        filetype = \"DLL\"\n        version = \"0.1\"\n        description = \"Detects the dropper: 869fa4dfdbabfabe87d334f85ddda234 AKA dw20.dll/msacm32.drv dropped by 4a85af37de44daf5917f545c6fd03902 (RTF)\"\n        date = \"2012-10\"\n\n    ",
        "raw_strings": "strings:\n        $magic = { 4d 5a } // MZ\n        $string1 = \"www.micro1.zyns.com\"\n        $string2 = \"Mozilla/4.0 (compatible; MSIE 8.0; Win32)\"\n        $string3 = \"msacm32.drv\" wide\n        $string4 = \"C:\\\\Windows\\\\Explorer.exe\" wide\n        $string5 = \"Elevation:Administrator!\" wide\n        $string6 = \"C:\\\\Users\\\\cmd\\\\Desktop\\\\msacm32\\\\Release\\\\msacm32.pdb\"\n\n    ",
        "rule_name": "backdoor_apt_pcclient",
        "start_line": 8,
        "stop_line": 30,
        "strings": [
            {
                "name": "$magic",
                "type": "byte",
                "value": "{ 4d 5a }"
            },
            {
                "name": "$string1",
                "type": "text",
                "value": "www.micro1.zyns.com"
            },
            {
                "name": "$string2",
                "type": "text",
                "value": "Mozilla/4.0 (compatible; MSIE 8.0; Win32)"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$string3",
                "type": "text",
                "value": "msacm32.drv"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$string4",
                "type": "text",
                "value": "C:\\\\Windows\\\\Explorer.exe"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$string5",
                "type": "text",
                "value": "Elevation:Administrator!"
            },
            {
                "name": "$string6",
                "type": "text",
                "value": "C:\\\\Users\\\\cmd\\\\Desktop\\\\msacm32\\\\Release\\\\msacm32.pdb"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Ransom', '{Crypren}', '{"Author": "@pekeinfo", "weight": 1, "reference": "https://github.com/pekeinfo/DecryptCrypren"}', '[
    {
        "condition_terms": [
            "any",
            "of",
            "them"
        ],
        "metadata": [
            {
                "weight": 1
            },
            {
                "Author": "@pekeinfo"
            },
            {
                "reference": "https://github.com/pekeinfo/DecryptCrypren"
            }
        ],
        "raw_condition": "condition:\n        any of them\n",
        "raw_meta": "meta:\n        weight = 1\n        Author = \"@pekeinfo\"\n        reference = \"https://github.com/pekeinfo/DecryptCrypren\"\n    ",
        "raw_strings": "strings: \n        $a = \"won''t be able to recover your files anymore.</p>\"\n        $b = {6A 03 68 ?? ?? ?? ?? B9 74 F1 AE 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 98 3A 00 00 FF D6 6A 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ??}\n        $c = \"Please restart your computer and wait for instructions for decrypting your files\"\n    ",
        "rule_name": "Ransom",
        "start_line": 1,
        "stop_line": 12,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "won''t be able to recover your files anymore.</p>"
            },
            {
                "name": "$b",
                "type": "byte",
                "value": "{6A 03 68 ?? ?? ?? ?? B9 74 F1 AE 00 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 68 98 3A 00 00 FF D6 6A 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ??}"
            },
            {
                "name": "$c",
                "type": "text",
                "value": "Please restart your computer and wait for instructions for decrypting your files"
            }
        ],
        "tags": [
            "Crypren"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Mirai_Okiru', NULL, '{"date": "2018-01-05", "reference": "https://www.reddit.com/r/LinuxMalware/comments/7p00i3/quick_notes_for_okiru_satori_variant_of_mirai/", "description": "Detects Mirai Okiru MALW"}', '[
    {
        "comments": [
            "// $st07 = \"iptables -F\\n\" fullword nocase wide ascii"
        ],
        "condition_terms": [
            "all",
            "of",
            "them",
            "and",
            "is__elf",
            "and",
            "is__Mirai_gen7",
            "and",
            "filesize",
            "<",
            "100KB"
        ],
        "metadata": [
            {
                "description": "Detects Mirai Okiru MALW"
            },
            {
                "reference": "https://www.reddit.com/r/LinuxMalware/comments/7p00i3/quick_notes_for_okiru_satori_variant_of_mirai/"
            },
            {
                "date": "2018-01-05"
            }
        ],
        "raw_condition": "condition:\n    \t\tall of them\n\t\tand is__elf\n\t\tand is__Mirai_gen7\n\t\tand filesize < 100KB \n",
        "raw_meta": "meta:\n\t\tdescription = \"Detects Mirai Okiru MALW\"\n\t\treference = \"https://www.reddit.com/r/LinuxMalware/comments/7p00i3/quick_notes_for_okiru_satori_variant_of_mirai/\"\n\t\tdate = \"2018-01-05\"\n\n\t",
        "raw_strings": "strings:\n\t\t$hexsts01 = { 68 7f 27 70 60 62 73 3c 27 28 65 6e 69 28 65 72 }\n\t\t$hexsts02 = { 74 7e 65 68 7f 27 73 61 73 77 3c 27 28 65 6e 69 }\n\t\t// noted some Okiru variant doesnt have below function, uncomment to seek specific x86 bins\n    // $st07 = \"iptables -F\\n\" fullword nocase wide ascii\n    \n\t",
        "rule_name": "Mirai_Okiru",
        "start_line": 7,
        "stop_line": 24,
        "strings": [
            {
                "name": "$hexsts01",
                "type": "byte",
                "value": "{ 68 7f 27 70 60 62 73 3c 27 28 65 6e 69 28 65 72 }"
            },
            {
                "name": "$hexsts02",
                "type": "byte",
                "value": "{ 74 7e 65 68 7f 27 73 61 73 77 3c 27 28 65 6e 69 }"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'sig_8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93', NULL, '{"date": "2017-10-24", "hash1": "8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93", "author": "Christiaan Beek", "source": "https://pastebin.com/Y7pJv3tK", "reference": "BadRabbit", "description": "Bad Rabbit Ransomware"}', '[
    {
        "condition_terms": [
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "filesize",
            "<",
            "400KB",
            "and",
            "pe.imphash",
            "(",
            ")",
            "==",
            "\"94f57453c539227031b918edd52fc7f1\"",
            "and",
            "(",
            "1",
            "of",
            "(",
            "$x*",
            ")",
            "or",
            "4",
            "of",
            "them",
            ")",
            ")",
            "or",
            "(",
            "all",
            "of",
            "them",
            ")"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "description": "Bad Rabbit Ransomware"
            },
            {
                "author": "Christiaan Beek"
            },
            {
                "reference": "BadRabbit"
            },
            {
                "date": "2017-10-24"
            },
            {
                "hash1": "8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93"
            },
            {
                "source": "https://pastebin.com/Y7pJv3tK"
            }
        ],
        "raw_condition": "condition:\n      ( uint16(0) == 0x5a4d and\n        filesize < 400KB and\n        pe.imphash() == \"94f57453c539227031b918edd52fc7f1\" and\n        ( 1 of ($x*) or 4 of them )\n      ) or ( all of them )\n",
        "raw_meta": "meta:\n      description = \"Bad Rabbit Ransomware\"\n      author = \"Christiaan Beek\"\n      reference = \"BadRabbit\"\n      date = \"2017-10-24\"\n      hash1 = \"8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93\"\n      source = \"https://pastebin.com/Y7pJv3tK\"\n   ",
        "raw_strings": "strings:\n      $x1 = \"schtasks /Create /SC ONCE /TN viserion_%u /RU SYSTEM /TR \\\"%ws\\\" /ST %02d:%02d:00\" fullword wide\n      $x2 = \"need to do is submit the payment and get the decryption password.\" fullword ascii\n      $s3 = \"If you have already got the password, please enter it below.\" fullword ascii\n      $s4 = \"dispci.exe\" fullword wide\n      $s5 = \"\\\\\\\\.\\\\GLOBALROOT\\\\ArcName\\\\multi(0)disk(0)rdisk(0)partition(1)\" fullword wide\n      $s6 = \"Run DECRYPT app at your desktop after system boot\" fullword ascii\n      $s7 = \"Enter password#1: \" fullword wide\n      $s8 = \"Enter password#2: \" fullword wide\n      $s9 = \"C:\\\\Windows\\\\cscc.dat\" fullword wide\n      $s10 = \"schtasks /Delete /F /TN %ws\" fullword wide\n      $s11 = \"Password#1: \" fullword ascii\n      $s12 = \"\\\\AppData\" fullword wide\n      $s13 = \"Readme.txt\" fullword wide\n      $s14 = \"Disk decryption completed\" fullword wide\n      $s15 = \"Files decryption completed\" fullword wide\n      $s16 = \"http://diskcryptor.net/\" fullword wide\n      $s17 = \"Your personal installation key#1:\" fullword ascii\n      $s18 = \".3ds.7z.accdb.ai.asm.asp.aspx.avhd.back.bak.bmp.brw.c.cab.cc.cer.cfg.conf.cpp.crt.cs.ctl.cxx.dbf.der.dib.disk.djvu.doc.docx.dwg.\" wide\n      $s19 = \"Disable your anti-virus and anti-malware programs\" fullword wide\n      $s20 = \"bootable partition not mounted\" fullword ascii\n   ",
        "rule_name": "sig_8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93",
        "start_line": 3,
        "stop_line": 38,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$x1",
                "type": "text",
                "value": "schtasks /Create /SC ONCE /TN viserion_%u /RU SYSTEM /TR \\\"%ws\\\" /ST %02d:%02d:00"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$x2",
                "type": "text",
                "value": "need to do is submit the payment and get the decryption password."
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s3",
                "type": "text",
                "value": "If you have already got the password, please enter it below."
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s4",
                "type": "text",
                "value": "dispci.exe"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s5",
                "type": "text",
                "value": "\\\\\\\\.\\\\GLOBALROOT\\\\ArcName\\\\multi(0)disk(0)rdisk(0)partition(1)"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s6",
                "type": "text",
                "value": "Run DECRYPT app at your desktop after system boot"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s7",
                "type": "text",
                "value": "Enter password#1: "
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s8",
                "type": "text",
                "value": "Enter password#2: "
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s9",
                "type": "text",
                "value": "C:\\\\Windows\\\\cscc.dat"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s10",
                "type": "text",
                "value": "schtasks /Delete /F /TN %ws"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s11",
                "type": "text",
                "value": "Password#1: "
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s12",
                "type": "text",
                "value": "\\\\AppData"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s13",
                "type": "text",
                "value": "Readme.txt"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s14",
                "type": "text",
                "value": "Disk decryption completed"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s15",
                "type": "text",
                "value": "Files decryption completed"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s16",
                "type": "text",
                "value": "http://diskcryptor.net/"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s17",
                "type": "text",
                "value": "Your personal installation key#1:"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$s18",
                "type": "text",
                "value": ".3ds.7z.accdb.ai.asm.asp.aspx.avhd.back.bak.bmp.brw.c.cab.cc.cer.cfg.conf.cpp.crt.cs.ctl.cxx.dbf.der.dib.disk.djvu.doc.docx.dwg."
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s19",
                "type": "text",
                "value": "Disable your anti-virus and anti-malware programs"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s20",
                "type": "text",
                "value": "bootable partition not mounted"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'FUDCrypter', NULL, '{"author": "https://github.com/hwvs", "reference": "https://github.com/gigajew/FudCrypt/", "description": "Detects unmodified FUDCrypt samples", "last_modified": "2019-11-21"}', '[
    {
        "condition_terms": [
            "1",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Detects unmodified FUDCrypt samples"
            },
            {
                "reference": "https://github.com/gigajew/FudCrypt/"
            },
            {
                "author": "https://github.com/hwvs"
            },
            {
                "last_modified": "2019-11-21"
            }
        ],
        "raw_condition": "condition:\n        1 of them\n",
        "raw_meta": "meta:\n        description = \"Detects unmodified FUDCrypt samples\"\n        reference = \"https://github.com/gigajew/FudCrypt/\"\n        author = \"https://github.com/hwvs\"\n        last_modified = \"2019-11-21\"\n\n    ",
        "raw_strings": "strings:\n        $ = \"OcYjzPUtJkNbLOABqYvNbvhZf\" wide ascii\n        $ = \"gwiXxyIDDtoYzgMSRGMckRbJi\" wide ascii\n        $ = \"BclWgISTcaGjnwrzSCIuKruKm\" wide ascii\n        $ = \"CJyUSiUNrIVbgksjxpAMUkAJJ\" wide ascii\n        $ = \"fAMVdoPUEyHEWdxQIEJPRYbEN\" wide ascii\n        $ = \"CIGQUctdcUPqUjoucmcoffECY\" wide ascii\n        $ = \"wcZfHOgetgAExzSoWFJFQdAyO\" wide ascii\n        $ = \"DqYKDnIoLeZDWYlQWoxZnpfPR\" wide ascii\n        $ = \"MkhMoOHCbGUMqtnRDJKnBYnOj\" wide ascii\n        $ = \"sHEqLMGglkBAOIUfcSAgMvZfs\" wide ascii\n        $ = \"JtZApJhbFAIFxzHLjjyEQvtgd\" wide ascii\n        $ = \"IIQrSWZEMmoQIKGuxxwoTwXka\" wide ascii\n\n    ",
        "rule_name": "FUDCrypter",
        "start_line": 5,
        "stop_line": 29,
        "strings": [
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "OcYjzPUtJkNbLOABqYvNbvhZf"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "gwiXxyIDDtoYzgMSRGMckRbJi"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "BclWgISTcaGjnwrzSCIuKruKm"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "CJyUSiUNrIVbgksjxpAMUkAJJ"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "fAMVdoPUEyHEWdxQIEJPRYbEN"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "CIGQUctdcUPqUjoucmcoffECY"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "wcZfHOgetgAExzSoWFJFQdAyO"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "DqYKDnIoLeZDWYlQWoxZnpfPR"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "MkhMoOHCbGUMqtnRDJKnBYnOj"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "sHEqLMGglkBAOIUfcSAgMvZfs"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "JtZApJhbFAIFxzHLjjyEQvtgd"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "IIQrSWZEMmoQIKGuxxwoTwXka"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'BoousetCode', NULL, '{"author": "Seth Hardy", "description": "Boouset code tricks", "last_modified": "2014-06-19"}', '[
    {
        "condition_terms": [
            "any",
            "of",
            "them"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "description": "Boouset code tricks"
            },
            {
                "author": "Seth Hardy"
            },
            {
                "last_modified": "2014-06-19"
            }
        ],
        "raw_condition": "condition:\n        any of them\n",
        "raw_meta": "meta:\n        description = \"Boouset code tricks\"\n        author = \"Seth Hardy\"\n        last_modified = \"2014-06-19\"\n        \n    ",
        "raw_strings": "strings:\n        $boousetdat = { C6 ?? ?? ?? ?? 00 62 C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 75 }\n        \n    ",
        "rule_name": "BoousetCode",
        "start_line": 8,
        "stop_line": 21,
        "strings": [
            {
                "name": "$boousetdat",
                "type": "byte",
                "value": "{ C6 ?? ?? ?? ?? 00 62 C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 75 }"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'XHide', '{MALW}', '{"MD5": "c644c04bce21dacdeb1e6c14c081e359", "date": "2017-12-01", "SHA256": "59f5b21ef8a570c02453b5edb0e750a42a1382f6", "author": "Joan Soriano / @w0lfvan", "version": "1.0", "description": "XHide - Process Faker"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "XHide - Process Faker"
            },
            {
                "author": "Joan Soriano / @w0lfvan"
            },
            {
                "date": "2017-12-01"
            },
            {
                "version": "1.0"
            },
            {
                "MD5": "c644c04bce21dacdeb1e6c14c081e359"
            },
            {
                "SHA256": "59f5b21ef8a570c02453b5edb0e750a42a1382f6"
            }
        ],
        "raw_condition": "condition:\n\t\tall of them\n",
        "raw_meta": "meta:\n\t\tdescription = \"XHide - Process Faker\"\n\t\tauthor = \"Joan Soriano / @w0lfvan\"\n\t\tdate = \"2017-12-01\"\n\t\tversion = \"1.0\"\n\t\tMD5 = \"c644c04bce21dacdeb1e6c14c081e359\"\n\t\tSHA256 = \"59f5b21ef8a570c02453b5edb0e750a42a1382f6\"\n\t",
        "raw_strings": "strings:\n\t\t$a = \"XHide - Process Faker\"\n\t\t$b = \"Fakename: %s PidNum: %d\"\n\t",
        "rule_name": "XHide",
        "start_line": 1,
        "stop_line": 15,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "XHide - Process Faker"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "Fakename: %s PidNum: %d"
            }
        ],
        "tags": [
            "MALW"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Crimson', '{RAT}', '{"ref": "http://malwareconfig.com/stats/Crimson", "date": "2015/05", "author": " Kevin Breen <kevin@techanarchy.net>", "maltype": "Remote Access Trojan", "filetype": "jar", "Description": "Crimson Rat"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "(",
            "$a*",
            ")"
        ],
        "metadata": [
            {
                "author": " Kevin Breen <kevin@techanarchy.net>"
            },
            {
                "Description": "Crimson Rat"
            },
            {
                "date": "2015/05"
            },
            {
                "ref": "http://malwareconfig.com/stats/Crimson"
            },
            {
                "maltype": "Remote Access Trojan"
            },
            {
                "filetype": "jar"
            }
        ],
        "raw_condition": "condition:\n        all of ($a*)\n",
        "raw_meta": "meta:\n\t\tauthor = \" Kevin Breen <kevin@techanarchy.net>\"\n\t\tDescription = \"Crimson Rat\"\n\t\tdate = \"2015/05\"\n\t\tref = \"http://malwareconfig.com/stats/Crimson\"\n\t\tmaltype = \"Remote Access Trojan\"\n\t\tfiletype = \"jar\"\n\n\t",
        "raw_strings": "strings:\n\t\t$a1 = \"com/crimson/PK\"\n\t\t$a2 = \"com/crimson/bootstrapJar/PK\"\n\t\t$a3 = \"com/crimson/permaJarMulti/PermaJarReporter$1.classPK\"\n\t\t$a4 = \"com/crimson/universal/containers/KeyloggerLog.classPK\"\n        $a5 = \"com/crimson/universal/UploadTransfer.classPK\"\n        \n\t",
        "rule_name": "Crimson",
        "start_line": 1,
        "stop_line": 20,
        "strings": [
            {
                "name": "$a1",
                "type": "text",
                "value": "com/crimson/PK"
            },
            {
                "name": "$a2",
                "type": "text",
                "value": "com/crimson/bootstrapJar/PK"
            },
            {
                "name": "$a3",
                "type": "text",
                "value": "com/crimson/permaJarMulti/PermaJarReporter$1.classPK"
            },
            {
                "name": "$a4",
                "type": "text",
                "value": "com/crimson/universal/containers/KeyloggerLog.classPK"
            },
            {
                "name": "$a5",
                "type": "text",
                "value": "com/crimson/universal/UploadTransfer.classPK"
            }
        ],
        "tags": [
            "RAT"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'BeEF_browser_hooked', NULL, '{"date": "2015-10-07", "hash1": "587e611f49baf63097ad2421ad0299b7b8403169ec22456fb6286abf051228db", "author": "Pasquale Stirparo", "description": "Yara rule related to hook.js, BeEF Browser hooking capability"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Yara rule related to hook.js, BeEF Browser hooking capability"
            },
            {
                "author": "Pasquale Stirparo"
            },
            {
                "date": "2015-10-07"
            },
            {
                "hash1": "587e611f49baf63097ad2421ad0299b7b8403169ec22456fb6286abf051228db"
            }
        ],
        "raw_condition": "condition:\n\t\tall of them\n",
        "raw_meta": "meta:\n\t\tdescription = \"Yara rule related to hook.js, BeEF Browser hooking capability\"\n\t\tauthor = \"Pasquale Stirparo\"\n\t\tdate = \"2015-10-07\"\n\t\thash1 = \"587e611f49baf63097ad2421ad0299b7b8403169ec22456fb6286abf051228db\"\n\t\n\t",
        "raw_strings": "strings:\n\t\t$s0 = \"mitb.poisonAnchor\" wide ascii\n\t\t$s1 = \"this.request(this.httpproto\" wide ascii\n\t\t$s2 = \"beef.logger.get_dom_identifier\" wide ascii\n\t\t$s3 = \"return (!!window.opera\" wide ascii \n\t\t$s4 = \"history.pushState({ Be:\\\"EF\\\" }\" wide ascii \n\t\t$s5 = \"window.navigator.userAgent.match(/Opera\\\\/9\\\\.80.*Version\\\\/10\\\\./)\" wide ascii \n\t\t$s6 = \"window.navigator.userAgent.match(/Opera\\\\/9\\\\.80.*Version\\\\/11\\\\./)\" wide ascii \n\t\t$s7 = \"window.navigator.userAgent.match(/Avant TriCore/)\" wide ascii \n\t\t$s8 = \"window.navigator.userAgent.match(/Iceweasel\" wide ascii \n\t\t$s9 = \"mitb.sniff(\" wide ascii \n\t\t$s10 = \"Method XMLHttpRequest.open override\" wide ascii \n\t\t$s11 = \".browser.hasWebSocket\" wide ascii \n\t\t$s12 = \".mitb.poisonForm\" wide ascii \n\t\t$s13 = \"resolved=require.resolve(file,cwd||\" wide ascii \n\t\t$s14 = \"if (document.domain == domain.replace(/(\\\\r\\\\n|\\\\n|\\\\r)/gm\" wide ascii \n\t\t$s15 = \"beef.net.request\" wide ascii \n\t\t$s16 = \"uagent.search(engineOpera)\" wide ascii \n\t\t$s17 = \"mitb.sniff\" wide ascii\n\t\t$s18 = \"beef.logger.start\" wide ascii\n\t\n\t",
        "rule_name": "BeEF_browser_hooked",
        "start_line": 15,
        "stop_line": 46,
        "strings": [
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s0",
                "type": "text",
                "value": "mitb.poisonAnchor"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "this.request(this.httpproto"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s2",
                "type": "text",
                "value": "beef.logger.get_dom_identifier"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s3",
                "type": "text",
                "value": "return (!!window.opera"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s4",
                "type": "text",
                "value": "history.pushState({ Be:\\\"EF\\\" }"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s5",
                "type": "text",
                "value": "window.navigator.userAgent.match(/Opera\\\\/9\\\\.80.*Version\\\\/10\\\\./)"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s6",
                "type": "text",
                "value": "window.navigator.userAgent.match(/Opera\\\\/9\\\\.80.*Version\\\\/11\\\\./)"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s7",
                "type": "text",
                "value": "window.navigator.userAgent.match(/Avant TriCore/)"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s8",
                "type": "text",
                "value": "window.navigator.userAgent.match(/Iceweasel"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s9",
                "type": "text",
                "value": "mitb.sniff("
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s10",
                "type": "text",
                "value": "Method XMLHttpRequest.open override"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s11",
                "type": "text",
                "value": ".browser.hasWebSocket"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s12",
                "type": "text",
                "value": ".mitb.poisonForm"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s13",
                "type": "text",
                "value": "resolved=require.resolve(file,cwd||"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s14",
                "type": "text",
                "value": "if (document.domain == domain.replace(/(\\\\r\\\\n|\\\\n|\\\\r)/gm"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s15",
                "type": "text",
                "value": "beef.net.request"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s16",
                "type": "text",
                "value": "uagent.search(engineOpera)"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s17",
                "type": "text",
                "value": "mitb.sniff"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s18",
                "type": "text",
                "value": "beef.logger.start"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Generic_ATMPot', '{Generic_ATMPot}', '{"date": "2019-02-24", "author": "xylitol@temari.fr", "reference": "https://securelist.com/atm-robber-winpot/89611/", "description": "Generic rule for Winpot aka ATMPot"}', '[
    {
        "comments": [
            "// May only the challenge guide you"
        ],
        "condition_terms": [
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5A4D",
            "and",
            "uint32",
            "(",
            "uint32",
            "(",
            "0x3C",
            ")",
            ")",
            "==",
            "0x00004550",
            ")",
            "and",
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Generic rule for Winpot aka ATMPot"
            },
            {
                "author": "xylitol@temari.fr"
            },
            {
                "date": "2019-02-24"
            },
            {
                "reference": "https://securelist.com/atm-robber-winpot/89611/"
            }
        ],
        "raw_condition": "condition:  \n        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them\n",
        "raw_meta": "meta:\n        description = \"Generic rule for Winpot aka ATMPot\"\n        author = \"xylitol@temari.fr\"\n        date = \"2019-02-24\"\n        reference = \"https://securelist.com/atm-robber-winpot/89611/\"\n        // May only the challenge guide you\n    ",
        "raw_strings": "strings:\n        $api1 = \"CSCCNG\" ascii wide\n        $api2 = \"CscCngOpen\" ascii wide\n        $api3 = \"CscCngClose\" ascii wide\n        $string1 = \"%d,%02d;\" ascii wide\n/*\n0xD:\n.text:004022EC FF 15 20 70 40 00             CALL DWORD PTR DS:[407020]  ; cscwcng.CscCngDispense\n.text:004022F2 F6 C4 80                      TEST AH,80\nwinpot:\n.text:004019D4 FF 15 24 60 40 00             CALL DWORD PTR DS:[406024]  ; cscwcng.CscCngDispense\n.text:004019DA F6 C4 80                      TEST AH,80\n*/\n        $hex1 = { FF 15 ?? ?? ?? ?? F6 C4 80 }\n/*\n0xD...: 0040506E  25 31 5B 31 2D 34 5D 56 41 4C 3D 25 38 5B 30 2D 39 5D: %1[1-4]VAL=%8[0-9]\nwinpot: 0040404D  25 31 5B 30 2D 39 5D 56 41 4C 3D 25 38 5B 30 2D 39 5D: %1[0-9]VAL=%8[0-9]\n*/\n        $hex2 = { 25 31 5B ?? 2D ?? 5D 56 41 4C 3D 25 38 5B 30 2D 39 5D }\n    ",
        "rule_name": "Generic_ATMPot",
        "start_line": 5,
        "stop_line": 34,
        "strings": [
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$api1",
                "type": "text",
                "value": "CSCCNG"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$api2",
                "type": "text",
                "value": "CscCngOpen"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$api3",
                "type": "text",
                "value": "CscCngClose"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$string1",
                "type": "text",
                "value": "%d,%02d;"
            },
            {
                "name": "$hex1",
                "type": "byte",
                "value": "{ FF 15 ?? ?? ?? ?? F6 C4 80 }"
            },
            {
                "name": "$hex2",
                "type": "byte",
                "value": "{ 25 31 5B ?? 2D ?? 5D 56 41 4C 3D 25 38 5B 30 2D 39 5D }"
            }
        ],
        "tags": [
            "Generic_ATMPot"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Predator_The_Thief', '{Predator_The_Thief}', '{"date": "2018/10/12", "author": "Fumik0_", "source": "https://fumik0.com/2018/10/15/predator-the-thief-in-depth-analysis-v2-3-5/", "description": "Yara rule for Predator The Thief v2.3.5 & +"}', '[
    {
        "condition_terms": [
            "$mz",
            "at",
            "0",
            "and",
            "all",
            "of",
            "(",
            "$hex*",
            ")",
            "and",
            "all",
            "of",
            "(",
            "$s*",
            ")"
        ],
        "metadata": [
            {
                "description": "Yara rule for Predator The Thief v2.3.5 & +"
            },
            {
                "author": "Fumik0_"
            },
            {
                "date": "2018/10/12"
            },
            {
                "source": "https://fumik0.com/2018/10/15/predator-the-thief-in-depth-analysis-v2-3-5/"
            }
        ],
        "raw_condition": "condition:\n        $mz at 0 and all of ($hex*) and all of ($s*)\n",
        "raw_meta": "meta:\n        description = \"Yara rule for Predator The Thief v2.3.5 & +\"\n        author = \"Fumik0_\"\n        date = \"2018/10/12\"\n        source = \"https://fumik0.com/2018/10/15/predator-the-thief-in-depth-analysis-v2-3-5/\"\n   ",
        "raw_strings": "strings:\n        $mz = { 4D 5A }\n\n        $hex1 = { BF 00 00 40 06 } \n        $hex2 = { C6 04 31 6B }\n        $hex3 = { C6 04 31 63 }\n        $hex4 = { C6 04 31 75 }\n        $hex5 = { C6 04 31 66 }\n\n        $s1 = \"sqlite_\" ascii wide\n   ",
        "rule_name": "Predator_The_Thief",
        "start_line": 5,
        "stop_line": 23,
        "strings": [
            {
                "name": "$mz",
                "type": "byte",
                "value": "{ 4D 5A }"
            },
            {
                "name": "$hex1",
                "type": "byte",
                "value": "{ BF 00 00 40 06 }"
            },
            {
                "name": "$hex2",
                "type": "byte",
                "value": "{ C6 04 31 6B }"
            },
            {
                "name": "$hex3",
                "type": "byte",
                "value": "{ C6 04 31 63 }"
            },
            {
                "name": "$hex4",
                "type": "byte",
                "value": "{ C6 04 31 75 }"
            },
            {
                "name": "$hex5",
                "type": "byte",
                "value": "{ C6 04 31 66 }"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$s1",
                "type": "text",
                "value": "sqlite_"
            }
        ],
        "tags": [
            "Predator_The_Thief"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'hancitor', NULL, '{"date": "2018-09-18", "author": "J from THL <j@techhelplist.com>", "filetype": "memory", "maltype1": "Botnet", "reference1": "https://researchcenter.paloaltonetworks.com/2018/02/threat-brief-hancitor-actors/", "reference2": "https://www.virustotal.com/#/file/43e17f30b78c085e9bda8cadf5063cd5cec9edaa7441594ba1fe51391cc1c486/", "reference3": "https://www.virustotal.com/#/file/d135f03b9fdc709651ac9d0264e155c5580b072577a8ff24c90183b126b5e12a/", "description": "Memory string yara for Hancitor"}', '[
    {
        "condition_terms": [
            "5",
            "of",
            "(",
            "$a",
            ",",
            "$b",
            ",",
            "$c",
            ",",
            "$d",
            ",",
            "$e",
            ",",
            "$f",
            ")",
            "or",
            "$g"
        ],
        "metadata": [
            {
                "description": "Memory string yara for Hancitor"
            },
            {
                "author": "J from THL <j@techhelplist.com>"
            },
            {
                "reference1": "https://researchcenter.paloaltonetworks.com/2018/02/threat-brief-hancitor-actors/"
            },
            {
                "reference2": "https://www.virustotal.com/#/file/43e17f30b78c085e9bda8cadf5063cd5cec9edaa7441594ba1fe51391cc1c486/"
            },
            {
                "reference3": "https://www.virustotal.com/#/file/d135f03b9fdc709651ac9d0264e155c5580b072577a8ff24c90183b126b5e12a/"
            },
            {
                "date": "2018-09-18"
            },
            {
                "maltype1": "Botnet"
            },
            {
                "filetype": "memory"
            }
        ],
        "raw_condition": "condition:\n\t\t5 of ($a,$b,$c,$d,$e,$f) or $g\n\n",
        "raw_meta": "meta:\n\t\tdescription = \"Memory string yara for Hancitor\"\n\t\tauthor = \"J from THL <j@techhelplist.com>\"\n\t\treference1 = \"https://researchcenter.paloaltonetworks.com/2018/02/threat-brief-hancitor-actors/\"\n\t\treference2 = \"https://www.virustotal.com/#/file/43e17f30b78c085e9bda8cadf5063cd5cec9edaa7441594ba1fe51391cc1c486/\"\n\t\treference3 = \"https://www.virustotal.com/#/file/d135f03b9fdc709651ac9d0264e155c5580b072577a8ff24c90183b126b5e12a/\"\n\t\tdate = \"2018-09-18\"\n\t\tmaltype1 = \"Botnet\"\n\t\tfiletype = \"memory\"\n\n\t",
        "raw_strings": "strings:\n\t\t$a = \"GUID=\"\tascii\n                $b = \"&BUILD=\"\tascii\n                $c = \"&INFO=\"\tascii\n                $d = \"&IP=\"\tascii\n                $e = \"&TYPE=\" \tascii\n                $f = \"php|http\"\tascii\n\t\t$g = \"GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d\" ascii fullword\n\n\n\t",
        "rule_name": "hancitor",
        "start_line": 3,
        "stop_line": 27,
        "strings": [
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$a",
                "type": "text",
                "value": "GUID="
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$b",
                "type": "text",
                "value": "&BUILD="
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$c",
                "type": "text",
                "value": "&INFO="
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$d",
                "type": "text",
                "value": "&IP="
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$e",
                "type": "text",
                "value": "&TYPE="
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$f",
                "type": "text",
                "value": "php|http"
            },
            {
                "modifiers": [
                    "ascii",
                    "fullword"
                ],
                "name": "$g",
                "type": "text",
                "value": "GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Madness', '{DoS}', '{"date": "2014-01-15", "author": "Jason Jones <jasonjones@arbor.net>", "source": "https://github.com/arbor/yara/blob/master/madness.yara", "description": "Identify Madness Pro DDoS Malware"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Jason Jones <jasonjones@arbor.net>"
            },
            {
                "date": "2014-01-15"
            },
            {
                "description": "Identify Madness Pro DDoS Malware"
            },
            {
                "source": "https://github.com/arbor/yara/blob/master/madness.yara"
            }
        ],
        "raw_condition": "condition:\n        all of them\n",
        "raw_meta": "meta:\n        author = \"Jason Jones <jasonjones@arbor.net>\"\n        date = \"2014-01-15\"\n        description = \"Identify Madness Pro DDoS Malware\"\n        source = \"https://github.com/arbor/yara/blob/master/madness.yara\"\n    ",
        "raw_strings": "strings:\n        $ua1 = \"TW96aWxsYS81LjAgKFdpbmRvd3M7IFU7IFdpbmRvd3MgTlQgNS4xOyBlbi1VUzsgcnY6MS44LjAuNSkgR2Vja28vMjAwNjA3MzEgRmlyZWZveC8xLjUuMC41IEZsb2NrLzAuNy40LjE\"\n        $ua2 = \"TW96aWxsYS81LjAgKFgxMTsgVTsgTGludXggMi40LjItMiBpNTg2OyBlbi1VUzsgbTE4KSBHZWNrby8yMDAxMDEzMSBOZXRzY2FwZTYvNi4wMQ==\"\n        $str1= \"document.cookie=\" fullword\n        $str2 = \"[\\\"cookie\\\",\\\"\" fullword\n        $str3 = \"\\\"realauth=\" fullword\n        $str4 = \"\\\"location\\\"];\" fullword\n        $str5 = \"d3Rm\" fullword\n        $str6 = \"ZXhl\" fullword\n    ",
        "rule_name": "Madness",
        "start_line": 6,
        "stop_line": 23,
        "strings": [
            {
                "name": "$ua1",
                "type": "text",
                "value": "TW96aWxsYS81LjAgKFdpbmRvd3M7IFU7IFdpbmRvd3MgTlQgNS4xOyBlbi1VUzsgcnY6MS44LjAuNSkgR2Vja28vMjAwNjA3MzEgRmlyZWZveC8xLjUuMC41IEZsb2NrLzAuNy40LjE"
            },
            {
                "name": "$ua2",
                "type": "text",
                "value": "TW96aWxsYS81LjAgKFgxMTsgVTsgTGludXggMi40LjItMiBpNTg2OyBlbi1VUzsgbTE4KSBHZWNrby8yMDAxMDEzMSBOZXRzY2FwZTYvNi4wMQ=="
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$str1",
                "type": "text",
                "value": "document.cookie="
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$str2",
                "type": "text",
                "value": "[\\\"cookie\\\",\\\""
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$str3",
                "type": "text",
                "value": "\\\"realauth="
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$str4",
                "type": "text",
                "value": "\\\"location\\\"];"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$str5",
                "type": "text",
                "value": "d3Rm"
            },
            {
                "modifiers": [
                    "fullword"
                ],
                "name": "$str6",
                "type": "text",
                "value": "ZXhl"
            }
        ],
        "tags": [
            "DoS"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'QuarksPwDump_Gen', '{Toolkit}', '{"date": "2015-09-29", "hash1": "2b86e6aea37c324ce686bd2b49cf5b871d90f51cec24476daa01dd69543b54fa", "hash2": "87e4c76cd194568e65287f894b4afcef26d498386de181f568879dde124ff48f", "hash3": "a59be92bf4cce04335bd1a1fcf08c1a94d5820b80c068b3efe13e2ca83d857c9", "hash4": "c5cbb06caa5067fdf916e2f56572435dd40439d8e8554d3354b44f0fd45814ab", "hash5": "677c06db064ee8d8777a56a641f773266a4d8e0e48fbf0331da696bea16df6aa", "hash6": "d3a1eb1f47588e953b9759a76dfa3f07a3b95fab8d8aa59000fd98251d499674", "hash7": "8a81b3a75e783765fe4335a2a6d1e126b12e09380edc4da8319efd9288d88819", "score": 80, "author": "Florian Roth", "description": "Detects all QuarksPWDump versions"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Detects all QuarksPWDump versions"
            },
            {
                "author": "Florian Roth"
            },
            {
                "date": "2015-09-29"
            },
            {
                "score": 80
            },
            {
                "hash1": "2b86e6aea37c324ce686bd2b49cf5b871d90f51cec24476daa01dd69543b54fa"
            },
            {
                "hash2": "87e4c76cd194568e65287f894b4afcef26d498386de181f568879dde124ff48f"
            },
            {
                "hash3": "a59be92bf4cce04335bd1a1fcf08c1a94d5820b80c068b3efe13e2ca83d857c9"
            },
            {
                "hash4": "c5cbb06caa5067fdf916e2f56572435dd40439d8e8554d3354b44f0fd45814ab"
            },
            {
                "hash5": "677c06db064ee8d8777a56a641f773266a4d8e0e48fbf0331da696bea16df6aa"
            },
            {
                "hash6": "d3a1eb1f47588e953b9759a76dfa3f07a3b95fab8d8aa59000fd98251d499674"
            },
            {
                "hash7": "8a81b3a75e783765fe4335a2a6d1e126b12e09380edc4da8319efd9288d88819"
            }
        ],
        "raw_condition": "condition:\n\t\tall of them\n",
        "raw_meta": "meta:\n\t\tdescription = \"Detects all QuarksPWDump versions\"\n\t\tauthor = \"Florian Roth\"\n\t\tdate = \"2015-09-29\"\n\t\tscore = 80\n\t\thash1 = \"2b86e6aea37c324ce686bd2b49cf5b871d90f51cec24476daa01dd69543b54fa\"\n\t\thash2 = \"87e4c76cd194568e65287f894b4afcef26d498386de181f568879dde124ff48f\"\n\t\thash3 = \"a59be92bf4cce04335bd1a1fcf08c1a94d5820b80c068b3efe13e2ca83d857c9\"\n\t\thash4 = \"c5cbb06caa5067fdf916e2f56572435dd40439d8e8554d3354b44f0fd45814ab\"\n\t\thash5 = \"677c06db064ee8d8777a56a641f773266a4d8e0e48fbf0331da696bea16df6aa\"\n\t\thash6 = \"d3a1eb1f47588e953b9759a76dfa3f07a3b95fab8d8aa59000fd98251d499674\"\n\t\thash7 = \"8a81b3a75e783765fe4335a2a6d1e126b12e09380edc4da8319efd9288d88819\"\n\t",
        "raw_strings": "strings:\n\t\t$s1 = \"OpenProcessToken() error: 0x%08X\" fullword ascii\n\t\t$s2 = \"%d dumped\" fullword ascii\n\t\t$s3 = \"AdjustTokenPrivileges() error: 0x%08X\" fullword ascii\n\t\t$s4 = \"\\\\SAM-%u.dmp\" fullword ascii\n\t",
        "rule_name": "QuarksPwDump_Gen",
        "start_line": 5,
        "stop_line": 25,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "OpenProcessToken() error: 0x%08X"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s2",
                "type": "text",
                "value": "%d dumped"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s3",
                "type": "text",
                "value": "AdjustTokenPrivileges() error: 0x%08X"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s4",
                "type": "text",
                "value": "\\\\SAM-%u.dmp"
            }
        ],
        "tags": [
            "Toolkit"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Derkziel', NULL, '{"md5": "f5956953b7a4acab2e6fa478c0015972", "date": "2015-11", "site": "https://zoo.mlw.re/samples/f5956953b7a4acab2e6fa478c0015972", "author": "The Malware Hunter", "filetype": "pe", "reference": "https://bhf.su/threads/137898/", "description": "Derkziel info stealer (Steam, Opera, Yandex, ...)"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Derkziel info stealer (Steam, Opera, Yandex, ...)"
            },
            {
                "author": "The Malware Hunter"
            },
            {
                "filetype": "pe"
            },
            {
                "date": "2015-11"
            },
            {
                "md5": "f5956953b7a4acab2e6fa478c0015972"
            },
            {
                "site": "https://zoo.mlw.re/samples/f5956953b7a4acab2e6fa478c0015972"
            },
            {
                "reference": "https://bhf.su/threads/137898/"
            }
        ],
        "raw_condition": "condition:\n        all of them\n",
        "raw_meta": "meta:\n        description = \"Derkziel info stealer (Steam, Opera, Yandex, ...)\"\n        author = \"The Malware Hunter\"\n        filetype = \"pe\"\n        date = \"2015-11\"\n        md5 = \"f5956953b7a4acab2e6fa478c0015972\"\n        site = \"https://zoo.mlw.re/samples/f5956953b7a4acab2e6fa478c0015972\"\n        reference = \"https://bhf.su/threads/137898/\"\n    \n    ",
        "raw_strings": "strings:\n        $drz = \"{!}DRZ{!}\"\n        $ua = \"User-Agent: Uploador\"\n        $steam = \"SteamAppData.vdf\"\n        $login = \"loginusers.vdf\"\n        $config = \"config.vdf\"\n    \n    ",
        "rule_name": "Derkziel",
        "start_line": 6,
        "stop_line": 27,
        "strings": [
            {
                "name": "$drz",
                "type": "text",
                "value": "{!}DRZ{!}"
            },
            {
                "name": "$ua",
                "type": "text",
                "value": "User-Agent: Uploador"
            },
            {
                "name": "$steam",
                "type": "text",
                "value": "SteamAppData.vdf"
            },
            {
                "name": "$login",
                "type": "text",
                "value": "loginusers.vdf"
            },
            {
                "name": "$config",
                "type": "text",
                "value": "config.vdf"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'mimikatz_kirbi_ticket', NULL, '{"author": "Benjamin DELPY (gentilkiwi); Didier Stevens", "description": "KiRBi ticket for mimikatz"}', '[
    {
        "condition_terms": [
            "$asn1",
            "at",
            "0",
            "or",
            "$asn1_84",
            "at",
            "0"
        ],
        "metadata": [
            {
                "description": "KiRBi ticket for mimikatz"
            },
            {
                "author": "Benjamin DELPY (gentilkiwi); Didier Stevens"
            }
        ],
        "raw_condition": "condition:\n\t\t$asn1 at 0 or $asn1_84 at 0\n",
        "raw_meta": "meta:\n\t\tdescription\t\t= \"KiRBi ticket for mimikatz\"\n\t\tauthor\t\t\t= \"Benjamin DELPY (gentilkiwi); Didier Stevens\"\n\n\t",
        "raw_strings": "strings:\n\t\t$asn1\t\t\t= { 76 82 ?? ?? 30 82 ?? ?? a0 03 02 01 05 a1 03 02 01 16 }\n\t\t$asn1_84\t\t= { 76 84 ?? ?? ?? ?? 30 84 ?? ?? ?? ?? a0 84 00 00 00 03 02 01 05 a1 84 00 00 00 03 02 01 16 }\n\n\t",
        "rule_name": "mimikatz_kirbi_ticket",
        "start_line": 1,
        "stop_line": 13,
        "strings": [
            {
                "name": "$asn1",
                "type": "byte",
                "value": "{ 76 82 ?? ?? 30 82 ?? ?? a0 03 02 01 05 a1 03 02 01 16 }"
            },
            {
                "name": "$asn1_84",
                "type": "byte",
                "value": "{ 76 84 ?? ?? ?? ?? 30 84 ?? ?? ?? ?? a0 84 00 00 00 03 02 01 05 a1 84 00 00 00 03 02 01 16 }"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'APT17_Sample_FXSST_DLL', NULL, '{"date": "2015-05-14", "hash": "52f1add5ad28dc30f68afda5d41b354533d8bce3", "author": "Florian Roth", "reference": "https://goo.gl/ZiJyQv", "description": "Detects Samples related to APT17 activity - file FXSST.DLL"}', '[
    {
        "condition_terms": [
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "filesize",
            "<",
            "800KB",
            "and",
            "(",
            "1",
            "of",
            "(",
            "$x*",
            ")",
            "or",
            "all",
            "of",
            "(",
            "$y*",
            ")",
            ")",
            "and",
            "all",
            "of",
            "(",
            "$s*",
            ")"
        ],
        "metadata": [
            {
                "description": "Detects Samples related to APT17 activity - file FXSST.DLL"
            },
            {
                "author": "Florian Roth"
            },
            {
                "reference": "https://goo.gl/ZiJyQv"
            },
            {
                "date": "2015-05-14"
            },
            {
                "hash": "52f1add5ad28dc30f68afda5d41b354533d8bce3"
            }
        ],
        "raw_condition": "condition:\n        uint16(0) == 0x5a4d and filesize < 800KB and ( 1 of ($x*) or all of ($y*) ) and all of ($s*)\n",
        "raw_meta": "meta:\n        description = \"Detects Samples related to APT17 activity - file FXSST.DLL\"\n        author = \"Florian Roth\"\n        reference = \"https://goo.gl/ZiJyQv\"\n        date = \"2015-05-14\"\n        hash = \"52f1add5ad28dc30f68afda5d41b354533d8bce3\"\n        \n    ",
        "raw_strings": "strings:\n        $x1 = \"Microsoft? Windows? Operating System\" fullword wide\n        $x2 = \"fxsst.dll\" fullword ascii\n        $y1 = \"DllRegisterServer\" fullword ascii\n        $y2 = \".cSV\" fullword ascii\n        $s1 = \"GetLastActivePopup\"\n        $s2 = \"Sleep\"\n        $s3 = \"GetModuleFileName\"\n        $s4 = \"VirtualProtect\"\n        $s5 = \"HeapAlloc\"\n        $s6 = \"GetProcessHeap\"\n        $s7 = \"GetCommandLine\"\n   \n   ",
        "rule_name": "APT17_Sample_FXSST_DLL",
        "start_line": 5,
        "stop_line": 30,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$x1",
                "type": "text",
                "value": "Microsoft? Windows? Operating System"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$x2",
                "type": "text",
                "value": "fxsst.dll"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$y1",
                "type": "text",
                "value": "DllRegisterServer"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$y2",
                "type": "text",
                "value": ".cSV"
            },
            {
                "name": "$s1",
                "type": "text",
                "value": "GetLastActivePopup"
            },
            {
                "name": "$s2",
                "type": "text",
                "value": "Sleep"
            },
            {
                "name": "$s3",
                "type": "text",
                "value": "GetModuleFileName"
            },
            {
                "name": "$s4",
                "type": "text",
                "value": "VirtualProtect"
            },
            {
                "name": "$s5",
                "type": "text",
                "value": "HeapAlloc"
            },
            {
                "name": "$s6",
                "type": "text",
                "value": "GetProcessHeap"
            },
            {
                "name": "$s7",
                "type": "text",
                "value": "GetCommandLine"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'termite_ransomware', NULL, '{"author": "Marc Rivero | @seifreed", "reference": "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/", "description": "Rule to detect Termite Ransomware"}', '[
    {
        "condition_terms": [
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "filesize",
            "<",
            "6000KB",
            ")",
            "and",
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Rule to detect Termite Ransomware"
            },
            {
                "author": "Marc Rivero | @seifreed"
            },
            {
                "reference": "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/"
            }
        ],
        "raw_condition": "condition:\n   \n      ( uint16(0) == 0x5a4d and filesize < 6000KB ) and all of them \n",
        "raw_meta": "meta:\n\n      description = \"Rule to detect Termite Ransomware\"\n      author = \"Marc Rivero | @seifreed\"\n      reference = \"https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/\"\n      \n   ",
        "raw_strings": "strings:\n      \n      $s1 = \"C:\\\\Windows\\\\SysNative\\\\mswsock.dll\" fullword ascii\n      $s2 = \"C:\\\\Windows\\\\SysWOW64\\\\mswsock.dll\" fullword ascii\n      $s3 = \"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Termite.exe\" fullword ascii\n      $s4 = \"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Payment.exe\" fullword ascii\n      $s5 = \"C:\\\\Windows\\\\Termite.exe\" fullword ascii\n      $s6 = \"\\\\Shell\\\\Open\\\\Command\\\\\" fullword ascii\n      $s7 = \"t314.520@qq.com\" fullword ascii\n      $s8 = \"(*.JPG;*.PNG;*.BMP;*.GIF;*.ICO;*.CUR)|*.JPG;*.PNG;*.BMP;*.GIF;*.ICO;*.CUR|JPG\" fullword ascii\n      \n   ",
        "rule_name": "termite_ransomware",
        "start_line": 1,
        "stop_line": 23,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "C:\\\\Windows\\\\SysNative\\\\mswsock.dll"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s2",
                "type": "text",
                "value": "C:\\\\Windows\\\\SysWOW64\\\\mswsock.dll"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s3",
                "type": "text",
                "value": "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Termite.exe"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s4",
                "type": "text",
                "value": "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Payment.exe"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s5",
                "type": "text",
                "value": "C:\\\\Windows\\\\Termite.exe"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s6",
                "type": "text",
                "value": "\\\\Shell\\\\Open\\\\Command\\\\"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s7",
                "type": "text",
                "value": "t314.520@qq.com"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s8",
                "type": "text",
                "value": "(*.JPG;*.PNG;*.BMP;*.GIF;*.ICO;*.CUR)|*.JPG;*.PNG;*.BMP;*.GIF;*.ICO;*.CUR|JPG"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'CrossRAT', '{RAT}', '{"ref": "https://objective-see.com/blog/blog_0x28.html", "date": "26/01/2018", "author": "Simon Sigre (simon.sigre@gmail.com)", "description": "Detects CrossRAT known hash"}', '[
    {
        "condition_terms": [
            "filesize",
            "<",
            "400KB",
            "and",
            "$magic",
            "at",
            "0",
            "and",
            "1",
            "of",
            "(",
            "$string_*",
            ")",
            "and",
            "hash.md5",
            "(",
            "0",
            ",",
            "filesize",
            ")",
            "==",
            "\"85b794e080d83a91e904b97769e1e770\""
        ],
        "imports": [
            "hash"
        ],
        "metadata": [
            {
                "description": "Detects CrossRAT known hash"
            },
            {
                "author": "Simon Sigre (simon.sigre@gmail.com)"
            },
            {
                "date": "26/01/2018"
            },
            {
                "ref": "https://simonsigre.com"
            },
            {
                "ref": "https://objective-see.com/blog/blog_0x28.html"
            }
        ],
        "raw_condition": "condition:\n        filesize < 400KB and\n        $magic at 0 and 1 of ($string_*) and\n        hash.md5(0, filesize) == \"85b794e080d83a91e904b97769e1e770\"\n",
        "raw_meta": "meta:\n        description = \"Detects CrossRAT known hash\"\n        author = \"Simon Sigre (simon.sigre@gmail.com)\"\n        date = \"26/01/2018\"\n        ref = \"https://simonsigre.com\"\n        ref= \"https://objective-see.com/blog/blog_0x28.html\"\n    ",
        "raw_strings": "strings:\n        $magic = { 50 4b 03 04 ( 14 | 0a ) 00 }\n        $string_1 = \"META-INF/\"\n        $string_2 = \".class\" nocase\n\n    ",
        "rule_name": "CrossRAT",
        "start_line": 3,
        "stop_line": 20,
        "strings": [
            {
                "name": "$magic",
                "type": "byte",
                "value": "{ 50 4b 03 04 ( 14 | 0a ) 00 }"
            },
            {
                "name": "$string_1",
                "type": "text",
                "value": "META-INF/"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$string_2",
                "type": "text",
                "value": ".class"
            }
        ],
        "tags": [
            "RAT"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'CyberGate', '{RAT}', '{"ref": "http://malwareconfig.com/stats/CyberGate", "date": "2014/04", "author": " Kevin Breen <kevin@techanarchy.net>", "maltype": "Remote Access Trojan", "filetype": "exe"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "(",
            "$string*",
            ")",
            "and",
            "any",
            "of",
            "(",
            "$res*",
            ")"
        ],
        "metadata": [
            {
                "author": " Kevin Breen <kevin@techanarchy.net>"
            },
            {
                "date": "2014/04"
            },
            {
                "ref": "http://malwareconfig.com/stats/CyberGate"
            },
            {
                "maltype": "Remote Access Trojan"
            },
            {
                "filetype": "exe"
            }
        ],
        "raw_condition": "condition:\n\t\tall of ($string*) and any of ($res*)\n",
        "raw_meta": "meta:\n\t\tauthor = \" Kevin Breen <kevin@techanarchy.net>\"\n\t\tdate = \"2014/04\"\n\t\tref = \"http://malwareconfig.com/stats/CyberGate\"\n\t\tmaltype = \"Remote Access Trojan\"\n\t\tfiletype = \"exe\"\n\n\t",
        "raw_strings": "strings:\n\t\t$string1 = {23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}\n\t\t$string2 = {23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}\n\t\t$string3 = \"EditSvr\"\n\t\t$string4 = \"TLoader\"\n\t\t$string5 = \"Stroks\"\n\t\t$string6 = \"####@####\"\n\t\t$res1 = \"XX-XX-XX-XX\"\n\t\t$res2 = \"CG-CG-CG-CG\"\n\n\t",
        "rule_name": "CyberGate",
        "start_line": 5,
        "stop_line": 27,
        "strings": [
            {
                "name": "$string1",
                "type": "byte",
                "value": "{23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}"
            },
            {
                "name": "$string2",
                "type": "byte",
                "value": "{23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}"
            },
            {
                "name": "$string3",
                "type": "text",
                "value": "EditSvr"
            },
            {
                "name": "$string4",
                "type": "text",
                "value": "TLoader"
            },
            {
                "name": "$string5",
                "type": "text",
                "value": "Stroks"
            },
            {
                "name": "$string6",
                "type": "text",
                "value": "####@####"
            },
            {
                "name": "$res1",
                "type": "text",
                "value": "XX-XX-XX-XX"
            },
            {
                "name": "$res2",
                "type": "text",
                "value": "CG-CG-CG-CG"
            }
        ],
        "tags": [
            "RAT"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Upatre_Hazgurut', NULL, '{"date": "2015-10-13", "hash1": "7ee0d20b15e24b7fe72154d9521e1959752b4e9c20d2992500df9ac096450a50", "hash2": "79ffc620ddb143525fa32bc6a83c636168501a4a589a38cdb0a74afac1ee8b92", "hash3": "62d8a6880c594fe9529158b94a9336179fa7a3d3bf1aa9d0baaf07d03b281bd3", "hash4": "c64282aca980d558821bec8b3dfeae562d9620139dc43d02ee4d1745cd989f2a", "hash5": "a35f9870f9d4b993eb094460b05ee1f657199412807abe6264121dd7cc12aa70", "hash6": "f8cb2730ebc8fac1c58da1346ad1208585fe730c4f03d976eb1e13a1f5d81ef9", "hash7": "b65ad7e2d299d6955d95b7ae9b62233c34bc5f6aa9f87dc482914f8ad2cba5d2", "hash8": "6b857ef314938d37997c178ea50687a281d8ff9925f0c4e70940754643e2c0e3", "hash9": "33a288cef0ae7192b34bd2ef3f523dfb7c6cbc2735ba07edf988400df1713041", "score": 70, "author": "Florian Roth", "hash10": "2a8e50afbc376cb2a9700d2d83c1be0c21ef942309676ecac897ba4646aba273", "hash11": "3d0f2c7e07b7d64b1bad049b804ff1aae8c1fc945a42ad555eca3e1698c7f7d3", "hash12": "951360b32a78173a1f81da0ded8b4400e230125d05970d41621830efc5337274", "hash13": "bd90faebfd7663ef89b120fe69809532cada3eb94bb94094e8bc615f70670295", "hash14": "8c5823f67f9625e4be39a67958f0f614ece49c18596eacc5620524bc9b6bad3d", "reference": "https://weankor.vxstream-sandbox.com/sample/6b857ef314938d37997c178ea50687a281d8ff9925f0c4e70940754643e2c0e3?environmentId=7", "description": "Detects Upatre malware - file hazgurut.exe"}', '[
    {
        "condition_terms": [
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "filesize",
            "<",
            "1500KB",
            "and",
            "$a1",
            "in",
            "(",
            "0",
            "..",
            "4000",
            ")",
            "and",
            "all",
            "of",
            "(",
            "$s*",
            ")"
        ],
        "metadata": [
            {
                "description": "Detects Upatre malware - file hazgurut.exe"
            },
            {
                "author": "Florian Roth"
            },
            {
                "reference": "https://weankor.vxstream-sandbox.com/sample/6b857ef314938d37997c178ea50687a281d8ff9925f0c4e70940754643e2c0e3?environmentId=7"
            },
            {
                "date": "2015-10-13"
            },
            {
                "score": 70
            },
            {
                "hash1": "7ee0d20b15e24b7fe72154d9521e1959752b4e9c20d2992500df9ac096450a50"
            },
            {
                "hash2": "79ffc620ddb143525fa32bc6a83c636168501a4a589a38cdb0a74afac1ee8b92"
            },
            {
                "hash3": "62d8a6880c594fe9529158b94a9336179fa7a3d3bf1aa9d0baaf07d03b281bd3"
            },
            {
                "hash4": "c64282aca980d558821bec8b3dfeae562d9620139dc43d02ee4d1745cd989f2a"
            },
            {
                "hash5": "a35f9870f9d4b993eb094460b05ee1f657199412807abe6264121dd7cc12aa70"
            },
            {
                "hash6": "f8cb2730ebc8fac1c58da1346ad1208585fe730c4f03d976eb1e13a1f5d81ef9"
            },
            {
                "hash7": "b65ad7e2d299d6955d95b7ae9b62233c34bc5f6aa9f87dc482914f8ad2cba5d2"
            },
            {
                "hash8": "6b857ef314938d37997c178ea50687a281d8ff9925f0c4e70940754643e2c0e3"
            },
            {
                "hash9": "33a288cef0ae7192b34bd2ef3f523dfb7c6cbc2735ba07edf988400df1713041"
            },
            {
                "hash10": "2a8e50afbc376cb2a9700d2d83c1be0c21ef942309676ecac897ba4646aba273"
            },
            {
                "hash11": "3d0f2c7e07b7d64b1bad049b804ff1aae8c1fc945a42ad555eca3e1698c7f7d3"
            },
            {
                "hash12": "951360b32a78173a1f81da0ded8b4400e230125d05970d41621830efc5337274"
            },
            {
                "hash13": "bd90faebfd7663ef89b120fe69809532cada3eb94bb94094e8bc615f70670295"
            },
            {
                "hash14": "8c5823f67f9625e4be39a67958f0f614ece49c18596eacc5620524bc9b6bad3d"
            }
        ],
        "raw_condition": "condition:\n\t\tuint16(0) == 0x5a4d and filesize < 1500KB\n\t\tand $a1 in (0..4000)\n\t\tand all of ($s*)\n",
        "raw_meta": "meta:\n\t\tdescription = \"Detects Upatre malware - file hazgurut.exe\"\n\t\tauthor = \"Florian Roth\"\n\t\treference = \"https://weankor.vxstream-sandbox.com/sample/6b857ef314938d37997c178ea50687a281d8ff9925f0c4e70940754643e2c0e3?environmentId=7\"\n\t\tdate = \"2015-10-13\"\n\t\tscore = 70\n\t\thash1 = \"7ee0d20b15e24b7fe72154d9521e1959752b4e9c20d2992500df9ac096450a50\"\n\t\thash2 = \"79ffc620ddb143525fa32bc6a83c636168501a4a589a38cdb0a74afac1ee8b92\"\n\t\thash3 = \"62d8a6880c594fe9529158b94a9336179fa7a3d3bf1aa9d0baaf07d03b281bd3\"\n\t\thash4 = \"c64282aca980d558821bec8b3dfeae562d9620139dc43d02ee4d1745cd989f2a\"\n\t\thash5 = \"a35f9870f9d4b993eb094460b05ee1f657199412807abe6264121dd7cc12aa70\"\n\t\thash6 = \"f8cb2730ebc8fac1c58da1346ad1208585fe730c4f03d976eb1e13a1f5d81ef9\"\n\t\thash7 = \"b65ad7e2d299d6955d95b7ae9b62233c34bc5f6aa9f87dc482914f8ad2cba5d2\"\n\t\thash8 = \"6b857ef314938d37997c178ea50687a281d8ff9925f0c4e70940754643e2c0e3\"\n\t\thash9 = \"33a288cef0ae7192b34bd2ef3f523dfb7c6cbc2735ba07edf988400df1713041\"\n\t\thash10 = \"2a8e50afbc376cb2a9700d2d83c1be0c21ef942309676ecac897ba4646aba273\"\n\t\thash11 = \"3d0f2c7e07b7d64b1bad049b804ff1aae8c1fc945a42ad555eca3e1698c7f7d3\"\n\t\thash12 = \"951360b32a78173a1f81da0ded8b4400e230125d05970d41621830efc5337274\"\n\t\thash13 = \"bd90faebfd7663ef89b120fe69809532cada3eb94bb94094e8bc615f70670295\"\n\t\thash14 = \"8c5823f67f9625e4be39a67958f0f614ece49c18596eacc5620524bc9b6bad3d\"\n\t",
        "raw_strings": "strings:\n\t\t$a1 = \"barcod\" fullword ascii\n\n\t\t$s0 = \"msports.dll\" fullword ascii\n\t\t$s1 = \"nddeapi.dll\" fullword ascii\n\t\t$s2 = \"glmf32.dll\" fullword ascii\n\t\t$s3 = \"<requestedExecutionLevel level=\\\"requireAdministrator\\\" uiAccess=\\\"false\\\">\" fullword ascii\n\t\t$s4 = \"cmutil.dll\" fullword ascii\n\t\t$s5 = \"mprapi.dll\" fullword ascii\n\t\t$s6 = \"glmf32.dll\" fullword ascii\n\t",
        "rule_name": "Upatre_Hazgurut",
        "start_line": 13,
        "stop_line": 48,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$a1",
                "type": "text",
                "value": "barcod"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s0",
                "type": "text",
                "value": "msports.dll"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "nddeapi.dll"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s2",
                "type": "text",
                "value": "glmf32.dll"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s3",
                "type": "text",
                "value": "<requestedExecutionLevel level=\\\"requireAdministrator\\\" uiAccess=\\\"false\\\">"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s4",
                "type": "text",
                "value": "cmutil.dll"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s5",
                "type": "text",
                "value": "mprapi.dll"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s6",
                "type": "text",
                "value": "glmf32.dll"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'win_asyncrat_j1', NULL, '{"tlp": "white", "date": "2020-04-26", "author": "Johannes Bader @viql", "references": "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp", "description": "detects AsyncRAT"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "(",
            "$str_anti_*",
            ")",
            "and",
            "4",
            "of",
            "(",
            "$str_config_*",
            ")",
            "and",
            "(",
            "all",
            "of",
            "(",
            "$str_miner_*",
            ")",
            "or",
            "3",
            "of",
            "(",
            "$str_b_*",
            ")",
            ")"
        ],
        "metadata": [
            {
                "author": "Johannes Bader @viql"
            },
            {
                "date": "2020-04-26"
            },
            {
                "description": "detects AsyncRAT"
            },
            {
                "references": "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"
            },
            {
                "tlp": "white"
            }
        ],
        "raw_condition": "condition:\n        all of ($str_anti_*)  and \n        4 of ($str_config_*) and ( \n            all of ($str_miner_*) or \n            3 of ($str_b_*)\n        )\n        \n",
        "raw_meta": "meta:\n        author      = \"Johannes Bader @viql\"\n        date        = \"2020-04-26\"\n        description = \"detects AsyncRAT\"\n        references  = \"https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp\"\n        tlp         = \"white\"\n\n    ",
        "raw_strings": "strings:\n        $str_anti_1 = \"VIRTUAL\" wide\n        $str_anti_2 = \"vmware\" wide\n        $str_anti_3 = \"VirtualBox\" wide\n        $str_anti_4 = \"SbieDll.dll\" wide\n\n        $str_miner_1 = \"--donate-level=\" wide\n\n        $str_b_rev_run    = \"\\\\nuR\\\\noisreVtnerruC\\\\swodniW\\\\tfosorciM\\\\erawtfoS\" wide\n        $str_b_msg_pack_1 = \"(ext8,ext16,ex32) type $c7,$c8,$c9\" wide\n        $str_b_msg_pack_2 = \"(never used) type $c1\" wide\n        $str_b_schtask_1  = \"/create /f /sc ONLOGON /RL HIGHEST /tn \\\"''\" wide\n        $str_b_schtask_2  = \"\\\"'' /tr \\\"''\" wide\n\n        $str_config_1 = \"Antivirus\" wide\n        $str_config_2 = \"Pastebin\" wide\n        $str_config_3 = \"HWID\" wide\n        $str_config_4 = \"Installed\" wide\n        $str_config_5 = \"Pong\" wide\n        $str_config_6 = \"Performance\" wide\n\n    ",
        "rule_name": "win_asyncrat_j1",
        "start_line": 7,
        "stop_line": 44,
        "strings": [
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str_anti_1",
                "type": "text",
                "value": "VIRTUAL"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str_anti_2",
                "type": "text",
                "value": "vmware"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str_anti_3",
                "type": "text",
                "value": "VirtualBox"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str_anti_4",
                "type": "text",
                "value": "SbieDll.dll"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str_miner_1",
                "type": "text",
                "value": "--donate-level="
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str_b_rev_run",
                "type": "text",
                "value": "\\\\nuR\\\\noisreVtnerruC\\\\swodniW\\\\tfosorciM\\\\erawtfoS"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str_b_msg_pack_1",
                "type": "text",
                "value": "(ext8,ext16,ex32) type $c7,$c8,$c9"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str_b_msg_pack_2",
                "type": "text",
                "value": "(never used) type $c1"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str_b_schtask_1",
                "type": "text",
                "value": "/create /f /sc ONLOGON /RL HIGHEST /tn \\\"''"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str_b_schtask_2",
                "type": "text",
                "value": "\\\"'' /tr \\\"''"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str_config_1",
                "type": "text",
                "value": "Antivirus"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str_config_2",
                "type": "text",
                "value": "Pastebin"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str_config_3",
                "type": "text",
                "value": "HWID"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str_config_4",
                "type": "text",
                "value": "Installed"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str_config_5",
                "type": "text",
                "value": "Pong"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str_config_6",
                "type": "text",
                "value": "Performance"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Powerstager', NULL, '{"date": "02JAN2018", "hash1": "758097319d61e2744fb6b297f0bff957c6aab299278c1f56a90fba197795a0fa", "hash2": "83e714e72d9f3c500cad610c4772eae6152a232965191f0125c1c6f97004b7b5", "author": "Jeff White - jwhite@paloaltonetworks.com @noottrak", "reference": "https://researchcenter.paloaltonetworks.com/2018/01/unit42-powerstager-analysis/", "reference2": "https://github.com/z0noxz/powerstager", "description": "Detects PowerStager Windows executable, both x86 and x64"}', '[
    {
        "comments": [
            "//x64",
            "//x86"
        ],
        "condition_terms": [
            "uint16be",
            "(",
            "0",
            ")",
            "==",
            "0x4D5A",
            "and",
            "all",
            "of",
            "(",
            "$apicall_*",
            ")",
            "and",
            "$filename",
            "and",
            "$pathname",
            "and",
            "$filedesc",
            "and",
            "(",
            "2",
            "of",
            "(",
            "$decoder_x86*",
            ")",
            "or",
            "2",
            "of",
            "(",
            "$decoder_x64*",
            ")",
            ")"
        ],
        "metadata": [
            {
                "author": "Jeff White - jwhite@paloaltonetworks.com @noottrak"
            },
            {
                "date": "02JAN2018"
            },
            {
                "hash1": "758097319d61e2744fb6b297f0bff957c6aab299278c1f56a90fba197795a0fa"
            },
            {
                "hash2": "83e714e72d9f3c500cad610c4772eae6152a232965191f0125c1c6f97004b7b5"
            },
            {
                "description": "Detects PowerStager Windows executable, both x86 and x64"
            },
            {
                "reference": "https://researchcenter.paloaltonetworks.com/2018/01/unit42-powerstager-analysis/"
            },
            {
                "reference2": "https://github.com/z0noxz/powerstager"
            }
        ],
        "raw_condition": "condition:\n      uint16be(0) == 0x4D5A\n        and\n      all of ($apicall_*)\n        and\n      $filename\n        and\n      $pathname\n        and\n      $filedesc\n        and\n      (2 of ($decoder_x86*) or 2 of ($decoder_x64*))\n",
        "raw_meta": "meta:\n      author = \"Jeff White - jwhite@paloaltonetworks.com @noottrak\"\n      date = \"02JAN2018\"\n      hash1 = \"758097319d61e2744fb6b297f0bff957c6aab299278c1f56a90fba197795a0fa\" //x86\n      hash2 = \"83e714e72d9f3c500cad610c4772eae6152a232965191f0125c1c6f97004b7b5\" //x64\n      description = \"Detects PowerStager Windows executable, both x86 and x64\"\n      reference = \"https://researchcenter.paloaltonetworks.com/2018/01/unit42-powerstager-analysis/\"\n      reference2 = \"https://github.com/z0noxz/powerstager\"\n    \n    ",
        "raw_strings": "strings:\n      $filename = /%s\\\\[a-zA-Z0-9]{12}/\n      $pathname = \"TEMP\" wide ascii\n//    $errormsg = \"The version of this file is not compatible with the version of Windows you''re running.\" wide ascii\n      $filedesc = \"Lorem ipsum dolor sit amet, consecteteur adipiscing elit\" wide ascii\n      $apicall_01 = \"memset\"\n      $apicall_02 = \"getenv\"\n      $apicall_03 = \"fopen\"\n      $apicall_04 = \"memcpy\"\n      $apicall_05 = \"fwrite\"\n      $apicall_06 = \"fclose\"\n      $apicall_07 = \"CreateProcessA\"\n      $decoder_x86_01 = { 8D 95 [4] 8B 45 ?? 01 D0 0F B6 18 8B 4D ?? }\n      $decoder_x86_02 = { 89 C8 0F B6 84 05 [4] 31 C3 89 D9 8D 95 [4] 8B 45 ?? 01 D0 88 08 83 45 [2] 8B 45 ?? 3D }\n      $decoder_x64_01 = { 8B 85 [4] 48 98 44 0F [7] 8B 85 [4] 48 63 C8 48 }\n      $decoder_x64_02 = { 48 89 ?? 0F B6 [3-6] 44 89 C2 31 C2 8B 85 [4] 48 98 }\n\n    ",
        "rule_name": "Powerstager",
        "start_line": 1,
        "stop_line": 41,
        "strings": [
            {
                "name": "$filename",
                "type": "regex",
                "value": "/%s\\\\[a-zA-Z0-9]{12}/"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$pathname",
                "type": "text",
                "value": "TEMP"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$filedesc",
                "type": "text",
                "value": "Lorem ipsum dolor sit amet, consecteteur adipiscing elit"
            },
            {
                "name": "$apicall_01",
                "type": "text",
                "value": "memset"
            },
            {
                "name": "$apicall_02",
                "type": "text",
                "value": "getenv"
            },
            {
                "name": "$apicall_03",
                "type": "text",
                "value": "fopen"
            },
            {
                "name": "$apicall_04",
                "type": "text",
                "value": "memcpy"
            },
            {
                "name": "$apicall_05",
                "type": "text",
                "value": "fwrite"
            },
            {
                "name": "$apicall_06",
                "type": "text",
                "value": "fclose"
            },
            {
                "name": "$apicall_07",
                "type": "text",
                "value": "CreateProcessA"
            },
            {
                "name": "$decoder_x86_01",
                "type": "byte",
                "value": "{ 8D 95 [4] 8B 45 ?? 01 D0 0F B6 18 8B 4D ?? }"
            },
            {
                "name": "$decoder_x86_02",
                "type": "byte",
                "value": "{ 89 C8 0F B6 84 05 [4] 31 C3 89 D9 8D 95 [4] 8B 45 ?? 01 D0 88 08 83 45 [2] 8B 45 ?? 3D }"
            },
            {
                "name": "$decoder_x64_01",
                "type": "byte",
                "value": "{ 8B 85 [4] 48 98 44 0F [7] 8B 85 [4] 48 63 C8 48 }"
            },
            {
                "name": "$decoder_x64_02",
                "type": "byte",
                "value": "{ 48 89 ?? 0F B6 [3-6] 44 89 C2 31 C2 8B 85 [4] 48 98 }"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'NetWiredRC_B', '{RAT}', '{"date": "2014-12-23", "author": "Jean-Philippe Teissier / @Jipe_", "version": "1.1", "filetype": "memory", "description": "NetWiredRC"}', '[
    {
        "condition_terms": [
            "$mutex",
            "or",
            "(",
            "1",
            "of",
            "(",
            "$str*",
            ")",
            "and",
            "1",
            "of",
            "(",
            "$klg*",
            ")",
            ")"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "description": "NetWiredRC"
            },
            {
                "author": "Jean-Philippe Teissier / @Jipe_"
            },
            {
                "date": "2014-12-23"
            },
            {
                "filetype": "memory"
            },
            {
                "version": "1.1"
            }
        ],
        "raw_condition": "condition: \n\t\t$mutex or (1 of ($str*) and 1 of ($klg*))\n",
        "raw_meta": "meta:\n\t\tdescription = \"NetWiredRC\"\n\t\tauthor = \"Jean-Philippe Teissier / @Jipe_\"\n\t\tdate = \"2014-12-23\"\n\t\tfiletype = \"memory\"\n\t\tversion = \"1.1\" \n\n\t",
        "raw_strings": "strings:\n\t\t$mutex = \"LmddnIkX\"\n\n\t\t$str1 = \"%s.Identifier\"\n\t\t$str2 = \"%d:%I64u:%s%s;\"\n\t\t$str3 = \"%s%.2d-%.2d-%.4d\"\n\t\t$str4 = \"[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]\"\n\t\t$str5 = \"%.2d/%.2d/%d %.2d:%.2d:%.2d\"\n\t\t\n\t\t$klg1 = \"[Backspace]\"\n\t\t$klg2 = \"[Enter]\"\n\t\t$klg3 = \"[Tab]\"\n\t\t$klg4 = \"[Arrow Left]\"\n\t\t$klg5 = \"[Arrow Up]\"\n\t\t$klg6 = \"[Arrow Right]\"\n\t\t$klg7 = \"[Arrow Down]\"\n\t\t$klg8 = \"[Home]\"\n\t\t$klg9 = \"[Page Up]\"\n\t\t$klg10 = \"[Page Down]\"\n\t\t$klg11 = \"[End]\"\n\t\t$klg12 = \"[Break]\"\n\t\t$klg13 = \"[Delete]\"\n\t\t$klg14 = \"[Insert]\"\n\t\t$klg15 = \"[Print Screen]\"\n\t\t$klg16 = \"[Scroll Lock]\"\n\t\t$klg17 = \"[Caps Lock]\"\n\t\t$klg18 = \"[Alt]\"\n\t\t$klg19 = \"[Esc]\"\n\t\t$klg20 = \"[Ctrl+%c]\"\n\n\t",
        "rule_name": "NetWiredRC_B",
        "start_line": 7,
        "stop_line": 48,
        "strings": [
            {
                "name": "$mutex",
                "type": "text",
                "value": "LmddnIkX"
            },
            {
                "name": "$str1",
                "type": "text",
                "value": "%s.Identifier"
            },
            {
                "name": "$str2",
                "type": "text",
                "value": "%d:%I64u:%s%s;"
            },
            {
                "name": "$str3",
                "type": "text",
                "value": "%s%.2d-%.2d-%.4d"
            },
            {
                "name": "$str4",
                "type": "text",
                "value": "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"
            },
            {
                "name": "$str5",
                "type": "text",
                "value": "%.2d/%.2d/%d %.2d:%.2d:%.2d"
            },
            {
                "name": "$klg1",
                "type": "text",
                "value": "[Backspace]"
            },
            {
                "name": "$klg2",
                "type": "text",
                "value": "[Enter]"
            },
            {
                "name": "$klg3",
                "type": "text",
                "value": "[Tab]"
            },
            {
                "name": "$klg4",
                "type": "text",
                "value": "[Arrow Left]"
            },
            {
                "name": "$klg5",
                "type": "text",
                "value": "[Arrow Up]"
            },
            {
                "name": "$klg6",
                "type": "text",
                "value": "[Arrow Right]"
            },
            {
                "name": "$klg7",
                "type": "text",
                "value": "[Arrow Down]"
            },
            {
                "name": "$klg8",
                "type": "text",
                "value": "[Home]"
            },
            {
                "name": "$klg9",
                "type": "text",
                "value": "[Page Up]"
            },
            {
                "name": "$klg10",
                "type": "text",
                "value": "[Page Down]"
            },
            {
                "name": "$klg11",
                "type": "text",
                "value": "[End]"
            },
            {
                "name": "$klg12",
                "type": "text",
                "value": "[Break]"
            },
            {
                "name": "$klg13",
                "type": "text",
                "value": "[Delete]"
            },
            {
                "name": "$klg14",
                "type": "text",
                "value": "[Insert]"
            },
            {
                "name": "$klg15",
                "type": "text",
                "value": "[Print Screen]"
            },
            {
                "name": "$klg16",
                "type": "text",
                "value": "[Scroll Lock]"
            },
            {
                "name": "$klg17",
                "type": "text",
                "value": "[Caps Lock]"
            },
            {
                "name": "$klg18",
                "type": "text",
                "value": "[Alt]"
            },
            {
                "name": "$klg19",
                "type": "text",
                "value": "[Esc]"
            },
            {
                "name": "$klg20",
                "type": "text",
                "value": "[Ctrl+%c]"
            }
        ],
        "tags": [
            "RAT"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'MedussaHTTP_2019', NULL, '{"date": "2019-08-12", "author": "J from THL <j@techhelplist.com>", "maltype": "Bot", "version": 1, "filetype": "memory", "reference1": "https://app.any.run/tasks/68c8f400-eba5-4d6c-b1f1-8b07d4c014a4/", "reference2": "https://www.netscout.com/blog/asert/medusahttp-ddos-slithers-back-spotlight", "reference3": "https://twitter.com/malware_traffic/status/1161034462983008261", "description": "MedussaHTTP v20190812"}', '[
    {
        "condition_terms": [
            "9",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "J from THL <j@techhelplist.com>"
            },
            {
                "date": "2019-08-12"
            },
            {
                "reference1": "https://app.any.run/tasks/68c8f400-eba5-4d6c-b1f1-8b07d4c014a4/"
            },
            {
                "reference2": "https://www.netscout.com/blog/asert/medusahttp-ddos-slithers-back-spotlight"
            },
            {
                "reference3": "https://twitter.com/malware_traffic/status/1161034462983008261"
            },
            {
                "version": 1
            },
            {
                "maltype": "Bot"
            },
            {
                "filetype": "memory"
            },
            {
                "description": "MedussaHTTP v20190812"
            }
        ],
        "raw_condition": "condition:\n        9 of them\n",
        "raw_meta": "meta:\n        author = \"J from THL <j@techhelplist.com>\"\n        date = \"2019-08-12\"\n        reference1 = \"https://app.any.run/tasks/68c8f400-eba5-4d6c-b1f1-8b07d4c014a4/\"\n        reference2 = \"https://www.netscout.com/blog/asert/medusahttp-ddos-slithers-back-spotlight\"\n        reference3 = \"https://twitter.com/malware_traffic/status/1161034462983008261\"\n        version = 1\n        maltype = \"Bot\"\n        filetype = \"memory\"\n        description = \"MedussaHTTP v20190812\"\n\n    ",
        "raw_strings": "strings:\n        $text01 = \"|check|\" ascii\n        $text02 = \"POST!\" ascii\n        $text03 = \"httpactive\" ascii\n        $text04 = \"httpstrong\" ascii\n        $text05 = \"httppost\" ascii\n        $text06 = \"slavicdragon\" ascii\n        $text07 = \"slavicnodragon\" ascii\n        $text08 = \"smartflood\" ascii\n        $text09 = \"stop-all\" ascii\n        $text10 = \"botkill\" ascii\n        $text11 = \"updatehash\" ascii\n        $text12 = \"xyz=\" ascii\n        $text13 = \"abc=\" ascii\n\n\n\n    ",
        "rule_name": "MedussaHTTP_2019",
        "start_line": 2,
        "stop_line": 35,
        "strings": [
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$text01",
                "type": "text",
                "value": "|check|"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$text02",
                "type": "text",
                "value": "POST!"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$text03",
                "type": "text",
                "value": "httpactive"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$text04",
                "type": "text",
                "value": "httpstrong"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$text05",
                "type": "text",
                "value": "httppost"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$text06",
                "type": "text",
                "value": "slavicdragon"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$text07",
                "type": "text",
                "value": "slavicnodragon"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$text08",
                "type": "text",
                "value": "smartflood"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$text09",
                "type": "text",
                "value": "stop-all"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$text10",
                "type": "text",
                "value": "botkill"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$text11",
                "type": "text",
                "value": "updatehash"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$text12",
                "type": "text",
                "value": "xyz="
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$text13",
                "type": "text",
                "value": "abc="
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'PoetRat_Python', NULL, '{"Data": "6th May 2020", "Author": "Nishan Maharjan", "Description": "A yara rule to catch PoetRat python scripts"}', '[
    {
        "comments": [
            "// Any of the strings that stand out in the files, these are for the multiple python files, not just for a single file"
        ],
        "condition_terms": [
            "3",
            "of",
            "them"
        ],
        "metadata": [
            {
                "Author": "Nishan Maharjan"
            },
            {
                "Description": "A yara rule to catch PoetRat python scripts"
            },
            {
                "Data": "6th May 2020"
            }
        ],
        "raw_condition": "condition:\n        3 of them        \n",
        "raw_meta": "meta:\n        Author = \"Nishan Maharjan\"\n        Description = \"A yara rule to catch PoetRat python scripts\"\n        Data = \"6th May 2020\"\n    ",
        "raw_strings": "strings:\n\n        // Any of the strings that stand out in the files, these are for the multiple python files, not just for a single file\n        $encrptionFunction = \"Affine\"\n        $commands = /version|ls|cd|sysinfo|download|upload|shot|cp|mv|link|register|hid|compress|jobs|exit|tasklist|taskkill/\n        $domain = \"dellgenius.hopto.org\"\n        $grammer_massacre = /BADD|Bad Error Happened|/\n        $mayBePresent = /self\\.DIE|THE_GUID_KEY/\n        $pipe_out = \"Abibliophobia23\"\n        $shot = \"shot_{0}_{1}.png\"\n    ",
        "rule_name": "PoetRat_Python",
        "start_line": 1,
        "stop_line": 19,
        "strings": [
            {
                "name": "$encrptionFunction",
                "type": "text",
                "value": "Affine"
            },
            {
                "name": "$commands",
                "type": "regex",
                "value": "/version|ls|cd|sysinfo|download|upload|shot|cp|mv|link|register|hid|compress|jobs|exit|tasklist|taskkill/"
            },
            {
                "name": "$domain",
                "type": "text",
                "value": "dellgenius.hopto.org"
            },
            {
                "name": "$grammer_massacre",
                "type": "regex",
                "value": "/BADD|Bad Error Happened|/"
            },
            {
                "name": "$mayBePresent",
                "type": "regex",
                "value": "/self\\.DIE|THE_GUID_KEY/"
            },
            {
                "name": "$pipe_out",
                "type": "text",
                "value": "Abibliophobia23"
            },
            {
                "name": "$shot",
                "type": "text",
                "value": "shot_{0}_{1}.png"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'TRITON_ICS_FRAMEWORK', NULL, '{"md5": "0face841f7b2953e7c29c064d6886523", "author": "nicholas.carr @itsreallynick", "description": "TRITON framework recovered during Mandiant ICS incident response"}', '[
    {
        "condition_terms": [
            "2",
            "of",
            "(",
            "$python_*",
            ")",
            "and",
            "7",
            "of",
            "(",
            "$py_*",
            ")",
            "and",
            "filesize",
            "<",
            "3MB"
        ],
        "metadata": [
            {
                "author": "nicholas.carr @itsreallynick"
            },
            {
                "md5": "0face841f7b2953e7c29c064d6886523"
            },
            {
                "description": "TRITON framework recovered during Mandiant ICS incident response"
            }
        ],
        "raw_condition": "condition:\n          2 of ($python_*) and 7 of ($py_*) and filesize < 3MB\n",
        "raw_meta": "meta:\n          author = \"nicholas.carr @itsreallynick\"\n          md5 = \"0face841f7b2953e7c29c064d6886523\"\n          description = \"TRITON framework recovered during Mandiant ICS incident response\"\n      ",
        "raw_strings": "strings:\n          $python_compiled = \".pyc\" nocase ascii wide\n          $python_module_01 = \"__module__\" nocase ascii wide\n          $python_module_02 = \"<module>\" nocase ascii wide\n          $python_script_01 = \"import Ts\" nocase ascii wide\n          $python_script_02 = \"def ts_\" nocase ascii wide  \n\n          $py_cnames_01 = \"TS_cnames.py\" nocase ascii wide\n          $py_cnames_02 = \"TRICON\" nocase ascii wide\n          $py_cnames_03 = \"TriStation \" nocase ascii wide\n          $py_cnames_04 = \" chassis \" nocase ascii wide  \n\n          $py_tslibs_01 = \"GetCpStatus\" nocase ascii wide\n          $py_tslibs_02 = \"ts_\" ascii wide\n          $py_tslibs_03 = \" sequence\" nocase ascii wide\n          $py_tslibs_04 = /import Ts(Hi|Low|Base)[^:alpha:]/ nocase ascii wide\n          $py_tslibs_05 = /module\\s?version/ nocase ascii wide\n          $py_tslibs_06 = \"bad \" nocase ascii wide\n          $py_tslibs_07 = \"prog_cnt\" nocase ascii wide  \n\n          $py_tsbase_01 = \"TsBase.py\" nocase ascii wide\n          $py_tsbase_02 = \".TsBase(\" nocase ascii wide \n         \n          $py_tshi_01 = \"TsHi.py\" nocase ascii wide\n          $py_tshi_02 = \"keystate\" nocase ascii wide\n          $py_tshi_03 = \"GetProjectInfo\" nocase ascii wide\n          $py_tshi_04 = \"GetProgramTable\" nocase ascii wide\n          $py_tshi_05 = \"SafeAppendProgramMod\" nocase ascii wide\n          $py_tshi_06 = \".TsHi(\" ascii nocase wide  \n\n          $py_tslow_01 = \"TsLow.py\" nocase ascii wide\n          $py_tslow_02 = \"print_last_error\" ascii nocase wide\n          $py_tslow_03 = \".TsLow(\" ascii nocase wide\n          $py_tslow_04 = \"tcm_\" ascii wide\n          $py_tslow_05 = \" TCM found\" nocase ascii wide  \n\n          $py_crc_01 = \"crc.pyc\" nocase ascii wide\n          $py_crc_02 = \"CRC16_MODBUS\" ascii wide\n          $py_crc_03 = \"Kotov Alaxander\" nocase ascii wide\n          $py_crc_04 = \"CRC_CCITT_XMODEM\" ascii wide\n          $py_crc_05 = \"crc16ret\" ascii wide\n          $py_crc_06 = \"CRC16_CCITT_x1D0F\" ascii wide\n          $py_crc_07 = /CRC16_CCITT[^_]/ ascii wide  \n\n          $py_sh_01 = \"sh.pyc\" nocase ascii wide  \n\n          $py_keyword_01 = \" FAILURE\" ascii wide\n          $py_keyword_02 = \"symbol table\" nocase ascii wide  \n\n          $py_TRIDENT_01 = \"inject.bin\" ascii nocase wide\n          $py_TRIDENT_02 = \"imain.bin\" ascii nocase wide  \n\n      ",
        "rule_name": "TRITON_ICS_FRAMEWORK",
        "start_line": 5,
        "stop_line": 65,
        "strings": [
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$python_compiled",
                "type": "text",
                "value": ".pyc"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$python_module_01",
                "type": "text",
                "value": "__module__"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$python_module_02",
                "type": "text",
                "value": "<module>"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$python_script_01",
                "type": "text",
                "value": "import Ts"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$python_script_02",
                "type": "text",
                "value": "def ts_"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_cnames_01",
                "type": "text",
                "value": "TS_cnames.py"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_cnames_02",
                "type": "text",
                "value": "TRICON"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_cnames_03",
                "type": "text",
                "value": "TriStation "
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_cnames_04",
                "type": "text",
                "value": " chassis "
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_tslibs_01",
                "type": "text",
                "value": "GetCpStatus"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$py_tslibs_02",
                "type": "text",
                "value": "ts_"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_tslibs_03",
                "type": "text",
                "value": " sequence"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_tslibs_04",
                "type": "regex",
                "value": "/import Ts(Hi|Low|Base)[^:alpha:]/"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_tslibs_05",
                "type": "regex",
                "value": "/module\\s?version/"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_tslibs_06",
                "type": "text",
                "value": "bad "
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_tslibs_07",
                "type": "text",
                "value": "prog_cnt"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_tsbase_01",
                "type": "text",
                "value": "TsBase.py"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_tsbase_02",
                "type": "text",
                "value": ".TsBase("
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_tshi_01",
                "type": "text",
                "value": "TsHi.py"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_tshi_02",
                "type": "text",
                "value": "keystate"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_tshi_03",
                "type": "text",
                "value": "GetProjectInfo"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_tshi_04",
                "type": "text",
                "value": "GetProgramTable"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_tshi_05",
                "type": "text",
                "value": "SafeAppendProgramMod"
            },
            {
                "modifiers": [
                    "ascii",
                    "nocase",
                    "wide"
                ],
                "name": "$py_tshi_06",
                "type": "text",
                "value": ".TsHi("
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_tslow_01",
                "type": "text",
                "value": "TsLow.py"
            },
            {
                "modifiers": [
                    "ascii",
                    "nocase",
                    "wide"
                ],
                "name": "$py_tslow_02",
                "type": "text",
                "value": "print_last_error"
            },
            {
                "modifiers": [
                    "ascii",
                    "nocase",
                    "wide"
                ],
                "name": "$py_tslow_03",
                "type": "text",
                "value": ".TsLow("
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$py_tslow_04",
                "type": "text",
                "value": "tcm_"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_tslow_05",
                "type": "text",
                "value": " TCM found"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_crc_01",
                "type": "text",
                "value": "crc.pyc"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$py_crc_02",
                "type": "text",
                "value": "CRC16_MODBUS"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_crc_03",
                "type": "text",
                "value": "Kotov Alaxander"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$py_crc_04",
                "type": "text",
                "value": "CRC_CCITT_XMODEM"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$py_crc_05",
                "type": "text",
                "value": "crc16ret"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$py_crc_06",
                "type": "text",
                "value": "CRC16_CCITT_x1D0F"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$py_crc_07",
                "type": "regex",
                "value": "/CRC16_CCITT[^_]/"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_sh_01",
                "type": "text",
                "value": "sh.pyc"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$py_keyword_01",
                "type": "text",
                "value": " FAILURE"
            },
            {
                "modifiers": [
                    "nocase",
                    "ascii",
                    "wide"
                ],
                "name": "$py_keyword_02",
                "type": "text",
                "value": "symbol table"
            },
            {
                "modifiers": [
                    "ascii",
                    "nocase",
                    "wide"
                ],
                "name": "$py_TRIDENT_01",
                "type": "text",
                "value": "inject.bin"
            },
            {
                "modifiers": [
                    "ascii",
                    "nocase",
                    "wide"
                ],
                "name": "$py_TRIDENT_02",
                "type": "text",
                "value": "imain.bin"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Batel_export_function', NULL, '{"date": "2016/10/15", "author": "@j0sm1", "filetype": "binary", "reference": "https://www.symantec.com/security_response/writeup.jsp?docid=2016-091923-4146-99", "description": "Batel backdoor"}', '[
    {
        "condition_terms": [
            "pe.exports",
            "(",
            "\"run_shell\"",
            ")",
            "and",
            "pe.imports",
            "(",
            "\"kernel32.dll\"",
            ",",
            "\"GetTickCount\"",
            ")",
            "and",
            "pe.imports",
            "(",
            "\"kernel32.dll\"",
            ",",
            "\"IsDebuggerPresent\"",
            ")",
            "and",
            "pe.imports",
            "(",
            "\"msvcr100.dll\"",
            ",",
            "\"_crt_debugger_hook\"",
            ")",
            "and",
            "pe.imports",
            "(",
            "\"kernel32.dll\"",
            ",",
            "\"TerminateProcess\"",
            ")",
            "and",
            "pe.imports",
            "(",
            "\"kernel32.dll\"",
            ",",
            "\"UnhandledExceptionFilter\"",
            ")"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "@j0sm1"
            },
            {
                "date": "2016/10/15"
            },
            {
                "description": "Batel backdoor"
            },
            {
                "reference": "https://www.symantec.com/security_response/writeup.jsp?docid=2016-091923-4146-99"
            },
            {
                "filetype": "binary"
            }
        ],
        "raw_condition": "condition:\n        pe.exports(\"run_shell\") and pe.imports(\"kernel32.dll\",\"GetTickCount\") and pe.imports(\"kernel32.dll\",\"IsDebuggerPresent\") and pe.imports(\"msvcr100.dll\",\"_crt_debugger_hook\") and pe.imports(\"kernel32.dll\",\"TerminateProcess\") and pe.imports(\"kernel32.dll\",\"UnhandledExceptionFilter\")\n",
        "raw_meta": "meta:\n        author = \"@j0sm1\"\n        date = \"2016/10/15\"\n        description = \"Batel backdoor\"\n        reference = \"https://www.symantec.com/security_response/writeup.jsp?docid=2016-091923-4146-99\"\n        filetype = \"binary\"\n\n    ",
        "rule_name": "Batel_export_function",
        "start_line": 8,
        "stop_line": 20
    }
]
');
INSERT INTO public.rule VALUES (default, 'unpacked_shiva_ransomware', NULL, '{"author": "Marc Rivero | @seifreed", "reference": "https://twitter.com/malwrhunterteam/status/1037424962569732096", "description": "Rule to detect an unpacked sample of Shiva ransopmw"}', '[
    {
        "condition_terms": [
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "filesize",
            "<",
            "800KB",
            ")",
            "and",
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Rule to detect an unpacked sample of Shiva ransopmw"
            },
            {
                "author": "Marc Rivero | @seifreed"
            },
            {
                "reference": "https://twitter.com/malwrhunterteam/status/1037424962569732096"
            }
        ],
        "raw_condition": "condition:\n\n      ( uint16(0) == 0x5a4d and filesize < 800KB ) and all of them \n",
        "raw_meta": "meta:\n\n      description = \"Rule to detect an unpacked sample of Shiva ransopmw\"\n      author = \"Marc Rivero | @seifreed\"\n      reference = \"https://twitter.com/malwrhunterteam/status/1037424962569732096\"\n    \n   ",
        "raw_strings": "strings:\n\n      $s1 = \"c:\\\\Users\\\\sys\\\\Desktop\\\\v 0.5\\\\Shiva\\\\Shiva\\\\obj\\\\Debug\\\\shiva.pdb\" fullword ascii\n      $s2 = \"This email will be as confirmation you are ready to pay for decryption key.\" fullword wide\n      $s3 = \"Your important files are now encrypted due to a security problem with your PC!\" fullword wide\n      $s4 = \"write.php?info=\" fullword wide\n      $s5 = \" * Do not try to decrypt your data using third party software, it may cause permanent data loss.\" fullword wide\n      $s6 = \" * Do not rename encrypted files.\" fullword wide\n      $s7 = \".compositiontemplate\" fullword wide\n      $s8 = \"You have to pay for decryption in Bitcoins. The price depends on how fast you write to us.\" fullword wide\n      $s9 = \"\\\\READ_IT.txt\" fullword wide\n      $s10 = \".lastlogin\" fullword wide\n      $s11 = \".logonxp\" fullword wide\n      $s12 = \" * Decryption of your files with the help of third parties may cause increased price\" fullword wide\n      $s13 = \"After payment we will send you the decryption tool that will decrypt all your files.\" fullword wide\n   \n   ",
        "rule_name": "unpacked_shiva_ransomware",
        "start_line": 1,
        "stop_line": 28,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "c:\\\\Users\\\\sys\\\\Desktop\\\\v 0.5\\\\Shiva\\\\Shiva\\\\obj\\\\Debug\\\\shiva.pdb"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s2",
                "type": "text",
                "value": "This email will be as confirmation you are ready to pay for decryption key."
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s3",
                "type": "text",
                "value": "Your important files are now encrypted due to a security problem with your PC!"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s4",
                "type": "text",
                "value": "write.php?info="
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s5",
                "type": "text",
                "value": " * Do not try to decrypt your data using third party software, it may cause permanent data loss."
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s6",
                "type": "text",
                "value": " * Do not rename encrypted files."
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s7",
                "type": "text",
                "value": ".compositiontemplate"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s8",
                "type": "text",
                "value": "You have to pay for decryption in Bitcoins. The price depends on how fast you write to us."
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s9",
                "type": "text",
                "value": "\\\\READ_IT.txt"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s10",
                "type": "text",
                "value": ".lastlogin"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s11",
                "type": "text",
                "value": ".logonxp"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s12",
                "type": "text",
                "value": " * Decryption of your files with the help of third parties may cause increased price"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s13",
                "type": "text",
                "value": "After payment we will send you the decryption tool that will decrypt all your files."
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'APT_Hikit_msrv', NULL, '{"author": "ThreatConnect Intelligence Research Team"}', '[
    {
        "condition_terms": [
            "any",
            "of",
            "them"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "ThreatConnect Intelligence Research Team"
            }
        ],
        "raw_condition": "condition:\n    any of them\n",
        "raw_meta": "meta:\n    author = \"ThreatConnect Intelligence Research Team\"\n\n",
        "raw_strings": "strings:\n    $m = {6D 73 72 76 2E 64 6C 6C 00 44 6C 6C}\n\n",
        "rule_name": "APT_Hikit_msrv",
        "start_line": 8,
        "stop_line": 19,
        "strings": [
            {
                "name": "$m",
                "type": "byte",
                "value": "{6D 73 72 76 2E 64 6C 6C 00 44 6C 6C}"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Mozart', NULL, '{"author": "Nick Hoffman - Morphick Inc", "reference": "http://securitykitten.github.io/the-mozart-ram-scraper/", "description": "Detects samples of the Mozart POS RAM scraping utility"}', '[
    {
        "condition_terms": [
            "any",
            "of",
            "(",
            "$pdb",
            ",",
            "$output",
            ",",
            "$encode_data",
            ")",
            "or",
            "all",
            "of",
            "(",
            "$service*",
            ")"
        ],
        "metadata": [
            {
                "author": "Nick Hoffman - Morphick Inc"
            },
            {
                "description": "Detects samples of the Mozart POS RAM scraping utility"
            },
            {
                "reference": "http://securitykitten.github.io/the-mozart-ram-scraper/"
            }
        ],
        "raw_condition": "condition:\n      any of ($pdb, $output, $encode_data) or\n      all of ($service*)\n",
        "raw_meta": "meta:\n       author = \"Nick Hoffman - Morphick Inc\"\n       description = \"Detects samples of the Mozart POS RAM scraping utility\"\n       reference = \"http://securitykitten.github.io/the-mozart-ram-scraper/\"\n   ",
        "raw_strings": "strings:\n       $pdb = \"z:\\\\Slender\\\\mozart\\\\mozart\\\\Release\\\\mozart.pdb\" nocase wide ascii\n       $output = {67 61 72 62 61 67 65 2E 74 6D 70 00}\n       $service_name = \"NCR SelfServ Platform Remote Monitor\" nocase wide ascii\n       $service_name_short = \"NCR_RemoteMonitor\"\n       $encode_data = {B8 08 10 00 00 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 53 55 8B AC 24 14 10 00 00 89 84 24 0C 10 00 00 56 8B C5 33 F6 33 DB 8D 50 01 8D A4 24 00 00 00 00 8A 08 40 84 C9 ?? ?? 2B C2 89 44 24 0C ?? ?? 8B 94 24 1C 10 00 00 57 8B FD 2B FA 89 7C 24 10 ?? ?? 8B 7C 24 10 8A 04 17 02 86 E0 BA 40 00 88 02 B8 ?? ?? ?? ?? 46 8D 78 01 8D A4 24 00 00 00 00 8A 08 40 84 C9 ?? ?? 2B C7 3B F0 ?? ?? 33 F6 8B C5 43 42 8D 78 01 8A 08 40 84 C9 ?? ?? 2B C7 3B D8 ?? ?? 5F 8B B4 24 1C 10 00 00 8B C5 C6 04 33 00 8D 50 01 8A 08 40 84 C9 ?? ?? 8B 8C 24 20 10 00 00 2B C2 51 8D 54 24 14 52 50 56 E8 ?? ?? ?? ?? 83 C4 10 8B D6 5E 8D 44 24 0C 8B C8 5D 2B D1 5B 8A 08 88 0C 02 40 84 C9 ?? ?? 8B 8C 24 04 10 00 00 E8 ?? ?? ?? ?? 81 C4 08 10 00 00}\n   ",
        "rule_name": "Mozart",
        "start_line": 5,
        "stop_line": 20,
        "strings": [
            {
                "modifiers": [
                    "nocase",
                    "wide",
                    "ascii"
                ],
                "name": "$pdb",
                "type": "text",
                "value": "z:\\\\Slender\\\\mozart\\\\mozart\\\\Release\\\\mozart.pdb"
            },
            {
                "name": "$output",
                "type": "byte",
                "value": "{67 61 72 62 61 67 65 2E 74 6D 70 00}"
            },
            {
                "modifiers": [
                    "nocase",
                    "wide",
                    "ascii"
                ],
                "name": "$service_name",
                "type": "text",
                "value": "NCR SelfServ Platform Remote Monitor"
            },
            {
                "name": "$service_name_short",
                "type": "text",
                "value": "NCR_RemoteMonitor"
            },
            {
                "name": "$encode_data",
                "type": "byte",
                "value": "{B8 08 10 00 00 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? 53 55 8B AC 24 14 10 00 00 89 84 24 0C 10 00 00 56 8B C5 33 F6 33 DB 8D 50 01 8D A4 24 00 00 00 00 8A 08 40 84 C9 ?? ?? 2B C2 89 44 24 0C ?? ?? 8B 94 24 1C 10 00 00 57 8B FD 2B FA 89 7C 24 10 ?? ?? 8B 7C 24 10 8A 04 17 02 86 E0 BA 40 00 88 02 B8 ?? ?? ?? ?? 46 8D 78 01 8D A4 24 00 00 00 00 8A 08 40 84 C9 ?? ?? 2B C7 3B F0 ?? ?? 33 F6 8B C5 43 42 8D 78 01 8A 08 40 84 C9 ?? ?? 2B C7 3B D8 ?? ?? 5F 8B B4 24 1C 10 00 00 8B C5 C6 04 33 00 8D 50 01 8A 08 40 84 C9 ?? ?? 8B 8C 24 20 10 00 00 2B C2 51 8D 54 24 14 52 50 56 E8 ?? ?? ?? ?? 83 C4 10 8B D6 5E 8D 44 24 0C 8B C8 5D 2B D1 5B 8A 08 88 0C 02 40 84 C9 ?? ?? 8B 8C 24 04 10 00 00 E8 ?? ?? ?? ?? 81 C4 08 10 00 00}"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Emissary_APT_Malware_1', NULL, '{"date": "2016-01-02", "hash1": "9420017390c598ee535c24f7bcbd39f40eca699d6c94dc35bcf59ddf918c59ab", "hash2": "70561f58c9e5868f44169854bcc906001947d98d15e9b4d2fbabd1262d938629", "hash3": "0e64e68f6f88b25530699a1cd12f6f2790ea98e6e8fa3b4bc279f8e5c09d7290", "hash4": "69caa2a4070559d4cafdf79020c4356c721088eb22398a8740dea8d21ae6e664", "hash5": "675869fac21a94c8f470765bc6dd15b17cc4492dd639b878f241a45b2c3890fc", "hash6": "e817610b62ccd00bdfc9129f947ac7d078d97525e9628a3aa61027396dba419b", "hash7": "a8b0d084949c4f289beb4950f801bf99588d1b05f68587b245a31e8e82f7a1b8", "hash8": "acf7dc5a10b00f0aac102ecd9d87cd94f08a37b2726cb1e16948875751d04cc9", "hash9": "e21b47dfa9e250f49a3ab327b7444902e545bed3c4dcfa5e2e990af20593af6d", "score": 75, "author": "Florian Roth", "hash10": "e369417a7623d73346f6dff729e68f7e057f7f6dae7bb03d56a7510cb3bfe538", "hash11": "29d8dc863427c8e37b75eb738069c2172e79607acc7b65de6f8086ba36abf051", "hash12": "98fb1d2975babc18624e3922406545458642e01360746870deee397df93f50e0", "hash13": "fbcb401cf06326ab4bb53fb9f01f1ca647f16f926811ea66984f1a1b8cf2f7bb", "reference": "http://goo.gl/V0epcf", "description": "Detect Emissary Malware - from samples A08E81B411.DAT, ishelp.dll"}', '[
    {
        "condition_terms": [
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "filesize",
            "<",
            "250KB",
            "and",
            "3",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Detect Emissary Malware - from samples A08E81B411.DAT, ishelp.dll"
            },
            {
                "author": "Florian Roth"
            },
            {
                "reference": "http://goo.gl/V0epcf"
            },
            {
                "date": "2016-01-02"
            },
            {
                "score": 75
            },
            {
                "hash1": "9420017390c598ee535c24f7bcbd39f40eca699d6c94dc35bcf59ddf918c59ab"
            },
            {
                "hash2": "70561f58c9e5868f44169854bcc906001947d98d15e9b4d2fbabd1262d938629"
            },
            {
                "hash3": "0e64e68f6f88b25530699a1cd12f6f2790ea98e6e8fa3b4bc279f8e5c09d7290"
            },
            {
                "hash4": "69caa2a4070559d4cafdf79020c4356c721088eb22398a8740dea8d21ae6e664"
            },
            {
                "hash5": "675869fac21a94c8f470765bc6dd15b17cc4492dd639b878f241a45b2c3890fc"
            },
            {
                "hash6": "e817610b62ccd00bdfc9129f947ac7d078d97525e9628a3aa61027396dba419b"
            },
            {
                "hash7": "a8b0d084949c4f289beb4950f801bf99588d1b05f68587b245a31e8e82f7a1b8"
            },
            {
                "hash8": "acf7dc5a10b00f0aac102ecd9d87cd94f08a37b2726cb1e16948875751d04cc9"
            },
            {
                "hash9": "e21b47dfa9e250f49a3ab327b7444902e545bed3c4dcfa5e2e990af20593af6d"
            },
            {
                "hash10": "e369417a7623d73346f6dff729e68f7e057f7f6dae7bb03d56a7510cb3bfe538"
            },
            {
                "hash11": "29d8dc863427c8e37b75eb738069c2172e79607acc7b65de6f8086ba36abf051"
            },
            {
                "hash12": "98fb1d2975babc18624e3922406545458642e01360746870deee397df93f50e0"
            },
            {
                "hash13": "fbcb401cf06326ab4bb53fb9f01f1ca647f16f926811ea66984f1a1b8cf2f7bb"
            }
        ],
        "raw_condition": "condition:\n        uint16(0) == 0x5a4d and filesize < 250KB and 3 of them\n",
        "raw_meta": "meta:\n        description = \"Detect Emissary Malware - from samples A08E81B411.DAT, ishelp.dll\"\n        author = \"Florian Roth\"\n        reference = \"http://goo.gl/V0epcf\"\n        date = \"2016-01-02\"\n        score = 75\n        hash1 = \"9420017390c598ee535c24f7bcbd39f40eca699d6c94dc35bcf59ddf918c59ab\"\n        hash2 = \"70561f58c9e5868f44169854bcc906001947d98d15e9b4d2fbabd1262d938629\"\n        hash3 = \"0e64e68f6f88b25530699a1cd12f6f2790ea98e6e8fa3b4bc279f8e5c09d7290\"\n        hash4 = \"69caa2a4070559d4cafdf79020c4356c721088eb22398a8740dea8d21ae6e664\"\n        hash5 = \"675869fac21a94c8f470765bc6dd15b17cc4492dd639b878f241a45b2c3890fc\"\n        hash6 = \"e817610b62ccd00bdfc9129f947ac7d078d97525e9628a3aa61027396dba419b\"\n        hash7 = \"a8b0d084949c4f289beb4950f801bf99588d1b05f68587b245a31e8e82f7a1b8\"\n        hash8 = \"acf7dc5a10b00f0aac102ecd9d87cd94f08a37b2726cb1e16948875751d04cc9\"\n        hash9 = \"e21b47dfa9e250f49a3ab327b7444902e545bed3c4dcfa5e2e990af20593af6d\"\n        hash10 = \"e369417a7623d73346f6dff729e68f7e057f7f6dae7bb03d56a7510cb3bfe538\"\n        hash11 = \"29d8dc863427c8e37b75eb738069c2172e79607acc7b65de6f8086ba36abf051\"\n        hash12 = \"98fb1d2975babc18624e3922406545458642e01360746870deee397df93f50e0\"\n        hash13 = \"fbcb401cf06326ab4bb53fb9f01f1ca647f16f926811ea66984f1a1b8cf2f7bb\"\n\n    ",
        "raw_strings": "strings:\n        $s1 = \"cmd.exe /c %s > %s\" fullword ascii\n        $s2 = \"execute cmd timeout.\" fullword ascii\n        $s3 = \"rundll32.exe \\\"%s\\\",Setting\" fullword ascii\n        $s4 = \"DownloadFile - exception:%s.\" fullword ascii\n        $s5 = \"CDllApp::InitInstance() - Evnet create successful.\" fullword ascii\n        $s6 = \"UploadFile - EncryptBuffer Error\" fullword ascii\n        $s7 = \"WinDLL.dll\" fullword wide\n        $s8 = \"DownloadFile - exception:%s,code:0x%08x.\" fullword ascii\n        $s9 = \"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\" fullword ascii\n        $s10 = \"CDllApp::InitInstance() - Evnet already exists.\" fullword ascii\n\n    ",
        "rule_name": "Emissary_APT_Malware_1",
        "start_line": 12,
        "stop_line": 49,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "cmd.exe /c %s > %s"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s2",
                "type": "text",
                "value": "execute cmd timeout."
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s3",
                "type": "text",
                "value": "rundll32.exe \\\"%s\\\",Setting"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s4",
                "type": "text",
                "value": "DownloadFile - exception:%s."
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s5",
                "type": "text",
                "value": "CDllApp::InitInstance() - Evnet create successful."
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s6",
                "type": "text",
                "value": "UploadFile - EncryptBuffer Error"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s7",
                "type": "text",
                "value": "WinDLL.dll"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s8",
                "type": "text",
                "value": "DownloadFile - exception:%s,code:0x%08x."
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s9",
                "type": "text",
                "value": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s10",
                "type": "text",
                "value": "CDllApp::InitInstance() - Evnet already exists."
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'rtf_Kaba_jDoe', NULL, '{"date": "2013-12-10", "author": "@patrickrolsen", "maltype": "APT.Kaba", "version": "0.1", "filetype": "RTF", "description": "fe439af268cd3de3a99c21ea40cf493f, d0e0e68a88dce443b24453cc951cf55f, b563af92f144dea7327c9597d9de574e, and def0c9a4c732c3a1e8910db3f9451620"}', '[
    {
        "condition_terms": [
            "(",
            "$magic1",
            "or",
            "$magic2",
            "or",
            "$magic3",
            "at",
            "0",
            ")",
            "and",
            "all",
            "of",
            "(",
            "$author*",
            ")",
            "and",
            "$string1"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "@patrickrolsen"
            },
            {
                "maltype": "APT.Kaba"
            },
            {
                "filetype": "RTF"
            },
            {
                "version": "0.1"
            },
            {
                "description": "fe439af268cd3de3a99c21ea40cf493f, d0e0e68a88dce443b24453cc951cf55f, b563af92f144dea7327c9597d9de574e, and def0c9a4c732c3a1e8910db3f9451620"
            },
            {
                "date": "2013-12-10"
            }
        ],
        "raw_condition": "condition:\n    ($magic1 or $magic2 or $magic3 at 0) and all of ($author*) and $string1\n",
        "raw_meta": "meta:\n    author = \"@patrickrolsen\"\n    maltype = \"APT.Kaba\"\n    filetype = \"RTF\"\n    version = \"0.1\"\n    description = \"fe439af268cd3de3a99c21ea40cf493f, d0e0e68a88dce443b24453cc951cf55f, b563af92f144dea7327c9597d9de574e, and def0c9a4c732c3a1e8910db3f9451620\"\n    date = \"2013-12-10\"\n\n",
        "raw_strings": "strings:\n    $magic1 = { 7b 5c 72 74 30 31 } // {\\rt01\n    $magic2 = { 7b 5c 72 74 66 31 } // {\\rtf1\n    $magic3 = { 7b 5c 72 74 78 61 33 } // {\\rtxa3\n    $author1 = { 4A 6F 68 6E 20 44 6F 65 } // \"John Doe\"\n    $author2 = { 61 75 74 68 6f 72 20 53 74 6f 6e 65 } // \"author Stone\"\n    $string1 = { 44 30 [16] 43 46 [23] 31 31 45 }\n\n",
        "rule_name": "rtf_Kaba_jDoe",
        "start_line": 8,
        "stop_line": 29,
        "strings": [
            {
                "name": "$magic1",
                "type": "byte",
                "value": "{ 7b 5c 72 74 30 31 }"
            },
            {
                "name": "$magic2",
                "type": "byte",
                "value": "{ 7b 5c 72 74 66 31 }"
            },
            {
                "name": "$magic3",
                "type": "byte",
                "value": "{ 7b 5c 72 74 78 61 33 }"
            },
            {
                "name": "$author1",
                "type": "byte",
                "value": "{ 4A 6F 68 6E 20 44 6F 65 }"
            },
            {
                "name": "$author2",
                "type": "byte",
                "value": "{ 61 75 74 68 6f 72 20 53 74 6f 6e 65 }"
            },
            {
                "name": "$string1",
                "type": "byte",
                "value": "{ 44 30 [16] 43 46 [23] 31 31 45 }"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'POS_bruteforcing_bot', NULL, '{"ref": "https://github.com/reed1713", "date": "3/11/2014", "maltype": "botnet", "reference": "http://www.alienvault.com/open-threat-exchange/blog/botnet-bruteforcing-point-of-sale-via-remote-desktop", "description": "botnet bruteforcing POS terms via RDP"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "maltype": "botnet"
            },
            {
                "ref": "https://github.com/reed1713"
            },
            {
                "reference": "http://www.alienvault.com/open-threat-exchange/blog/botnet-bruteforcing-point-of-sale-via-remote-desktop"
            },
            {
                "date": "3/11/2014"
            },
            {
                "description": "botnet bruteforcing POS terms via RDP"
            }
        ],
        "raw_condition": "condition:\n\t\tall of them\n",
        "raw_meta": "meta:\n\t\tmaltype = \"botnet\"\n    ref = \"https://github.com/reed1713\"\n\t\treference = \"http://www.alienvault.com/open-threat-exchange/blog/botnet-bruteforcing-point-of-sale-via-remote-desktop\"\n\t\tdate = \"3/11/2014\"\n\t\tdescription = \"botnet bruteforcing POS terms via RDP\"\n\t",
        "raw_strings": "strings:\n\t\t$type=\"Microsoft-Windows-Security-Auditing\"\n\t\t$eventid=\"4688\"\n\t\t$data=\"\\\\AppData\\\\Roaming\\\\lsacs.exe\"\n\n\t",
        "rule_name": "POS_bruteforcing_bot",
        "start_line": 6,
        "stop_line": 21,
        "strings": [
            {
                "name": "$type",
                "type": "text",
                "value": "Microsoft-Windows-Security-Auditing"
            },
            {
                "name": "$eventid",
                "type": "text",
                "value": "4688"
            },
            {
                "name": "$data",
                "type": "text",
                "value": "\\\\AppData\\\\Roaming\\\\lsacs.exe"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'diamond_fox', NULL, '{"date": "2015-08-22", "author": "Brian Wallace @botnet_hunter", "description": "Identify DiamondFox", "author_email": "bwall@ballastsecurity.net"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Brian Wallace @botnet_hunter"
            },
            {
                "author_email": "bwall@ballastsecurity.net"
            },
            {
                "date": "2015-08-22"
            },
            {
                "description": "Identify DiamondFox"
            }
        ],
        "raw_condition": "condition:\n        all of them\n",
        "raw_meta": "meta:\n        author = \"Brian Wallace @botnet_hunter\"\n        author_email = \"bwall@ballastsecurity.net\"\n        date = \"2015-08-22\"\n        description = \"Identify DiamondFox\"\n   \n    ",
        "raw_strings": "strings:\n        $s1 = \"UPDATE_B\"\n        $s2 = \"UNISTALL_B\"\n        $s3 = \"S_PROTECT\"\n        $s4 = \"P_WALLET\"\n        $s5 = \"GR_COMMAND\"\n        $s6 = \"FTPUPLOAD\"\n   \n    ",
        "rule_name": "diamond_fox",
        "start_line": 6,
        "stop_line": 25,
        "strings": [
            {
                "name": "$s1",
                "type": "text",
                "value": "UPDATE_B"
            },
            {
                "name": "$s2",
                "type": "text",
                "value": "UNISTALL_B"
            },
            {
                "name": "$s3",
                "type": "text",
                "value": "S_PROTECT"
            },
            {
                "name": "$s4",
                "type": "text",
                "value": "P_WALLET"
            },
            {
                "name": "$s5",
                "type": "text",
                "value": "GR_COMMAND"
            },
            {
                "name": "$s6",
                "type": "text",
                "value": "FTPUPLOAD"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'cryptonar_ransomware', NULL, '{"author": "Marc Rivero | @seifreed", "reference": "https://www.bleepingcomputer.com/news/security/cryptonar-ransomware-discovered-and-quickly-decrypted/", "description": "Rule to detect CryptoNar Ransomware"}', '[
    {
        "condition_terms": [
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "filesize",
            "<",
            "2000KB",
            ")",
            "and",
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Rule to detect CryptoNar Ransomware"
            },
            {
                "author": "Marc Rivero | @seifreed"
            },
            {
                "reference": "https://www.bleepingcomputer.com/news/security/cryptonar-ransomware-discovered-and-quickly-decrypted/"
            }
        ],
        "raw_condition": "condition:\n      ( uint16(0) == 0x5a4d and filesize < 2000KB) and all of them \n",
        "raw_meta": "meta:\n   \n      description = \"Rule to detect CryptoNar Ransomware\"\n      author = \"Marc Rivero | @seifreed\"\n      reference = \"https://www.bleepingcomputer.com/news/security/cryptonar-ransomware-discovered-and-quickly-decrypted/\"\n      \n   ",
        "raw_strings": "strings:\n   \n      $s1 = \"C:\\\\narnar\\\\CryptoNar\\\\CryptoNarDecryptor\\\\obj\\\\Debug\\\\CryptoNar.pdb\" fullword ascii\n      $s2 = \"CryptoNarDecryptor.exe\" fullword wide\n      $s3 = \"server will eliminate the key after 72 hours since its generation (since the moment your computer was infected). Once this has \" fullword ascii\n      $s4 = \"Do not delete this file, else the decryption process will be broken\" fullword wide\n      $s5 = \"key you received, and wait until the decryption process is done.\" fullword ascii\n      $s6 = \"In order to receive your decryption key, you will have to pay $200 in bitcoins to this bitcoin address: [bitcoin address]\" fullword ascii\n      $s7 = \"Decryption process failed\" fullword wide\n      $s8 = \"CryptoNarDecryptor.KeyValidationWindow.resources\" fullword ascii\n      $s9 = \"Important note: Removing CryptoNar will not restore access to your encrypted files.\" fullword ascii\n      $s10 = \"johnsmith987654@tutanota.com\" fullword wide\n      $s11 = \"Decryption process will start soon\" fullword wide\n      $s12 = \"CryptoNarDecryptor.DecryptionProgressBarForm.resources\" fullword ascii\n      $s13 = \"DecryptionProcessProgressBar\" fullword wide\n      $s14 = \"CryptoNarDecryptor.Properties.Resources.resources\" fullword ascii\n      \n   ",
        "rule_name": "cryptonar_ransomware",
        "start_line": 1,
        "stop_line": 28,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "C:\\\\narnar\\\\CryptoNar\\\\CryptoNarDecryptor\\\\obj\\\\Debug\\\\CryptoNar.pdb"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s2",
                "type": "text",
                "value": "CryptoNarDecryptor.exe"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s3",
                "type": "text",
                "value": "server will eliminate the key after 72 hours since its generation (since the moment your computer was infected). Once this has "
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s4",
                "type": "text",
                "value": "Do not delete this file, else the decryption process will be broken"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s5",
                "type": "text",
                "value": "key you received, and wait until the decryption process is done."
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s6",
                "type": "text",
                "value": "In order to receive your decryption key, you will have to pay $200 in bitcoins to this bitcoin address: [bitcoin address]"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s7",
                "type": "text",
                "value": "Decryption process failed"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s8",
                "type": "text",
                "value": "CryptoNarDecryptor.KeyValidationWindow.resources"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s9",
                "type": "text",
                "value": "Important note: Removing CryptoNar will not restore access to your encrypted files."
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s10",
                "type": "text",
                "value": "johnsmith987654@tutanota.com"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s11",
                "type": "text",
                "value": "Decryption process will start soon"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s12",
                "type": "text",
                "value": "CryptoNarDecryptor.DecryptionProgressBarForm.resources"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s13",
                "type": "text",
                "value": "DecryptionProcessProgressBar"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s14",
                "type": "text",
                "value": "CryptoNarDecryptor.Properties.Resources.resources"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Windows_Malware_Zeus', '{Zeus_1134}', '{"date": "2014-03-03", "author": "Xylitol xylitol@malwareint.com", "reference": "http://www.xylibox.com/2014/03/zeus-1134.html", "description": "Match first two bytes, protocol and string present in Zeus 1.1.3.4"}', '[
    {
        "condition_terms": [
            "(",
            "$mz",
            "at",
            "0",
            "and",
            "all",
            "of",
            "(",
            "$protocol*",
            ")",
            "and",
            "(",
            "$stringR1",
            "or",
            "$stringR2",
            ")",
            ")"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "Xylitol xylitol@malwareint.com"
            },
            {
                "date": "2014-03-03"
            },
            {
                "description": "Match first two bytes, protocol and string present in Zeus 1.1.3.4"
            },
            {
                "reference": "http://www.xylibox.com/2014/03/zeus-1134.html"
            }
        ],
        "raw_condition": "condition:\n                    ($mz at 0 and all of ($protocol*) and ($stringR1 or $stringR2))\n    ",
        "raw_meta": "meta:\n                    author = \"Xylitol xylitol@malwareint.com\"\n                    date = \"2014-03-03\"\n                    description = \"Match first two bytes, protocol and string present in Zeus 1.1.3.4\"\n                    reference = \"http://www.xylibox.com/2014/03/zeus-1134.html\"\n                    \n            ",
        "raw_strings": "strings:\n                    $mz = {4D 5A}\n                    $protocol1 = \"X_ID: \"\n                    $protocol2 = \"X_OS: \"\n                    $protocol3 = \"X_BV: \"\n                    $stringR1 = \"InitializeSecurityDescriptor\"\n                    $stringR2 = \"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1)\"\n            ",
        "rule_name": "Windows_Malware_Zeus",
        "start_line": 8,
        "stop_line": 25,
        "strings": [
            {
                "name": "$mz",
                "type": "byte",
                "value": "{4D 5A}"
            },
            {
                "name": "$protocol1",
                "type": "text",
                "value": "X_ID: "
            },
            {
                "name": "$protocol2",
                "type": "text",
                "value": "X_OS: "
            },
            {
                "name": "$protocol3",
                "type": "text",
                "value": "X_BV: "
            },
            {
                "name": "$stringR1",
                "type": "text",
                "value": "InitializeSecurityDescriptor"
            },
            {
                "name": "$stringR2",
                "type": "text",
                "value": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1)"
            }
        ],
        "tags": [
            "Zeus_1134"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'apt_win32_dll_rat_1a53b0cp32e46g0qio7', NULL, '{"info": "Indicators for FTA-1020", "hash1": "75d3d1f23628122a64a2f1b7ef33f5cf", "hash2": "d9821468315ccd3b9ea03161566ef18e", "hash3": "b9af5f5fd434a65d7aa1b55f5441c90a", "author": "https://www.fidelissecurity.com/", "reference": "https://github.com/fideliscyber"}', '[
    {
        "comments": [
            "// Loop to decode a static string. It reveals the \"1a53b0cp32e46g0qio9\" static string sent in the beacon",
            "// cmp     \teax, 14h",
            "// inc\t\teax",
            "// Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "// Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0;rv:11.0) like Gecko"
        ],
        "condition_terms": [
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5A4D",
            "or",
            "uint32",
            "(",
            "0",
            ")",
            "==",
            "0x4464c457f",
            ")",
            "and",
            "(",
            "all",
            "of",
            "them",
            ")"
        ],
        "metadata": [
            {
                "author": "https://www.fidelissecurity.com/"
            },
            {
                "info": "Indicators for FTA-1020"
            },
            {
                "hash1": "75d3d1f23628122a64a2f1b7ef33f5cf"
            },
            {
                "hash2": "d9821468315ccd3b9ea03161566ef18e"
            },
            {
                "hash3": "b9af5f5fd434a65d7aa1b55f5441c90a"
            },
            {
                "reference": "https://github.com/fideliscyber"
            }
        ],
        "raw_condition": "condition:\n\t(uint16(0) == 0x5A4D or uint32(0) == 0x4464c457f) and (all of them)\n",
        "raw_meta": "meta:\n\t\tauthor = \"https://www.fidelissecurity.com/\"\n        \tinfo = \"Indicators for FTA-1020\"\n\t\thash1 = \"75d3d1f23628122a64a2f1b7ef33f5cf\"\n\t\thash2 = \"d9821468315ccd3b9ea03161566ef18e\"\n\t\thash3 = \"b9af5f5fd434a65d7aa1b55f5441c90a\"\n\t\treference = \"https://github.com/fideliscyber\"\n\t",
        "raw_strings": "strings:\n    \t// Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0;rv:11.0) like Gecko\n\t\t$ = { c7 [2] 64 00 63 00 c7 [2] 69 00 62 00 c7 [2] 7a 00 7e 00 c7 [2] 2d 00 43 00 c7 [2] 59 00 2d 00 c7 [2] 3b 00 23 00 c7 [2] 3e 00 36 00 c7 [2] 2d 00 5a 00 c7 [2] 42 00 5a 00 c7 [2] 3b 00 39 00 c7 [2] 36 00 2d 00 c7 [2] 59 00 7f 00 c7 [2] 64 00 69 00 c7 [2] 68 00 63 00 c7 [2] 79 00 22 00 c7 [2] 3a 00 23 00 c7 [2] 3d 00 36 00 c7 [2] 2d 00 7f 00 c7 [2] 7b 00 37 00 c7 [2] 3c 00 3c 00 c7 [2] 23 00 3d 00 c7 [2] 24 00 2d 00 c7 [2] 61 00 64 00 c7 [2] 66 00 68 00 c7 [2] 2d 00 4a 00 c7 [2] 68 00 6e 00 c7 [2] 66 00 62 00 } // offset 10001566\n\t// Software\\Microsoft\\Windows\\CurrentVersion\\Run\n       $ = { c7 [2] 23 00 24 00 c7 [2] 24 00 33 00 c7 [2] 38 00 22 00 c7 [2] 00 00 33 00 c7 [2] 24 00 25 00 c7 [2] 3f 00 39 00 c7 [2] 38 00 0a 00 c7 [2] 04 00 23 00 c7 [2] 38 00 00 00 c7 [2] 43 00 66 00 c7 [2] 6d 00 60 00 c7 [2] 67 00 52 00 c7 [2] 6e 00 63 00 c7 [2] 7b 00 67 00 c7 [2] 70 00 00 00 c7 [2] 43 00 4d 00 c7 [2] 44 00 00 00 c7 [2] 0f 00 43 00 c7 [2] 00 00 50 00 c7 [2] 49 00 4e 00 c7 [2] 47 00 00 00 c7 [2] 11 00 12 00 c7 [2] 17 00 0e 00 c7 [2] 10 00 0e 00 c7 [2] 10 00 0e 00 c7 [2] 11 00 06 00 c7 [2] 44 00 45 00 c7 [2] 4c 00 00 00 } // 10003D09\n\t$ = { 66 [4-7] 0d 40 83 f8 44 7c ?? }\n       // xor\t\tword ptr [ebp+eax*2+var_5C], 14h\n\t// inc\t\teax\n\t// cmp     \teax, 14h\n       // Loop to decode a static string. It reveals the \"1a53b0cp32e46g0qio9\" static string sent in the beacon\n\t$ = { 66 [4-7] 14 40 83 f8 14 7c ?? } // 100017F0\n\t$ = { 66 [4-7] 56 40 83 f8 2d 7c ?? } // 10003621\n\t$ = { 66 [4-7] 20 40 83 f8 1a 7c ?? } // 10003640\n\t$ = { 80 [2-7] 2e 40 3d 50 02 00 00 72 ?? } //  10003930\n\t$ = \"%08x%08x%08x%08x\" wide ascii\n\t$ = \"WinHttpGetIEProxyConfigForCurrentUser\" wide ascii\n\n\t",
        "rule_name": "apt_win32_dll_rat_1a53b0cp32e46g0qio7",
        "start_line": 5,
        "stop_line": 33,
        "strings": [
            {
                "name": "$",
                "type": "byte",
                "value": "{ c7 [2] 64 00 63 00 c7 [2] 69 00 62 00 c7 [2] 7a 00 7e 00 c7 [2] 2d 00 43 00 c7 [2] 59 00 2d 00 c7 [2] 3b 00 23 00 c7 [2] 3e 00 36 00 c7 [2] 2d 00 5a 00 c7 [2] 42 00 5a 00 c7 [2] 3b 00 39 00 c7 [2] 36 00 2d 00 c7 [2] 59 00 7f 00 c7 [2] 64 00 69 00 c7 [2] 68 00 63 00 c7 [2] 79 00 22 00 c7 [2] 3a 00 23 00 c7 [2] 3d 00 36 00 c7 [2] 2d 00 7f 00 c7 [2] 7b 00 37 00 c7 [2] 3c 00 3c 00 c7 [2] 23 00 3d 00 c7 [2] 24 00 2d 00 c7 [2] 61 00 64 00 c7 [2] 66 00 68 00 c7 [2] 2d 00 4a 00 c7 [2] 68 00 6e 00 c7 [2] 66 00 62 00 }"
            },
            {
                "name": "$",
                "type": "byte",
                "value": "{ c7 [2] 23 00 24 00 c7 [2] 24 00 33 00 c7 [2] 38 00 22 00 c7 [2] 00 00 33 00 c7 [2] 24 00 25 00 c7 [2] 3f 00 39 00 c7 [2] 38 00 0a 00 c7 [2] 04 00 23 00 c7 [2] 38 00 00 00 c7 [2] 43 00 66 00 c7 [2] 6d 00 60 00 c7 [2] 67 00 52 00 c7 [2] 6e 00 63 00 c7 [2] 7b 00 67 00 c7 [2] 70 00 00 00 c7 [2] 43 00 4d 00 c7 [2] 44 00 00 00 c7 [2] 0f 00 43 00 c7 [2] 00 00 50 00 c7 [2] 49 00 4e 00 c7 [2] 47 00 00 00 c7 [2] 11 00 12 00 c7 [2] 17 00 0e 00 c7 [2] 10 00 0e 00 c7 [2] 10 00 0e 00 c7 [2] 11 00 06 00 c7 [2] 44 00 45 00 c7 [2] 4c 00 00 00 }"
            },
            {
                "name": "$",
                "type": "byte",
                "value": "{ 66 [4-7] 0d 40 83 f8 44 7c ?? }"
            },
            {
                "name": "$",
                "type": "byte",
                "value": "{ 66 [4-7] 14 40 83 f8 14 7c ?? }"
            },
            {
                "name": "$",
                "type": "byte",
                "value": "{ 66 [4-7] 56 40 83 f8 2d 7c ?? }"
            },
            {
                "name": "$",
                "type": "byte",
                "value": "{ 66 [4-7] 20 40 83 f8 1a 7c ?? }"
            },
            {
                "name": "$",
                "type": "byte",
                "value": "{ 80 [2-7] 2e 40 3d 50 02 00 00 72 ?? }"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "%08x%08x%08x%08x"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$",
                "type": "text",
                "value": "WinHttpGetIEProxyConfigForCurrentUser"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'ransomware_PetrWrap', NULL, '{"hash": "71B6A493388E7D0B40C83CE903BC6B04", "author": "Kaspersky Lab", "version": "1.0", "copyright": "Kaspersky Lab", "reference": "https://securelist.com/schroedingers-petya/78870/", "description": "Rule to detect PetrWrap ransomware samples", "last_modified": "2017-06-27"}', '[
    {
        "condition_terms": [
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5A4D",
            "and",
            "filesize",
            "<",
            "1000000",
            "and",
            "any",
            "of",
            "them"
        ],
        "metadata": [
            {
                "copyright": "Kaspersky Lab"
            },
            {
                "description": "Rule to detect PetrWrap ransomware samples"
            },
            {
                "reference": "https://securelist.com/schroedingers-petya/78870/"
            },
            {
                "last_modified": "2017-06-27"
            },
            {
                "author": "Kaspersky Lab"
            },
            {
                "hash": "71B6A493388E7D0B40C83CE903BC6B04"
            },
            {
                "version": "1.0"
            }
        ],
        "raw_condition": "condition:\n\tuint16(0) == 0x5A4D and filesize < 1000000 and any of them \n",
        "raw_meta": "meta:\n\tcopyright= \"Kaspersky Lab\"\n\tdescription = \"Rule to detect PetrWrap ransomware samples\"\n    reference = \"https://securelist.com/schroedingers-petya/78870/\"\n\tlast_modified = \"2017-06-27\"\n\tauthor = \"Kaspersky Lab\"\n\thash = \"71B6A493388E7D0B40C83CE903BC6B04\"\n\tversion = \"1.0\"\n",
        "raw_strings": "strings:\n\t$a1 = \"MIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2n2JmURWV/uHB0ZrlQ/wcYJBwLhQ9EqJ3iDqmN19Oo7NtyEUmbYmopcqYLIBZzQ2ZTK0A2DtX4GRKxEEFLCy7vP12EYOPXknVy/mf0JFWixz29QiTf5oLu15wVLONCuEibGaNNpgqCXsPwfITDbDDmdrRIiUEUw6o3pt5pNOskfOJbMan2TZu\" fullword wide\n\t$a2 = \".3ds.7z.accdb.ai.asp.aspx.avhd.back.bak.c.cfg.conf.cpp.cs.ctl.dbf.disk.djvu.doc.docx.dwg.eml.fdb.gz.h.hdd.kdbx.mail.mdb.msg.nrg.ora.ost.ova.ovf.pdf.php.pmf.ppt.pptx.pst.pvi.py.pyc.rar.rtf.sln.sql.tar.vbox.vbs.vcb.vdi.vfd.vmc.vmdk.vmsd.vmx.vsdx.vsv.work.xls\" fullword wide\n\t$a3 = \"DESTROY ALL OF YOUR DATA PLEASE ENSURE THAT YOUR POWER CABLE IS PLUGGED\" fullword ascii\n\t$a4 = \"1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX\" fullword ascii\n\t$a5 = \"wowsmith123456posteo.net.\" fullword wide\n",
        "rule_name": "ransomware_PetrWrap",
        "start_line": 1,
        "stop_line": 19,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$a1",
                "type": "text",
                "value": "MIIBCgKCAQEAxP/VqKc0yLe9JhVqFMQGwUITO6WpXWnKSNQAYT0O65Cr8PjIQInTeHkXEjfO2n2JmURWV/uHB0ZrlQ/wcYJBwLhQ9EqJ3iDqmN19Oo7NtyEUmbYmopcqYLIBZzQ2ZTK0A2DtX4GRKxEEFLCy7vP12EYOPXknVy/mf0JFWixz29QiTf5oLu15wVLONCuEibGaNNpgqCXsPwfITDbDDmdrRIiUEUw6o3pt5pNOskfOJbMan2TZu"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$a2",
                "type": "text",
                "value": ".3ds.7z.accdb.ai.asp.aspx.avhd.back.bak.c.cfg.conf.cpp.cs.ctl.dbf.disk.djvu.doc.docx.dwg.eml.fdb.gz.h.hdd.kdbx.mail.mdb.msg.nrg.ora.ost.ova.ovf.pdf.php.pmf.ppt.pptx.pst.pvi.py.pyc.rar.rtf.sln.sql.tar.vbox.vbs.vcb.vdi.vfd.vmc.vmdk.vmsd.vmx.vsdx.vsv.work.xls"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$a3",
                "type": "text",
                "value": "DESTROY ALL OF YOUR DATA PLEASE ENSURE THAT YOUR POWER CABLE IS PLUGGED"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$a4",
                "type": "text",
                "value": "1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$a5",
                "type": "text",
                "value": "wowsmith123456posteo.net."
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'easterjackpos', NULL, '{"date": "2014-09-02", "author": "Brian Wallace @botnet_hunter", "description": "Identify JackPOS", "author_email": "bwall@ballastsecurity.net"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Brian Wallace @botnet_hunter"
            },
            {
                "author_email": "bwall@ballastsecurity.net"
            },
            {
                "date": "2014-09-02"
            },
            {
                "description": "Identify JackPOS"
            }
        ],
        "raw_condition": "condition:\n        all of them\n",
        "raw_meta": "meta:\n        author = \"Brian Wallace @botnet_hunter\"\n        author_email = \"bwall@ballastsecurity.net\"\n        date = \"2014-09-02\"\n        description = \"Identify JackPOS\"\n\t",
        "raw_strings": "strings:\n\t    $s1 = \"updateinterval=\"\n        $s2 = \"cardinterval=\"\n        $s3 = \"{[!17!]}{[!18!]}\"\n    ",
        "rule_name": "easterjackpos",
        "start_line": 5,
        "stop_line": 17,
        "strings": [
            {
                "name": "$s1",
                "type": "text",
                "value": "updateinterval="
            },
            {
                "name": "$s2",
                "type": "text",
                "value": "cardinterval="
            },
            {
                "name": "$s3",
                "type": "text",
                "value": "{[!17!]}{[!18!]}"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Payload_Exe2Hex', '{toolkit}', '{"date": "2016-01-15", "score": 70, "author": "Florian Roth", "reference": "https://github.com/g0tmi1k/exe2hex", "description": "Detects payload generated by exe2hex"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "(",
            "$a*",
            ")",
            "or",
            "all",
            "of",
            "(",
            "$b*",
            ")",
            "or",
            "all",
            "of",
            "(",
            "$c*",
            ")",
            "or",
            "all",
            "of",
            "(",
            "$d*",
            ")"
        ],
        "metadata": [
            {
                "description": "Detects payload generated by exe2hex"
            },
            {
                "author": "Florian Roth"
            },
            {
                "reference": "https://github.com/g0tmi1k/exe2hex"
            },
            {
                "date": "2016-01-15"
            },
            {
                "score": 70
            }
        ],
        "raw_condition": "condition:\n\t\tall of ($a*) or all of ($b*) or all of ($c*) or all of ($d*)\n",
        "raw_meta": "meta:\n\t\tdescription = \"Detects payload generated by exe2hex\"\n\t\tauthor = \"Florian Roth\"\n\t\treference = \"https://github.com/g0tmi1k/exe2hex\"\n\t\tdate = \"2016-01-15\"\n\t\tscore = 70\n\t",
        "raw_strings": "strings:\n\t\t$a1 = \"set /p \\\"=4d5a\" ascii\n\t\t$a2 = \"powershell -Command \\\"$hex=\" ascii\n\t\t$b1 = \"set+%2Fp+%22%3D4d5\" ascii\n\t\t$b2 = \"powershell+-Command+%22%24hex\" ascii\n\t\t$c1 = \"echo 4d 5a \" ascii\n\t\t$c2 = \"echo r cx >>\" ascii\n\t\t$d1 = \"echo+4d+5a+\" ascii\n\t\t$d2 = \"echo+r+cx+%3E%3E\" ascii\n\t",
        "rule_name": "Payload_Exe2Hex",
        "start_line": 13,
        "stop_line": 31,
        "strings": [
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$a1",
                "type": "text",
                "value": "set /p \\\"=4d5a"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$a2",
                "type": "text",
                "value": "powershell -Command \\\"$hex="
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$b1",
                "type": "text",
                "value": "set+%2Fp+%22%3D4d5"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$b2",
                "type": "text",
                "value": "powershell+-Command+%22%24hex"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$c1",
                "type": "text",
                "value": "echo 4d 5a "
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$c2",
                "type": "text",
                "value": "echo r cx >>"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$d1",
                "type": "text",
                "value": "echo+4d+5a+"
            },
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$d2",
                "type": "text",
                "value": "echo+r+cx+%3E%3E"
            }
        ],
        "tags": [
            "toolkit"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'elknot_xor', '{malware}', '{"date": "2016-04-25", "author": "liuya@360.cn", "sample": "474429d9da170e733213940acc9a2b1c, 2579aa65a28c32778790ec1c673abc49", "reference": "http://liuya0904.blogspot.tw/2016/04/new-elknotbillgates-variant-with-xor.html", "description": "elknot/Billgates variants with XOR like C2 encryption scheme"}', '[
    {
        "comments": [
            "/*\n    .rodata:08104D20 E8 00 00 00 00                          call    $+5\n    .rodata:08104D25 87 1C 24                                xchg    ebx, [esp+4+var_4] ;\n    .rodata:08104D28 83 EB 05                                sub     ebx, 5\n    .rodata:08104D2B 8D 83 00 FD FF FF                       lea     eax, [ebx-300h]\n    .rodata:08104D31 83 BB 10 CA 02 00 02                    cmp     dword ptr [ebx+2CA10h], 2\n    .rodata:08104D38 75 05                                   jnz     short loc_8104D3F\n    .rodata:08104D3A 05 00 01 00 00                          add     eax, 100h\n    .rodata:08104D3F                         loc_8104D3F:                           \n    .rodata:08104D3F 50                                      push    eax\n    .rodata:08104D40 FF 74 24 10                             push    [esp+8+strsVector]\n*/",
            "/*\n   seg000:08130801 68 00 09 13 08                          push    offset dword_8130900\n    seg000:08130806 83 3D 30 17 13 08 02                    cmp     ds:dword_8131730, 2\n    seg000:0813080D 75 07                                   jnz     short loc_8130816\n    seg000:0813080F 81 04 24 00 01 00 00                    add     dword ptr [esp], 100h\n    seg000:08130816                         loc_8130816:                           \n    seg000:08130816 50                                      push    eax\n    seg000:08130817 E8 15 00 00 00                          call    sub_8130831\n    seg000:0813081C E9 C8 F6 F5 FF                          jmp     near ptr 808FEE9h\n   */",
            "//md5=474429d9da170e733213940acc9a2b1c"
        ],
        "condition_terms": [
            "1",
            "of",
            "(",
            "$decrypt_c2_func_*",
            ")"
        ],
        "metadata": [
            {
                "author": "liuya@360.cn"
            },
            {
                "date": "2016-04-25"
            },
            {
                "description": "elknot/Billgates variants with XOR like C2 encryption scheme"
            },
            {
                "reference": "http://liuya0904.blogspot.tw/2016/04/new-elknotbillgates-variant-with-xor.html"
            },
            {
                "sample": "474429d9da170e733213940acc9a2b1c, 2579aa65a28c32778790ec1c673abc49"
            }
        ],
        "raw_condition": "condition:\n    1 of ($decrypt_c2_func_*)\n",
        "raw_meta": "meta:\n    author = \"liuya@360.cn\"\n    date = \"2016-04-25\"\n    description = \"elknot/Billgates variants with XOR like C2 encryption scheme\"\n    reference = \"http://liuya0904.blogspot.tw/2016/04/new-elknotbillgates-variant-with-xor.html\"\n    sample = \"474429d9da170e733213940acc9a2b1c, 2579aa65a28c32778790ec1c673abc49\"\n\n",
        "raw_strings": "strings:\n   //md5=474429d9da170e733213940acc9a2b1c\n   /*\n   seg000:08130801 68 00 09 13 08                          push    offset dword_8130900\n    seg000:08130806 83 3D 30 17 13 08 02                    cmp     ds:dword_8131730, 2\n    seg000:0813080D 75 07                                   jnz     short loc_8130816\n    seg000:0813080F 81 04 24 00 01 00 00                    add     dword ptr [esp], 100h\n    seg000:08130816                         loc_8130816:                           \n    seg000:08130816 50                                      push    eax\n    seg000:08130817 E8 15 00 00 00                          call    sub_8130831\n    seg000:0813081C E9 C8 F6 F5 FF                          jmp     near ptr 808FEE9h\n   */\n    $decrypt_c2_func_1 = {08 83 [5] 02 75 07 81 04 24 00 01 00 00 50 e8 [4] e9}\n\n    // md5=2579aa65a28c32778790ec1c673abc49\n    /*\n    .rodata:08104D20 E8 00 00 00 00                          call    $+5\n    .rodata:08104D25 87 1C 24                                xchg    ebx, [esp+4+var_4] ;\n    .rodata:08104D28 83 EB 05                                sub     ebx, 5\n    .rodata:08104D2B 8D 83 00 FD FF FF                       lea     eax, [ebx-300h]\n    .rodata:08104D31 83 BB 10 CA 02 00 02                    cmp     dword ptr [ebx+2CA10h], 2\n    .rodata:08104D38 75 05                                   jnz     short loc_8104D3F\n    .rodata:08104D3A 05 00 01 00 00                          add     eax, 100h\n    .rodata:08104D3F                         loc_8104D3F:                           \n    .rodata:08104D3F 50                                      push    eax\n    .rodata:08104D40 FF 74 24 10                             push    [esp+8+strsVector]\n*/\n$decrypt_c2_func_2 = {e8 00 00 00 00 87 [2] 83 eb 05 8d 83 [4] 83 bb [4] 02 75 05}\n\n",
        "rule_name": "elknot_xor",
        "start_line": 6,
        "stop_line": 46,
        "strings": [
            {
                "name": "$decrypt_c2_func_1",
                "type": "byte",
                "value": "{08 83 [5] 02 75 07 81 04 24 00 01 00 00 50 e8 [4] e9}"
            },
            {
                "name": "$decrypt_c2_func_2",
                "type": "byte",
                "value": "{e8 00 00 00 00 87 [2] 83 eb 05 8d 83 [4] 83 bb [4] 02 75 05}"
            }
        ],
        "tags": [
            "malware"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'universal_1337_stealer_serveur', '{Stealer}', '{"date": "24/02/2013", "author": "Kevin Falcoz", "description": "Universal 1337 Stealer Serveur"}', '[
    {
        "condition_terms": [
            "$signature1",
            "and",
            "$signature2",
            "or",
            "$signature3",
            "and",
            "$signature4"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "Kevin Falcoz"
            },
            {
                "date": "24/02/2013"
            },
            {
                "description": "Universal 1337 Stealer Serveur"
            }
        ],
        "raw_condition": "condition:\n\t\t$signature1 and $signature2 or $signature3 and $signature4\n",
        "raw_meta": "meta:\n\t\tauthor=\"Kevin Falcoz\"\n\t\tdate=\"24/02/2013\"\n\t\tdescription=\"Universal 1337 Stealer Serveur\"\n\t\t\n\t",
        "raw_strings": "strings:\n\t\t$signature1={2A 5B 53 2D 50 2D 4C 2D 49 2D 54 5D 2A} /*[S-P-L-I-T]*/\n\t\t$signature2={2A 5B 48 2D 45 2D 52 2D 45 5D 2A} /*[H-E-R-E]*/\n\t\t$signature3={46 54 50 7E} /*FTP~*/\n\t\t$signature4={7E 31 7E 31 7E 30 7E 30} /*~1~1~0~0*/\n\t\t\n\t",
        "rule_name": "universal_1337_stealer_serveur",
        "start_line": 8,
        "stop_line": 23,
        "strings": [
            {
                "name": "$signature1",
                "type": "byte",
                "value": "{2A 5B 53 2D 50 2D 4C 2D 49 2D 54 5D 2A}"
            },
            {
                "name": "$signature2",
                "type": "byte",
                "value": "{2A 5B 48 2D 45 2D 52 2D 45 5D 2A}"
            },
            {
                "name": "$signature3",
                "type": "byte",
                "value": "{46 54 50 7E}"
            },
            {
                "name": "$signature4",
                "type": "byte",
                "value": "{7E 31 7E 31 7E 30 7E 30}"
            }
        ],
        "tags": [
            "Stealer"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Kovter', NULL, '{"date": "9-19-2016", "maltype": "Kovter", "reference": "http://blog.airbuscybersecurity.com/post/2016/03/FILELESS-MALWARE-%E2%80%93-A-BEHAVIOURAL-ANALYSIS-OF-KOVTER-PERSISTENCE", "description": "fileless malware"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "maltype": "Kovter"
            },
            {
                "reference": "http://blog.airbuscybersecurity.com/post/2016/03/FILELESS-MALWARE-%E2%80%93-A-BEHAVIOURAL-ANALYSIS-OF-KOVTER-PERSISTENCE"
            },
            {
                "date": "9-19-2016"
            },
            {
                "description": "fileless malware"
            }
        ],
        "raw_condition": "condition:\n\t\tall of them\n",
        "raw_meta": "meta:\n\t\tmaltype = \"Kovter\"\n    reference = \"http://blog.airbuscybersecurity.com/post/2016/03/FILELESS-MALWARE-%E2%80%93-A-BEHAVIOURAL-ANALYSIS-OF-KOVTER-PERSISTENCE\"\n\t\tdate = \"9-19-2016\"\n\t\tdescription = \"fileless malware\"\n\t",
        "raw_strings": "strings:\n\t\t$type=\"Microsoft-Windows-Security-Auditing\" wide ascii\n\t\t$eventid=\"4688\" wide ascii\n\t\t$data=\"Windows\\\\System32\\\\regsvr32.exe\" wide ascii\n\t\t\n\t\t$type1=\"Microsoft-Windows-Security-Auditing\" wide ascii\n\t\t$eventid1=\"4689\" wide ascii\n\t\t$data1=\"Windows\\\\System32\\\\mshta.exe\" wide ascii\n\t\t\n\t\t$type2=\"Microsoft-Windows-Security-Auditing\" wide ascii\n\t\t$eventid2=\"4689\" wide ascii\n\t\t$data2=\"Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\" wide ascii\n\n\t\t$type3=\"Microsoft-Windows-Security-Auditing\" wide ascii\n\t\t$eventid3=\"4689\" wide ascii\n\t\t$data3=\"Windows\\\\System32\\\\wbem\\\\WmiPrvSE.exe\" wide ascii\n\n\n\t",
        "rule_name": "Kovter",
        "start_line": 6,
        "stop_line": 33,
        "strings": [
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$type",
                "type": "text",
                "value": "Microsoft-Windows-Security-Auditing"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$eventid",
                "type": "text",
                "value": "4688"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$data",
                "type": "text",
                "value": "Windows\\\\System32\\\\regsvr32.exe"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$type1",
                "type": "text",
                "value": "Microsoft-Windows-Security-Auditing"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$eventid1",
                "type": "text",
                "value": "4689"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$data1",
                "type": "text",
                "value": "Windows\\\\System32\\\\mshta.exe"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$type2",
                "type": "text",
                "value": "Microsoft-Windows-Security-Auditing"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$eventid2",
                "type": "text",
                "value": "4689"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$data2",
                "type": "text",
                "value": "Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$type3",
                "type": "text",
                "value": "Microsoft-Windows-Security-Auditing"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$eventid3",
                "type": "text",
                "value": "4689"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$data3",
                "type": "text",
                "value": "Windows\\\\System32\\\\wbem\\\\WmiPrvSE.exe"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Adwind', NULL, '{"author": "Asaf Aprozper, asafa AT minerva-labs.com", "reference": "https://minerva-labs.com/post/adwind-and-other-evasive-java-rats", "description": "Adwind RAT", "last_modified": "2017-06-25"}', '[
    {
        "condition_terms": [
            "$PK",
            "at",
            "0",
            "and",
            "$a0",
            "and",
            "$a1"
        ],
        "metadata": [
            {
                "author": "Asaf Aprozper, asafa AT minerva-labs.com"
            },
            {
                "description": "Adwind RAT"
            },
            {
                "reference": "https://minerva-labs.com/post/adwind-and-other-evasive-java-rats"
            },
            {
                "last_modified": "2017-06-25"
            }
        ],
        "raw_condition": "condition:\n        $PK at 0 and $a0 and $a1\n",
        "raw_meta": "meta:\n        author=\"Asaf Aprozper, asafa AT minerva-labs.com\"\n        description = \"Adwind RAT\"\n        reference = \"https://minerva-labs.com/post/adwind-and-other-evasive-java-rats\"\n        last_modified = \"2017-06-25\"\n",
        "raw_strings": "strings:\n        $a0 = \"META-INF/MANIFEST.MF\"\n        $a1 = /Main(\\$)Q[0-9][0-9][0-9][0-9]/\n        $PK = \"PK\"\n",
        "rule_name": "Adwind",
        "start_line": 1,
        "stop_line": 14,
        "strings": [
            {
                "name": "$a0",
                "type": "text",
                "value": "META-INF/MANIFEST.MF"
            },
            {
                "name": "$a1",
                "type": "regex",
                "value": "/Main(\\$)Q[0-9][0-9][0-9][0-9]/"
            },
            {
                "name": "$PK",
                "type": "text",
                "value": "PK"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'genome', NULL, '{"date": "2014-09-07", "author": "Brian Wallace @botnet_hunter", "description": "Identify Genome", "author_email": "bwall@ballastsecurity.net"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Brian Wallace @botnet_hunter"
            },
            {
                "author_email": "bwall@ballastsecurity.net"
            },
            {
                "date": "2014-09-07"
            },
            {
                "description": "Identify Genome"
            }
        ],
        "raw_condition": "condition:\n        all of them\n",
        "raw_meta": "meta:\n        author = \"Brian Wallace @botnet_hunter\"\n        author_email = \"bwall@ballastsecurity.net\"\n        date = \"2014-09-07\"\n        description = \"Identify Genome\"\n\t",
        "raw_strings": "strings:\n\t    $s1 = \"Attempting to create more than one keyboard::Monitor instance\"\n        $s2 = \"{Right windows}\"\n        $s3 = \"Access violation - no RTTI data!\"\n    ",
        "rule_name": "genome",
        "start_line": 5,
        "stop_line": 17,
        "strings": [
            {
                "name": "$s1",
                "type": "text",
                "value": "Attempting to create more than one keyboard::Monitor instance"
            },
            {
                "name": "$s2",
                "type": "text",
                "value": "{Right windows}"
            },
            {
                "name": "$s3",
                "type": "text",
                "value": "Access violation - no RTTI data!"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'urausy_skype_dat', '{memory}', '{"author": "AlienVault Labs", "description": "Yara rule to match against memory of processes infected by Urausy skype.dat"}', '[
    {
        "condition_terms": [
            "$a",
            "and",
            "$b",
            "and",
            "(",
            "all",
            "of",
            "(",
            "$win*",
            ")",
            "or",
            "all",
            "of",
            "(",
            "$desk*",
            ")",
            ")"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "AlienVault Labs"
            },
            {
                "description": "Yara rule to match against memory of processes infected by Urausy skype.dat"
            }
        ],
        "raw_condition": "condition:\n\t\t$a and $b and (all of ($win*) or all of ($desk*))\n",
        "raw_meta": "meta:\n\t\tauthor = \"AlienVault Labs\"\n\t\tdescription = \"Yara rule to match against memory of processes infected by Urausy skype.dat\"\n\t",
        "raw_strings": "strings:\n\t\t$a = \"skype.dat\" ascii wide\n\t\t$b = \"skype.ini\" ascii wide\n\t\t$win1 = \"CreateWindow\"\n\t\t$win2 = \"YIWEFHIWQ\" ascii wide\n\t\t$desk1 = \"CreateDesktop\"\n\t\t$desk2 = \"MyDesktop\" ascii wide\n\t",
        "rule_name": "urausy_skype_dat",
        "start_line": 8,
        "stop_line": 21,
        "strings": [
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$a",
                "type": "text",
                "value": "skype.dat"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$b",
                "type": "text",
                "value": "skype.ini"
            },
            {
                "name": "$win1",
                "type": "text",
                "value": "CreateWindow"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$win2",
                "type": "text",
                "value": "YIWEFHIWQ"
            },
            {
                "name": "$desk1",
                "type": "text",
                "value": "CreateDesktop"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$desk2",
                "type": "text",
                "value": "MyDesktop"
            }
        ],
        "tags": [
            "memory"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'shrug2_ransomware', NULL, '{"author": "Marc Rivero | @seifreed", "reference": "https://blogs.quickheal.com/new-net-ransomware-shrug2/", "description": "Rule to detect Shrug2 ransomware"}', '[
    {
        "condition_terms": [
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "filesize",
            "<",
            "2000KB",
            ")",
            "and",
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Rule to detect Shrug2 ransomware"
            },
            {
                "author": "Marc Rivero | @seifreed"
            },
            {
                "reference": "https://blogs.quickheal.com/new-net-ransomware-shrug2/"
            }
        ],
        "raw_condition": "condition:\n      ( uint16(0) == 0x5a4d and filesize < 2000KB ) and all of them \n",
        "raw_meta": "meta:\n\n      description = \"Rule to detect Shrug2 ransomware\"\n      author = \"Marc Rivero | @seifreed\"\n      reference = \"https://blogs.quickheal.com/new-net-ransomware-shrug2/\"\n       \n   ",
        "raw_strings": "strings:\n\n      $s1 = \"C:\\\\Users\\\\Gamer\\\\Desktop\\\\Shrug2\\\\ShrugTwo\\\\ShrugTwo\\\\obj\\\\Debug\\\\ShrugTwo.pdb\" fullword ascii\n      $s2 = \"http://tempacc11vl.000webhostapp.com/\" fullword wide\n      $s4 = \"Shortcut for @ShrugDecryptor@.exe\" fullword wide\n      $s5 = \"C:\\\\Users\\\\\" fullword wide\n      $s6 = \"http://clients3.google.com/generate_204\" fullword wide\n      $s7 = \"\\\\Desktop\\\\@ShrugDecryptor@.lnk\" fullword wide\n   \n   ",
        "rule_name": "shrug2_ransomware",
        "start_line": 1,
        "stop_line": 20,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "C:\\\\Users\\\\Gamer\\\\Desktop\\\\Shrug2\\\\ShrugTwo\\\\ShrugTwo\\\\obj\\\\Debug\\\\ShrugTwo.pdb"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s2",
                "type": "text",
                "value": "http://tempacc11vl.000webhostapp.com/"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s4",
                "type": "text",
                "value": "Shortcut for @ShrugDecryptor@.exe"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s5",
                "type": "text",
                "value": "C:\\\\Users\\\\"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s6",
                "type": "text",
                "value": "http://clients3.google.com/generate_204"
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s7",
                "type": "text",
                "value": "\\\\Desktop\\\\@ShrugDecryptor@.lnk"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Zegost', '{Trojan}', '{"date": "10/06/2013", "author": "Kevin Falcoz", "description": "Zegost Trojan"}', '[
    {
        "condition_terms": [
            "$signature1",
            "and",
            "$signature2"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "Kevin Falcoz"
            },
            {
                "date": "10/06/2013"
            },
            {
                "description": "Zegost Trojan"
            }
        ],
        "raw_condition": "condition:\n\t\t$signature1 and $signature2\n",
        "raw_meta": "meta:\n\t\tauthor=\"Kevin Falcoz\"\n\t\tdate=\"10/06/2013\"\n\t\tdescription=\"Zegost Trojan\"\n\t\t\n\t",
        "raw_strings": "strings:\n\t\t$signature1={39 2F 66 33 30 4C 69 35 75 62 4F 35 44 4E 41 44 44 78 47 38 73 37 36 32 74 71 59 3D}\n\t\t$signature2={00 BA DA 22 51 42 6F 6D 65 00}\n\t\t\n\t",
        "rule_name": "Zegost",
        "start_line": 8,
        "stop_line": 21,
        "strings": [
            {
                "name": "$signature1",
                "type": "byte",
                "value": "{39 2F 66 33 30 4C 69 35 75 62 4F 35 44 4E 41 44 44 78 47 38 73 37 36 32 74 71 59 3D}"
            },
            {
                "name": "$signature2",
                "type": "byte",
                "value": "{00 BA DA 22 51 42 6F 6D 65 00}"
            }
        ],
        "tags": [
            "Trojan"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'apt_backspace', NULL, '{"date": "2015-05-14", "hash": "6cbfeb7526de65eb2e3c848acac05da1e885636d17c1c45c62ad37e44cd84f99", "author": "Bit Byte Bitten", "description": "Detects APT backspace"}', '[
    {
        "condition_terms": [
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Detects APT backspace"
            },
            {
                "author": "Bit Byte Bitten"
            },
            {
                "date": "2015-05-14"
            },
            {
                "hash": "6cbfeb7526de65eb2e3c848acac05da1e885636d17c1c45c62ad37e44cd84f99"
            }
        ],
        "raw_condition": "condition:\n        uint16(0) == 0x5a4d and all of them\n",
        "raw_meta": "meta:\n        description = \"Detects APT backspace\"\n        author = \"Bit Byte Bitten\"\n        date = \"2015-05-14\"\n        hash = \"6cbfeb7526de65eb2e3c848acac05da1e885636d17c1c45c62ad37e44cd84f99\"\n        \n    ",
        "raw_strings": "strings:\n        $s1 = \"!! Use Splice Socket !!\"\n        $s2 = \"User-Agent: SJZJ (compatible; MSIE 6.0; Win32)\"\n        $s3 = \"g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d\"\n\n    ",
        "rule_name": "apt_backspace",
        "start_line": 5,
        "stop_line": 21,
        "strings": [
            {
                "name": "$s1",
                "type": "text",
                "value": "!! Use Splice Socket !!"
            },
            {
                "name": "$s2",
                "type": "text",
                "value": "User-Agent: SJZJ (compatible; MSIE 6.0; Win32)"
            },
            {
                "name": "$s3",
                "type": "text",
                "value": "g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'shifu_shiz', NULL, '{"date": "2018-03-16", "author": "J from THL <j@techhelplist.com>", "filetype": "memory", "maltype1": "Banker", "maltype2": "Keylogger", "maltype3": "Stealer", "reference1": "https://researchcenter.paloaltonetworks.com/2017/01/unit42-2016-updates-shifu-banking-trojan/", "reference2": "https://beta.virusbay.io/sample/browse/24a6dfaa98012a839658c143475a1e46", "reference3": "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/crime_shifu_trojan.yar", "description": "Memory string yara for Shifu/Shiz"}', '[
    {
        "condition_terms": [
            "18",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Memory string yara for Shifu/Shiz"
            },
            {
                "author": "J from THL <j@techhelplist.com>"
            },
            {
                "reference1": "https://researchcenter.paloaltonetworks.com/2017/01/unit42-2016-updates-shifu-banking-trojan/"
            },
            {
                "reference2": "https://beta.virusbay.io/sample/browse/24a6dfaa98012a839658c143475a1e46"
            },
            {
                "reference3": "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/crime_shifu_trojan.yar"
            },
            {
                "date": "2018-03-16"
            },
            {
                "maltype1": "Banker"
            },
            {
                "maltype2": "Keylogger"
            },
            {
                "maltype3": "Stealer"
            },
            {
                "filetype": "memory"
            }
        ],
        "raw_condition": "condition:\n\t\t18 of them\n",
        "raw_meta": "meta:\n\t\tdescription = \"Memory string yara for Shifu/Shiz\"\n\t\tauthor = \"J from THL <j@techhelplist.com>\"\n\t\treference1 = \"https://researchcenter.paloaltonetworks.com/2017/01/unit42-2016-updates-shifu-banking-trojan/\"\n\t\treference2 = \"https://beta.virusbay.io/sample/browse/24a6dfaa98012a839658c143475a1e46\"\n    reference3 = \"https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/crime_shifu_trojan.yar\"\n\t\tdate = \"2018-03-16\"\n\t\tmaltype1 = \"Banker\"\n\t\tmaltype2 = \"Keylogger\"\n\t\tmaltype3 = \"Stealer\"\n\t\tfiletype = \"memory\"\n\n\t",
        "raw_strings": "strings:\n\t\t$aa = \"auth_loginByPassword\"\tfullword ascii\n\t\t$ab = \"back_command\"\tfullword ascii\n\t\t$ac = \"back_custom1\"\tfullword ascii\n\t\t$ad = \"GetClipboardData\"\tfullword ascii\n\t\t$ae = \"iexplore.exe|opera.exe|java.exe|javaw.exe|explorer.exe|isclient.exe|intpro.exe|ipc_full.exe\"\tfullword ascii\n\t\t$af = \"mnp.exe|cbsmain.dll|firefox.exe|clmain.exe|core.exe|maxthon.exe|avant.exe|safari.exe\"\tfullword ascii\n\t\t$ag = \"svchost.exe|chrome.exe|notepad.exe|rundll32.exe|netscape.exe|tbb-firefox.exe|frd.exe\"\tfullword ascii\n\t\t$ah = \"!inject\"\tfullword ascii\n\t\t$ai = \"!deactivebc\"\tfullword ascii\n\t\t$aj = \"!kill_os\"\tfullword ascii\n\t\t$ak = \"!load\"\tfullword ascii\n\t\t$al = \"!new_config\"\tfullword ascii\n\t\t$am = \"!activebc\"\tfullword ascii\n\t\t$an = \"keylog.txt\"\tfullword ascii\n\t\t$ao = \"keys_path.txt\"\tfullword ascii\n\t\t$ap = \"pass.log\"\tfullword ascii\n\t\t$aq = \"passwords.txt\"\tfullword ascii\n\t\t$ar = \"Content-Disposition: form-data; name=\\\"file\\\"; filename=\\\"report\\\"\"\tfullword ascii\n\t\t$as = \"Content-Disposition: form-data; name=\\\"pcname\\\"\"\tfullword ascii\n\t\t$at = \"botid=%s&ver=\"\tfullword ascii\n\t\t$au = \"action=auth&np=&login=\"\tfullword ascii\n\t\t$av = \"&ctl00%24MainMenu%24Login1%24UserName=\"\tfullword ascii\n\t\t$aw = \"&cvv=\"\tfullword ascii\n\t\t$ax = \"&cvv2=\"\tfullword ascii\n\t\t$ay = \"&domain=\"\tfullword ascii\n\t\t$az = \"LOGIN_AUTHORIZATION_CODE=\"\tfullword ascii\n\t\t$ba = \"name=%s&port=%u\"\tfullword ascii\n\t\t$bb = \"PeekNamedPipe\"\tfullword ascii\n\t\t$bc = \"[pst]\"\tfullword ascii\n\t\t$bd = \"[ret]\"\tfullword ascii\n\t\t$be = \"[tab]\"\tfullword ascii\n\t\t$bf = \"[bks]\"\tfullword ascii\n\t\t$bg = \"[del]\"\tfullword ascii\n\t\t$bh = \"[ins]\"\tfullword ascii\n\t\t$bi = \"&up=%u&os=%03u&rights=%s&ltime=%s%d&token=%d&cn=\"\tfullword ascii\n\n\t",
        "rule_name": "shifu_shiz",
        "start_line": 3,
        "stop_line": 55,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$aa",
                "type": "text",
                "value": "auth_loginByPassword"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$ab",
                "type": "text",
                "value": "back_command"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$ac",
                "type": "text",
                "value": "back_custom1"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$ad",
                "type": "text",
                "value": "GetClipboardData"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$ae",
                "type": "text",
                "value": "iexplore.exe|opera.exe|java.exe|javaw.exe|explorer.exe|isclient.exe|intpro.exe|ipc_full.exe"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$af",
                "type": "text",
                "value": "mnp.exe|cbsmain.dll|firefox.exe|clmain.exe|core.exe|maxthon.exe|avant.exe|safari.exe"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$ag",
                "type": "text",
                "value": "svchost.exe|chrome.exe|notepad.exe|rundll32.exe|netscape.exe|tbb-firefox.exe|frd.exe"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$ah",
                "type": "text",
                "value": "!inject"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$ai",
                "type": "text",
                "value": "!deactivebc"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$aj",
                "type": "text",
                "value": "!kill_os"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$ak",
                "type": "text",
                "value": "!load"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$al",
                "type": "text",
                "value": "!new_config"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$am",
                "type": "text",
                "value": "!activebc"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$an",
                "type": "text",
                "value": "keylog.txt"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$ao",
                "type": "text",
                "value": "keys_path.txt"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$ap",
                "type": "text",
                "value": "pass.log"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$aq",
                "type": "text",
                "value": "passwords.txt"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$ar",
                "type": "text",
                "value": "Content-Disposition: form-data; name=\\\"file\\\"; filename=\\\"report\\\""
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$as",
                "type": "text",
                "value": "Content-Disposition: form-data; name=\\\"pcname\\\""
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$at",
                "type": "text",
                "value": "botid=%s&ver="
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$au",
                "type": "text",
                "value": "action=auth&np=&login="
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$av",
                "type": "text",
                "value": "&ctl00%24MainMenu%24Login1%24UserName="
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$aw",
                "type": "text",
                "value": "&cvv="
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$ax",
                "type": "text",
                "value": "&cvv2="
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$ay",
                "type": "text",
                "value": "&domain="
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$az",
                "type": "text",
                "value": "LOGIN_AUTHORIZATION_CODE="
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$ba",
                "type": "text",
                "value": "name=%s&port=%u"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$bb",
                "type": "text",
                "value": "PeekNamedPipe"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$bc",
                "type": "text",
                "value": "[pst]"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$bd",
                "type": "text",
                "value": "[ret]"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$be",
                "type": "text",
                "value": "[tab]"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$bf",
                "type": "text",
                "value": "[bks]"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$bg",
                "type": "text",
                "value": "[del]"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$bh",
                "type": "text",
                "value": "[ins]"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$bi",
                "type": "text",
                "value": "&up=%u&os=%03u&rights=%s&ltime=%s%d&token=%d&cn="
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'APT_bestia', NULL, '{"date": "2014-03-19", "hash0": "9bb03bb5af40d1202378f95a6485fba8", "hash1": "7d9a806e0da0b869b10870dd6c7692c5", "author": "Adam Ziaja <adam@adamziaja.com> http://adamziaja.com", "maltype": "apt", "filetype": "exe", "references": "http://zaufanatrzeciastrona.pl/post/ukierunkowany-atak-na-pracownikow-polskich-samorzadow/", "description": "Bestia.3.02.012.07 malware used in APT attacks on Polish government"}', '[
    {
        "comments": [
            "/* generated with https://github.com/Xen0ph0n/YaraGenerator */",
            "/* PL */"
        ],
        "condition_terms": [
            "17",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Adam Ziaja <adam@adamziaja.com> http://adamziaja.com"
            },
            {
                "date": "2014-03-19"
            },
            {
                "description": "Bestia.3.02.012.07 malware used in APT attacks on Polish government"
            },
            {
                "references": "http://zaufanatrzeciastrona.pl/post/ukierunkowany-atak-na-pracownikow-polskich-samorzadow/"
            },
            {
                "hash0": "9bb03bb5af40d1202378f95a6485fba8"
            },
            {
                "hash1": "7d9a806e0da0b869b10870dd6c7692c5"
            },
            {
                "maltype": "apt"
            },
            {
                "filetype": "exe"
            }
        ],
        "raw_condition": "condition:\n    17 of them\n",
        "raw_meta": "meta:\n    author = \"Adam Ziaja <adam@adamziaja.com> http://adamziaja.com\"\n    date = \"2014-03-19\"\n    description = \"Bestia.3.02.012.07 malware used in APT attacks on Polish government\"\n    references = \"http://zaufanatrzeciastrona.pl/post/ukierunkowany-atak-na-pracownikow-polskich-samorzadow/\" /* PL */\n    hash0 = \"9bb03bb5af40d1202378f95a6485fba8\"\n    hash1 = \"7d9a806e0da0b869b10870dd6c7692c5\"\n    maltype = \"apt\"\n    filetype = \"exe\"\n",
        "raw_strings": "strings:\n    /* generated with https://github.com/Xen0ph0n/YaraGenerator */\n    $string0 = \"u4(UeK\"\n    $string1 = \"nMiq/''p\"\n    $string2 = \"_9pJMf\"\n    $string3 = \"ICMP.DLL\"\n    $string4 = \"EG}QAp\"\n    $string5 = \"tsjWj:U\"\n    $string6 = \"FileVersion\" wide\n    $string7 = \"O2nQpp\"\n    $string8 = \"2}W8we\"\n    $string9 = \"ILqkC:l\"\n    $string10 = \"f1yzMk\"\n    $string11 = \"AutoIt v3 Script: 3, 3, 8, 1\" wide\n    $string12 = \"wj<1uH\"\n    $string13 = \"6fL-uD\"\n    $string14 = \"B9Iavo<\"\n    $string15 = \"rUS)sO\"\n    $string16 = \"FJH{_/f\"\n    $string17 = \"3e 03V\"\n",
        "rule_name": "APT_bestia",
        "start_line": 4,
        "stop_line": 37,
        "strings": [
            {
                "name": "$string0",
                "type": "text",
                "value": "u4(UeK"
            },
            {
                "name": "$string1",
                "type": "text",
                "value": "nMiq/''p"
            },
            {
                "name": "$string2",
                "type": "text",
                "value": "_9pJMf"
            },
            {
                "name": "$string3",
                "type": "text",
                "value": "ICMP.DLL"
            },
            {
                "name": "$string4",
                "type": "text",
                "value": "EG}QAp"
            },
            {
                "name": "$string5",
                "type": "text",
                "value": "tsjWj:U"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$string6",
                "type": "text",
                "value": "FileVersion"
            },
            {
                "name": "$string7",
                "type": "text",
                "value": "O2nQpp"
            },
            {
                "name": "$string8",
                "type": "text",
                "value": "2}W8we"
            },
            {
                "name": "$string9",
                "type": "text",
                "value": "ILqkC:l"
            },
            {
                "name": "$string10",
                "type": "text",
                "value": "f1yzMk"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$string11",
                "type": "text",
                "value": "AutoIt v3 Script: 3, 3, 8, 1"
            },
            {
                "name": "$string12",
                "type": "text",
                "value": "wj<1uH"
            },
            {
                "name": "$string13",
                "type": "text",
                "value": "6fL-uD"
            },
            {
                "name": "$string14",
                "type": "text",
                "value": "B9Iavo<"
            },
            {
                "name": "$string15",
                "type": "text",
                "value": "rUS)sO"
            },
            {
                "name": "$string16",
                "type": "text",
                "value": "FJH{_/f"
            },
            {
                "name": "$string17",
                "type": "text",
                "value": "3e 03V"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Android_OmniRat', NULL, '{"date": "01-July-2016", "author": "Jacob Soo Lead Re", "source": "https://blog.avast.com/2015/11/05/droidjack-isnt-the-only-spying-software-out-there-avast-discovers-that-omnirat-is-currently-being-used-and-spread-by-criminals-to-gain-full-remote-co", "description": "This rule try to detects OmniRat"}', '[
    {
        "condition_terms": [
            "(",
            "androguard.activity",
            "(",
            "/com.app.MainActivity/i",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.WRITE_EXTERNAL_STORAGE/i",
            ")",
            "and",
            "androguard.package_name",
            "(",
            "/com.app/i",
            ")",
            ")",
            "and",
            "$a"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "Jacob Soo Lead Re"
            },
            {
                "date": "01-July-2016"
            },
            {
                "description": "This rule try to detects OmniRat"
            },
            {
                "source": "https://blog.avast.com/2015/11/05/droidjack-isnt-the-only-spying-software-out-there-avast-discovers-that-omnirat-is-currently-being-used-and-spread-by-criminals-to-gain-full-remote-co"
            }
        ],
        "raw_condition": "condition:\n\t\t(androguard.activity(/com.app.MainActivity/i) and \n\t\t androguard.permission(/android.permission.WRITE_EXTERNAL_STORAGE/i) and \n\t\t androguard.package_name(/com.app/i)) and $a\n",
        "raw_meta": "meta:\n\t\tauthor = \"Jacob Soo Lead Re\"\n\t\tdate = \"01-July-2016\"\n\t\tdescription = \"This rule try to detects OmniRat\"\n\t\tsource = \"https://blog.avast.com/2015/11/05/droidjack-isnt-the-only-spying-software-out-there-avast-discovers-that-omnirat-is-currently-being-used-and-spread-by-criminals-to-gain-full-remote-co\"\n\n\t",
        "raw_strings": "strings:\n\t\t$a = \"android.engine.apk\"\n\t",
        "rule_name": "Android_OmniRat",
        "start_line": 8,
        "stop_line": 22,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "android.engine.apk"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'screenlocker_acroware', NULL, '{"author": "Marc Rivero | @seifreed", "reference": "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/", "description": "Rule to detect Acroware ScreenLocker"}', '[
    {
        "condition_terms": [
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "filesize",
            "<",
            "2000KB",
            ")",
            "and",
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Rule to detect Acroware ScreenLocker"
            },
            {
                "author": "Marc Rivero | @seifreed"
            },
            {
                "reference": "https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/"
            }
        ],
        "raw_condition": "condition:\n      ( uint16(0) == 0x5a4d and filesize < 2000KB ) and all of them\n",
        "raw_meta": "meta:\n\n      description = \"Rule to detect Acroware ScreenLocker\"\n      author = \"Marc Rivero | @seifreed\"\n      reference = \"https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-august-31st-2018-devs-on-vacation/\"\n      \n   ",
        "raw_strings": "strings:\n\n      $s1 = \"C:\\\\Users\\\\patri\\\\Documents\\\\Visual Studio 2015\\\\Projects\\\\Advanced Ransi\\\\Advanced Ransi\\\\obj\\\\Debug\\\\Advanced Ransi.pdb\" fullword ascii\n      $s2 = \"All your Personal Data got encrypted and the decryption key is stored on a hidden\" fullword ascii\n      $s3 = \"alphaoil@mail2tor.com any try of removing this Ransomware will result in an instantly \" fullword ascii\n      $s4 = \"HKEY_CURRENT_USER\\\\SoftwareE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\" fullword wide\n      $s5 = \"webserver, after 72 hours the decryption key will get removed and your personal\" fullword ascii\n      \n   ",
        "rule_name": "screenlocker_acroware",
        "start_line": 1,
        "stop_line": 19,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "C:\\\\Users\\\\patri\\\\Documents\\\\Visual Studio 2015\\\\Projects\\\\Advanced Ransi\\\\Advanced Ransi\\\\obj\\\\Debug\\\\Advanced Ransi.pdb"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s2",
                "type": "text",
                "value": "All your Personal Data got encrypted and the decryption key is stored on a hidden"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s3",
                "type": "text",
                "value": "alphaoil@mail2tor.com any try of removing this Ransomware will result in an instantly "
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s4",
                "type": "text",
                "value": "HKEY_CURRENT_USER\\\\SoftwareE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s5",
                "type": "text",
                "value": "webserver, after 72 hours the decryption key will get removed and your personal"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'with_sqlite', '{sqlite}', '{"author": "Julian J. Gonzalez <info@seguridadparatodos.es>", "reference": "http://www.st2labs.com", "description": "Rule to detect the presence of SQLite data in raw image"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Julian J. Gonzalez <info@seguridadparatodos.es>"
            },
            {
                "reference": "http://www.st2labs.com"
            },
            {
                "description": "Rule to detect the presence of SQLite data in raw image"
            }
        ],
        "raw_condition": "condition:\n\t\tall of them\n",
        "raw_meta": "meta:\n\t\tauthor = \"Julian J. Gonzalez <info@seguridadparatodos.es>\"\n\t\treference = \"http://www.st2labs.com\"\n\t\tdescription = \"Rule to detect the presence of SQLite data in raw image\"\n\t",
        "raw_strings": "strings:\n\t\t$hex_string = {53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00}\n\t",
        "rule_name": "with_sqlite",
        "start_line": 5,
        "stop_line": 15,
        "strings": [
            {
                "name": "$hex_string",
                "type": "byte",
                "value": "{53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00}"
            }
        ],
        "tags": [
            "sqlite"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'backoff', NULL, '{"date": "2014-08-21", "author": "Brian Wallace @botnet_hunter", "description": "Identify Backoff", "author_email": "bwall@ballastsecurity.net"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Brian Wallace @botnet_hunter"
            },
            {
                "author_email": "bwall@ballastsecurity.net"
            },
            {
                "date": "2014-08-21"
            },
            {
                "description": "Identify Backoff"
            }
        ],
        "raw_condition": "condition:\n        all of them\n",
        "raw_meta": "meta:\n        author = \"Brian Wallace @botnet_hunter\"\n        author_email = \"bwall@ballastsecurity.net\"\n        date = \"2014-08-21\"\n        description = \"Identify Backoff\"\n\n    ",
        "raw_strings": "strings:\n        $s1 = \"&op=%d&id=%s&ui=%s&wv=%d&gr=%s&bv=%s\"\n        $s2 = \"%s @ %s\"\n        $s3 = \"Upload KeyLogs\"\n\n    ",
        "rule_name": "backoff",
        "start_line": 6,
        "stop_line": 22,
        "strings": [
            {
                "name": "$s1",
                "type": "text",
                "value": "&op=%d&id=%s&ui=%s&wv=%d&gr=%s&bv=%s"
            },
            {
                "name": "$s2",
                "type": "text",
                "value": "%s @ %s"
            },
            {
                "name": "$s3",
                "type": "text",
                "value": "Upload KeyLogs"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'XMRIG_Miner', NULL, '{"ref": "https://gist.github.com/GelosSnake/c2d4d6ef6f93ccb7d3afb5b1e26c7b4e"}', '[
    {
        "condition_terms": [
            "$a1"
        ],
        "metadata": [
            {
                "ref": "https://gist.github.com/GelosSnake/c2d4d6ef6f93ccb7d3afb5b1e26c7b4e"
            }
        ],
        "raw_condition": "condition:\n    $a1  \n",
        "raw_meta": "meta:\n  ref = \"https://gist.github.com/GelosSnake/c2d4d6ef6f93ccb7d3afb5b1e26c7b4e\"\n  ",
        "raw_strings": "strings:\n    $a1 = \"stratum+tcp\"\n    ",
        "rule_name": "XMRIG_Miner",
        "start_line": 1,
        "stop_line": 9,
        "strings": [
            {
                "name": "$a1",
                "type": "text",
                "value": "stratum+tcp"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'apt_all_JavaScript_ScanboxFramework_obfuscated', NULL, '{"ref": "https://www.fidelissecurity.com/TradeSecret"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "ref": "https://www.fidelissecurity.com/TradeSecret"
            }
        ],
        "raw_condition": "condition:\n\n                  all of them\n\n",
        "raw_meta": "meta:\n                    \n                    ref = \"https://www.fidelissecurity.com/TradeSecret\"\n\n                  ",
        "raw_strings": "strings:\n\n              $sa1 = /(var|new|return)\\s[_\\$]+\\s?/\n\n                  $sa2 = \"function\"\n\n                  $sa3 = \"toString\"\n\n                  $sa4 = \"toUpperCase\"\n\n                  $sa5 = \"arguments.length\"\n\n                  $sa6 = \"return\"\n\n                  $sa7 = \"while\"\n\n                  $sa8 = \"unescape(\"\n\n                  $sa9 = \"365*10*24*60*60*1000\"\n\n                  $sa10 = \">> 2\"\n\n                  $sa11 = \"& 3) << 4\"\n\n                  $sa12 = \"& 15) << 2\"\n\n                  $sa13 = \">> 6) | 192\"\n\n                  $sa14 = \"& 63) | 128\"\n\n                  $sa15 = \">> 12) | 224\"\n\n                  ",
        "rule_name": "apt_all_JavaScript_ScanboxFramework_obfuscated",
        "start_line": 7,
        "stop_line": 50,
        "strings": [
            {
                "name": "$sa1",
                "type": "regex",
                "value": "/(var|new|return)\\s[_\\$]+\\s?/"
            },
            {
                "name": "$sa2",
                "type": "text",
                "value": "function"
            },
            {
                "name": "$sa3",
                "type": "text",
                "value": "toString"
            },
            {
                "name": "$sa4",
                "type": "text",
                "value": "toUpperCase"
            },
            {
                "name": "$sa5",
                "type": "text",
                "value": "arguments.length"
            },
            {
                "name": "$sa6",
                "type": "text",
                "value": "return"
            },
            {
                "name": "$sa7",
                "type": "text",
                "value": "while"
            },
            {
                "name": "$sa8",
                "type": "text",
                "value": "unescape("
            },
            {
                "name": "$sa9",
                "type": "text",
                "value": "365*10*24*60*60*1000"
            },
            {
                "name": "$sa10",
                "type": "text",
                "value": ">> 2"
            },
            {
                "name": "$sa11",
                "type": "text",
                "value": "& 3) << 4"
            },
            {
                "name": "$sa12",
                "type": "text",
                "value": "& 15) << 2"
            },
            {
                "name": "$sa13",
                "type": "text",
                "value": ">> 6) | 192"
            },
            {
                "name": "$sa14",
                "type": "text",
                "value": "& 63) | 128"
            },
            {
                "name": "$sa15",
                "type": "text",
                "value": ">> 12) | 224"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'APT_Win_Pipcreat', NULL, '{"MD5": "f09d832bea93cf320986b53fce4b8397", "date": "2013-03", "author": "chort (@chort0)", "version": "1.0", "filetype": "pe,dll", "Reference": "http://www.cyberengineeringservices.com/login-exe-analysis-trojan-pipcreat/", "description": "APT backdoor Pipcreat"}', '[
    {
        "comments": [
            "// (incorrectly?) identified as Hupigon by many AV on VT "
        ],
        "condition_terms": [
            "$rut",
            "or",
            "(",
            "2",
            "of",
            "(",
            "$str*",
            ")",
            ")"
        ],
        "metadata": [
            {
                "author": "chort (@chort0)"
            },
            {
                "description": "APT backdoor Pipcreat"
            },
            {
                "filetype": "pe,dll"
            },
            {
                "date": "2013-03"
            },
            {
                "MD5": "f09d832bea93cf320986b53fce4b8397"
            },
            {
                "Reference": "http://www.cyberengineeringservices.com/login-exe-analysis-trojan-pipcreat/"
            },
            {
                "version": "1.0"
            }
        ],
        "raw_condition": "condition: \n    $rut or (2 of ($str*)) \n  ",
        "raw_meta": "meta: \n    author = \"chort (@chort0)\"\n    description = \"APT backdoor Pipcreat\"\n    filetype = \"pe,dll\" \n    date = \"2013-03\"\n    MD5 = \"f09d832bea93cf320986b53fce4b8397\" // (incorrectly?) identified as Hupigon by many AV on VT \n    Reference = \"http://www.cyberengineeringservices.com/login-exe-analysis-trojan-pipcreat/\"\n    version = \"1.0\"\n\n  ",
        "raw_strings": "strings: \n    $strA = \"pip creat failed\" wide fullword \n    $strB = \"CraatePipe\" ascii fullword \n    $strC = \"are you there? \" wide fullword \n    $strD = \"success kill process ok\" wide fullword \n    $strE = \"Vista|08|Win7\" wide fullword \n    $rut = \"are you there!@#$%^&*()_+\" ascii fullword \n    \n  ",
        "rule_name": "APT_Win_Pipcreat",
        "start_line": 6,
        "stop_line": 28,
        "strings": [
            {
                "modifiers": [
                    "wide",
                    "fullword"
                ],
                "name": "$strA",
                "type": "text",
                "value": "pip creat failed"
            },
            {
                "modifiers": [
                    "ascii",
                    "fullword"
                ],
                "name": "$strB",
                "type": "text",
                "value": "CraatePipe"
            },
            {
                "modifiers": [
                    "wide",
                    "fullword"
                ],
                "name": "$strC",
                "type": "text",
                "value": "are you there? "
            },
            {
                "modifiers": [
                    "wide",
                    "fullword"
                ],
                "name": "$strD",
                "type": "text",
                "value": "success kill process ok"
            },
            {
                "modifiers": [
                    "wide",
                    "fullword"
                ],
                "name": "$strE",
                "type": "text",
                "value": "Vista|08|Win7"
            },
            {
                "modifiers": [
                    "ascii",
                    "fullword"
                ],
                "name": "$rut",
                "type": "text",
                "value": "are you there!@#$%^&*()_+"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'korlia', NULL, '{"author": "Nick Hoffman", "company": "Morphick", "reference": "http://www.morphick.com/resources/lab-blog/curious-korlia", "information": "korlia malware found in apt dump"}', '[
    {
        "comments": [
            "//7C EE jl short loc_404F1C ",
            "//3B C1 cmp eax, ecx ",
            "//40 inc eax ",
            "//8B 4C 24 14 mov ecx, [esp+0D78h+var_D64]",
            "//88 0C 28 mov [eax+ebp], cl ",
            "//80 F1 28 xor cl, 28h ",
            "//8A 0C 28 mov cl, [eax+ebp] ",
            "//case c (not a variant of the above loop) ",
            "//72 DE jb short loc_4047F2 ",
            "//3B D1 cmp edx, ecx ",
            "//49 dec ecx ",
            "//F7 D1 not ecx ",
            "//F2 AE repne scasb ",
            "//42 inc edx ",
            "//83 C9 FF or ecx, 0FFFFFFFFh ",
            "//88 8A 28 50 40 00 mov byte_405028[edx], cl",
            "//33 C0 xor eax, eax ",
            "//32 CB xor cl, bl ",
            "//BF 28 50 40 00 mov edi, offset byte_405028 ",
            "//8A 8A 28 50 40 00 mov cl, byte_405028[edx] ",
            "//case b (variant of loop a) ",
            "//72 DE jb short loc_71001DE0",
            "//3B F1 cmp esi, ecx ",
            "//49 dec ecx ",
            "//F7 D1 not ecx ",
            "//F2 AE repne scasb ",
            "//46 inc esi ",
            "//33 C0 xor eax, eax ",
            "//88 86 98 40 00 71 mov byte ptr url[esi], al ",
            "//83 C9 FF or ecx, 0FFFFFFFFh ",
            "//32 C2 xor al, dl ",
            "//BF 98 40 00 71 mov edi, offset url ",
            "//8A 86 98 40 00 71 mov al, byte ptr url[esi]",
            "// ----------------- ",
            "//b2 1f mov dl, 0x1f ; mov key (wildcard) ",
            "//case a"
        ],
        "condition_terms": [
            "any",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Nick Hoffman"
            },
            {
                "company": "Morphick"
            },
            {
                "reference": "http://www.morphick.com/resources/lab-blog/curious-korlia"
            },
            {
                "information": "korlia malware found in apt dump"
            }
        ],
        "raw_condition": "condition:\nany of them \n",
        "raw_meta": "meta:\nauthor = \"Nick Hoffman\" \ncompany = \"Morphick\"\nreference = \"http://www.morphick.com/resources/lab-blog/curious-korlia\"\ninformation = \"korlia malware found in apt dump\" \n\n//case a\n//b2 1f mov dl, 0x1f ; mov key (wildcard) \n// ----------------- \n//8A 86 98 40 00 71 mov al, byte ptr url[esi]\n//BF 98 40 00 71 mov edi, offset url \n//32 C2 xor al, dl \n//83 C9 FF or ecx, 0FFFFFFFFh \n//88 86 98 40 00 71 mov byte ptr url[esi], al \n//33 C0 xor eax, eax \n//46 inc esi \n//F2 AE repne scasb \n//F7 D1 not ecx \n//49 dec ecx \n//3B F1 cmp esi, ecx \n//72 DE jb short loc_71001DE0\n\n//case b (variant of loop a) \n//8A 8A 28 50 40 00 mov cl, byte_405028[edx] \n//BF 28 50 40 00 mov edi, offset byte_405028 \n//32 CB xor cl, bl \n//33 C0 xor eax, eax \n//88 8A 28 50 40 00 mov byte_405028[edx], cl\n//83 C9 FF or ecx, 0FFFFFFFFh \n//42 inc edx \n//F2 AE repne scasb \n//F7 D1 not ecx \n//49 dec ecx \n//3B D1 cmp edx, ecx \n//72 DE jb short loc_4047F2 \n\n//case c (not a variant of the above loop) \n//8A 0C 28 mov cl, [eax+ebp] \n//80 F1 28 xor cl, 28h \n//88 0C 28 mov [eax+ebp], cl \n//8B 4C 24 14 mov ecx, [esp+0D78h+var_D64]\n//40 inc eax \n//3B C1 cmp eax, ecx \n//7C EE jl short loc_404F1C \n\n",
        "raw_strings": "strings:\n$a = {b2 ?? 8A 86 98 40 00 71 BF 98 40 00 71 32 c2 83 C9 FF 88 86 98 40 00 71 33 C0 46 F2 AE F7 D1 49 3B F1} \n$b = {B3 ?? ?? ?? 8A 8A 28 50 40 00 BF 28 50 40 00 32 CB 33 C0 88 8A 28 50 40 00 83 C9 FF 42 F2 AE F7 D1 49 3B D1} \n$c = {8A 0C 28 80 F1 ?? 88 0C 28 8B 4C 24 14 40 3B C1} \n$d = {00 62 69 73 6F 6E 61 6C 00} //config marker \"\\x00bisonal\\x00\"\n",
        "rule_name": "korlia",
        "start_line": 6,
        "stop_line": 60,
        "strings": [
            {
                "name": "$a",
                "type": "byte",
                "value": "{b2 ?? 8A 86 98 40 00 71 BF 98 40 00 71 32 c2 83 C9 FF 88 86 98 40 00 71 33 C0 46 F2 AE F7 D1 49 3B F1}"
            },
            {
                "name": "$b",
                "type": "byte",
                "value": "{B3 ?? ?? ?? 8A 8A 28 50 40 00 BF 28 50 40 00 32 CB 33 C0 88 8A 28 50 40 00 83 C9 FF 42 F2 AE F7 D1 49 3B D1}"
            },
            {
                "name": "$c",
                "type": "byte",
                "value": "{8A 0C 28 80 F1 ?? 88 0C 28 8B 4C 24 14 40 3B C1}"
            },
            {
                "name": "$d",
                "type": "byte",
                "value": "{00 62 69 73 6F 6E 61 6C 00}"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Grozlex', '{Stealer}', '{"date": "20/08/2013", "author": "Kevin Falcoz", "description": "Grozlex Stealer - Possible HCStealer"}', '[
    {
        "condition_terms": [
            "$signature"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "Kevin Falcoz"
            },
            {
                "date": "20/08/2013"
            },
            {
                "description": "Grozlex Stealer - Possible HCStealer"
            }
        ],
        "raw_condition": "condition:\n\t\t$signature\n",
        "raw_meta": "meta:\n\t\tauthor=\"Kevin Falcoz\"\n\t\tdate=\"20/08/2013\"\n\t\tdescription=\"Grozlex Stealer - Possible HCStealer\"\n\t\t\n\t",
        "raw_strings": "strings:\n\t\t$signature={4C 00 6F 00 67 00 73 00 20 00 61 00 74 00 74 00 61 00 63 00 68 00 65 00 64 00 20 00 62 00 79 00 20 00 69 00 43 00 6F 00 7A 00 65 00 6E}\n\t\n\t",
        "rule_name": "Grozlex",
        "start_line": 8,
        "stop_line": 20,
        "strings": [
            {
                "name": "$signature",
                "type": "byte",
                "value": "{4C 00 6F 00 67 00 73 00 20 00 61 00 74 00 74 00 61 00 63 00 68 00 65 00 64 00 20 00 62 00 79 00 20 00 69 00 43 00 6F 00 7A 00 65 00 6E}"
            }
        ],
        "tags": [
            "Stealer"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Cythosia', NULL, '{"date": "2015-03-21", "author": "Brian Wallace @botnet_hunter", "description": "Identify Cythosia", "author_email": "bwall@ballastsecurity.net"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Brian Wallace @botnet_hunter"
            },
            {
                "author_email": "bwall@ballastsecurity.net"
            },
            {
                "date": "2015-03-21"
            },
            {
                "description": "Identify Cythosia"
            }
        ],
        "raw_condition": "condition:\n        all of them\n",
        "raw_meta": "meta:\n        author = \"Brian Wallace @botnet_hunter\"\n        author_email = \"bwall@ballastsecurity.net\"\n        date = \"2015-03-21\"\n        description = \"Identify Cythosia\"\n\n    ",
        "raw_strings": "strings:\n        $str1 = \"HarvesterSocksBot.Properties.Resources\" wide\n\n    ",
        "rule_name": "Cythosia",
        "start_line": 6,
        "stop_line": 20,
        "strings": [
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str1",
                "type": "text",
                "value": "HarvesterSocksBot.Properties.Resources"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'apt_win32_dll_rat_hiZor_RAT', '{RAT}', '{"ref1": "http://www.threatgeek.com/2016/01/introducing-hi-zor-rat.html", "ref2": "https://github.com/Neo23x0/Loki/blob/b187ed063d73d0defc6958100ca7ad04aa77fc12/signatures/apt_hizor_rat.yar", "hash1": "75d3d1f23628122a64a2f1b7ef33f5cf", "hash2": "d9821468315ccd3b9ea03161566ef18e", "hash3": "b9af5f5fd434a65d7aa1b55f5441c90a", "reference": "https://www.fidelissecurity.com/sites/default/files/FTA_1020_Fidelis_Inocnation_FINAL.pdf", "description": "Detects hiZor RAT"}', '[
    {
        "comments": [
            "// Part of the encoded User-Agent = Mozilla"
        ],
        "condition_terms": [
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5A4D",
            "or",
            "uint32",
            "(",
            "0",
            ")",
            "==",
            "0x4464c457f",
            ")",
            "and",
            "(",
            "all",
            "of",
            "them",
            ")"
        ],
        "metadata": [
            {
                "description": "Detects hiZor RAT"
            },
            {
                "hash1": "75d3d1f23628122a64a2f1b7ef33f5cf"
            },
            {
                "hash2": "d9821468315ccd3b9ea03161566ef18e"
            },
            {
                "hash3": "b9af5f5fd434a65d7aa1b55f5441c90a"
            },
            {
                "ref1": "http://www.threatgeek.com/2016/01/introducing-hi-zor-rat.html"
            },
            {
                "ref2": "https://github.com/Neo23x0/Loki/blob/b187ed063d73d0defc6958100ca7ad04aa77fc12/signatures/apt_hizor_rat.yar"
            },
            {
                "reference": "https://www.fidelissecurity.com/sites/default/files/FTA_1020_Fidelis_Inocnation_FINAL.pdf"
            }
        ],
        "raw_condition": "condition:\n\t\t(uint16(0) == 0x5A4D or uint32(0) == 0x4464c457f) and (all of them)\n",
        "raw_meta": "meta:\n    description = \"Detects hiZor RAT\"\n\t\thash1 = \"75d3d1f23628122a64a2f1b7ef33f5cf\"\n\t\thash2 = \"d9821468315ccd3b9ea03161566ef18e\"\n\t\thash3 = \"b9af5f5fd434a65d7aa1b55f5441c90a\"\n    ref1 = \"http://www.threatgeek.com/2016/01/introducing-hi-zor-rat.html\"\n    ref2 = \"https://github.com/Neo23x0/Loki/blob/b187ed063d73d0defc6958100ca7ad04aa77fc12/signatures/apt_hizor_rat.yar\"\n    reference = \"https://www.fidelissecurity.com/sites/default/files/FTA_1020_Fidelis_Inocnation_FINAL.pdf\"\n\t",
        "raw_strings": "strings:\n\t\t// Part of the encoded User-Agent = Mozilla\n\t\t$s1 = { c7 [5] 40 00 62 00 c7 [5] 77 00 64 00 c7 [5] 61 00 61 00 c7 [5] 6c 00 }\n\n\t\t// XOR to decode User-Agent after string stacking 0x10001630\n\t\t$s2 = { 66 [7] 0d 40 83 ?? ?? 7c ?? }\n\n\t\t// XOR with 0x2E - 0x10002EF6\n\t\t$s3 = { 80 [2] 2e 40 3b ?? 72 ?? }\n\n\t\t$s4 = \"CmdProcessExited\" wide ascii\n\t\t$s5 = \"rootDir\" wide ascii\n\t\t$s6 = \"DllRegisterServer\" wide ascii\n\t\t$s7 = \"GetNativeSystemInfo\" wide ascii\n\t\t$s8 = \"%08x%08x%08x%08x\" wide ascii\n\t",
        "rule_name": "apt_win32_dll_rat_hiZor_RAT",
        "start_line": 5,
        "stop_line": 32,
        "strings": [
            {
                "name": "$s1",
                "type": "byte",
                "value": "{ c7 [5] 40 00 62 00 c7 [5] 77 00 64 00 c7 [5] 61 00 61 00 c7 [5] 6c 00 }"
            },
            {
                "name": "$s2",
                "type": "byte",
                "value": "{ 66 [7] 0d 40 83 ?? ?? 7c ?? }"
            },
            {
                "name": "$s3",
                "type": "byte",
                "value": "{ 80 [2] 2e 40 3b ?? 72 ?? }"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s4",
                "type": "text",
                "value": "CmdProcessExited"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s5",
                "type": "text",
                "value": "rootDir"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s6",
                "type": "text",
                "value": "DllRegisterServer"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s7",
                "type": "text",
                "value": "GetNativeSystemInfo"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$s8",
                "type": "text",
                "value": "%08x%08x%08x%08x"
            }
        ],
        "tags": [
            "RAT"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'onimiki', NULL, '{"author": "Olivier Bilodeau <bilodeau@eset.com>", "source": "https://github.com/eset/malware-ioc/", "contact": "windigo@eset.sk", "created": "2014-02-06", "license": "BSD 2-Clause", "malware": "Linux/Onimiki", "operation": "Windigo", "reference": "http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf", "description": "Linux/Onimiki malicious DNS server"}', '[
    {
        "comments": [
            "// code from offset: 0x46CBCD"
        ],
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Linux/Onimiki malicious DNS server"
            },
            {
                "malware": "Linux/Onimiki"
            },
            {
                "operation": "Windigo"
            },
            {
                "author": "Olivier Bilodeau <bilodeau@eset.com>"
            },
            {
                "created": "2014-02-06"
            },
            {
                "reference": "http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf"
            },
            {
                "contact": "windigo@eset.sk"
            },
            {
                "source": "https://github.com/eset/malware-ioc/"
            },
            {
                "license": "BSD 2-Clause"
            }
        ],
        "raw_condition": "condition:\n    all of them\n",
        "raw_meta": "meta:\n    description = \"Linux/Onimiki malicious DNS server\"\n    malware = \"Linux/Onimiki\"\n    operation = \"Windigo\"\n    author = \"Olivier Bilodeau <bilodeau@eset.com>\"\n    created = \"2014-02-06\"\n    reference = \"http://www.welivesecurity.com/wp-content/uploads/2014/03/operation_windigo.pdf\"\n    contact = \"windigo@eset.sk\"\n    source = \"https://github.com/eset/malware-ioc/\"\n    license = \"BSD 2-Clause\"\n\n  ",
        "raw_strings": "strings:\n    // code from offset: 0x46CBCD\n    $a1 = {43 0F B6 74 2A 0E 43 0F  B6 0C 2A 8D 7C 3D 00 8D}\n    $a2 = {74 35 00 8D 4C 0D 00 89  F8 41 F7 E3 89 F8 29 D0}\n    $a3 = {D1 E8 01 C2 89 F0 C1 EA  04 44 8D 0C 92 46 8D 0C}\n    $a4 = {8A 41 F7 E3 89 F0 44 29  CF 29 D0 D1 E8 01 C2 89}\n    $a5 = {C8 C1 EA 04 44 8D 04 92  46 8D 04 82 41 F7 E3 89}\n    $a6 = {C8 44 29 C6 29 D0 D1 E8  01 C2 C1 EA 04 8D 04 92}\n    $a7 = {8D 04 82 29 C1 42 0F B6  04 21 42 88 84 14 C0 01}\n    $a8 = {00 00 42 0F B6 04 27 43  88 04 32 42 0F B6 04 26}\n    $a9 = {42 88 84 14 A0 01 00 00  49 83 C2 01 49 83 FA 07}\n\n  ",
        "rule_name": "onimiki",
        "start_line": 37,
        "stop_line": 65,
        "strings": [
            {
                "name": "$a1",
                "type": "byte",
                "value": "{43 0F B6 74 2A 0E 43 0F  B6 0C 2A 8D 7C 3D 00 8D}"
            },
            {
                "name": "$a2",
                "type": "byte",
                "value": "{74 35 00 8D 4C 0D 00 89  F8 41 F7 E3 89 F8 29 D0}"
            },
            {
                "name": "$a3",
                "type": "byte",
                "value": "{D1 E8 01 C2 89 F0 C1 EA  04 44 8D 0C 92 46 8D 0C}"
            },
            {
                "name": "$a4",
                "type": "byte",
                "value": "{8A 41 F7 E3 89 F0 44 29  CF 29 D0 D1 E8 01 C2 89}"
            },
            {
                "name": "$a5",
                "type": "byte",
                "value": "{C8 C1 EA 04 44 8D 04 92  46 8D 04 82 41 F7 E3 89}"
            },
            {
                "name": "$a6",
                "type": "byte",
                "value": "{C8 44 29 C6 29 D0 D1 E8  01 C2 C1 EA 04 8D 04 92}"
            },
            {
                "name": "$a7",
                "type": "byte",
                "value": "{8D 04 82 29 C1 42 0F B6  04 21 42 88 84 14 C0 01}"
            },
            {
                "name": "$a8",
                "type": "byte",
                "value": "{00 00 42 0F B6 04 27 43  88 04 32 42 0F B6 04 26}"
            },
            {
                "name": "$a9",
                "type": "byte",
                "value": "{42 88 84 14 A0 01 00 00  49 83 C2 01 49 83 FA 07}"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'IceID_Bank_trojan', NULL, '{"org": "MalwareMustDie", "date": "2018-01-14", "author": "unixfreaxjp", "description": "Detects IcedID..adjusted several times"}', '[
    {
        "condition_terms": [
            "$header",
            "at",
            "0",
            "and",
            "all",
            "of",
            "(",
            "$magic*",
            ")",
            "and",
            "6",
            "of",
            "(",
            "$st0*",
            ")",
            "and",
            "pe.sections",
            "[",
            "0",
            "]",
            ".",
            "name",
            "contains",
            "\".text\"",
            "and",
            "pe.sections",
            "[",
            "1",
            "]",
            ".",
            "name",
            "contains",
            "\".rdata\"",
            "and",
            "pe.sections",
            "[",
            "2",
            "]",
            ".",
            "name",
            "contains",
            "\".data\"",
            "and",
            "pe.sections",
            "[",
            "3",
            "]",
            ".",
            "name",
            "contains",
            "\".rsrc\"",
            "and",
            "pe.characteristics",
            "&",
            "pe.EXECUTABLE_IMAGE",
            "and",
            "pe.characteristics",
            "&",
            "pe.RELOCS_STRIPPED"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "description": "Detects IcedID..adjusted several times"
            },
            {
                "author": "unixfreaxjp"
            },
            {
                "org": "MalwareMustDie"
            },
            {
                "date": "2018-01-14"
            }
        ],
        "raw_condition": "condition:\n\t\t$header at 0 and all of ($magic*) and 6 of ($st0*)\n\t\tand pe.sections[0].name contains \".text\"\n\t\tand pe.sections[1].name contains \".rdata\"\n\t\tand pe.sections[2].name contains \".data\"\n\t\tand pe.sections[3].name contains \".rsrc\"\n\t\tand pe.characteristics & pe.EXECUTABLE_IMAGE\n\t\tand pe.characteristics & pe.RELOCS_STRIPPED\n",
        "raw_meta": "meta:\n\t\tdescription = \"Detects IcedID..adjusted several times\"\n\t\tauthor = \"unixfreaxjp\"\n\t\torg = \"MalwareMustDie\"\n\t\tdate = \"2018-01-14\"\n    \n\t",
        "raw_strings": "strings:\n\t\t$header = { 4D 5A }\n\t\t$magic1 = { E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A ?? 68 ?? ?? }\n\t\t$st01 = \"CCmdTarget\" fullword nocase wide ascii\n\t\t$st02 = \"CUserException\" fullword nocase wide ascii\n\t\t$st03 = \"FileType\" fullword nocase wide ascii\n\t\t$st04 = \"FlsGetValue\" fullword nocase wide ascii\n\t\t$st05 = \"AVCShellWrapper@@\" fullword nocase wide ascii\n\t\t$st06 = \"AVCCmdTarget@@\" fullword nocase wide ascii\n\t\t$st07 = \"AUCThreadData@@\" fullword nocase wide ascii\n\t\t$st08 = \"AVCUserException@@\" fullword nocase wide ascii\n\n\t",
        "rule_name": "IceID_Bank_trojan",
        "start_line": 8,
        "stop_line": 36,
        "strings": [
            {
                "name": "$header",
                "type": "byte",
                "value": "{ 4D 5A }"
            },
            {
                "name": "$magic1",
                "type": "byte",
                "value": "{ E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A ?? 68 ?? ?? }"
            },
            {
                "modifiers": [
                    "fullword",
                    "nocase",
                    "wide",
                    "ascii"
                ],
                "name": "$st01",
                "type": "text",
                "value": "CCmdTarget"
            },
            {
                "modifiers": [
                    "fullword",
                    "nocase",
                    "wide",
                    "ascii"
                ],
                "name": "$st02",
                "type": "text",
                "value": "CUserException"
            },
            {
                "modifiers": [
                    "fullword",
                    "nocase",
                    "wide",
                    "ascii"
                ],
                "name": "$st03",
                "type": "text",
                "value": "FileType"
            },
            {
                "modifiers": [
                    "fullword",
                    "nocase",
                    "wide",
                    "ascii"
                ],
                "name": "$st04",
                "type": "text",
                "value": "FlsGetValue"
            },
            {
                "modifiers": [
                    "fullword",
                    "nocase",
                    "wide",
                    "ascii"
                ],
                "name": "$st05",
                "type": "text",
                "value": "AVCShellWrapper@@"
            },
            {
                "modifiers": [
                    "fullword",
                    "nocase",
                    "wide",
                    "ascii"
                ],
                "name": "$st06",
                "type": "text",
                "value": "AVCCmdTarget@@"
            },
            {
                "modifiers": [
                    "fullword",
                    "nocase",
                    "wide",
                    "ascii"
                ],
                "name": "$st07",
                "type": "text",
                "value": "AUCThreadData@@"
            },
            {
                "modifiers": [
                    "fullword",
                    "nocase",
                    "wide",
                    "ascii"
                ],
                "name": "$st08",
                "type": "text",
                "value": "AVCUserException@@"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Bublik', NULL, '{"date": "29/09/2013", "author": "Kevin Falcoz", "description": "Bublik Trojan Downloader"}', '[
    {
        "condition_terms": [
            "$signature1",
            "and",
            "$signature2"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "Kevin Falcoz"
            },
            {
                "date": "29/09/2013"
            },
            {
                "description": "Bublik Trojan Downloader"
            }
        ],
        "raw_condition": "condition:\n        $signature1 and $signature2\n",
        "raw_meta": "meta:\n        author=\"Kevin Falcoz\"\n        date=\"29/09/2013\"\n        description=\"Bublik Trojan Downloader\"\n        \n    ",
        "raw_strings": "strings:\n        $signature1={63 6F 6E 73 6F 6C 61 73}\n        $signature2={63 6C 55 6E 00 69 6E 66 6F 2E 69 6E 69}\n        \n    ",
        "rule_name": "Bublik",
        "start_line": 8,
        "stop_line": 22,
        "strings": [
            {
                "name": "$signature1",
                "type": "byte",
                "value": "{63 6F 6E 73 6F 6C 61 73}"
            },
            {
                "name": "$signature2",
                "type": "byte",
                "value": "{63 6C 55 6E 00 69 6E 66 6F 2E 69 6E 69}"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'LuckyCatCode', '{LuckyCat,Family}', '{"author": "Seth Hardy", "description": "LuckyCat code tricks", "last_modified": "2014-06-19"}', '[
    {
        "condition_terms": [
            "$xordecrypt",
            "or",
            "(",
            "$dll",
            "and",
            "$commonletters",
            ")"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "description": "LuckyCat code tricks"
            },
            {
                "author": "Seth Hardy"
            },
            {
                "last_modified": "2014-06-19"
            }
        ],
        "raw_condition": "condition:\n        $xordecrypt or ($dll and $commonletters)\n",
        "raw_meta": "meta:\n        description = \"LuckyCat code tricks\"\n        author = \"Seth Hardy\"\n        last_modified = \"2014-06-19\"\n        \n    ",
        "raw_strings": "strings:\n        $xordecrypt = { BF 0F 00 00 00 F7 F7 ?? ?? ?? ?? 32 14 39 80 F2 7B }\n        $dll = { C6 ?? ?? ?? 64 C6 ?? ?? ?? 6C C6 ?? ?? ?? 6C }\n        $commonletters = { B? 63 B? 61 B? 73 B? 65 }\n        \n    ",
        "rule_name": "LuckyCatCode",
        "start_line": 8,
        "stop_line": 22,
        "strings": [
            {
                "name": "$xordecrypt",
                "type": "byte",
                "value": "{ BF 0F 00 00 00 F7 F7 ?? ?? ?? ?? 32 14 39 80 F2 7B }"
            },
            {
                "name": "$dll",
                "type": "byte",
                "value": "{ C6 ?? ?? ?? 64 C6 ?? ?? ?? 6C C6 ?? ?? ?? 6C }"
            },
            {
                "name": "$commonletters",
                "type": "byte",
                "value": "{ B? 63 B? 61 B? 73 B? 65 }"
            }
        ],
        "tags": [
            "LuckyCat",
            "Family"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'custom_ssh_backdoor_server', NULL, '{"date": "2015-05-14", "hash": "0953b6c2181249b94282ca5736471f85d80d41c9", "author": "Florian Roth", "reference": "https://goo.gl/S46L3o", "description": "Custome SSH backdoor based on python and paramiko - file server.py"}', '[
    {
        "condition_terms": [
            "filesize",
            "<",
            "10KB",
            "and",
            "5",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Custome SSH backdoor based on python and paramiko - file server.py"
            },
            {
                "author": "Florian Roth"
            },
            {
                "reference": "https://goo.gl/S46L3o"
            },
            {
                "date": "2015-05-14"
            },
            {
                "hash": "0953b6c2181249b94282ca5736471f85d80d41c9"
            }
        ],
        "raw_condition": "condition:\n        filesize < 10KB and 5 of them\n",
        "raw_meta": "meta:\n        description = \"Custome SSH backdoor based on python and paramiko - file server.py\"\n        author = \"Florian Roth\"\n        reference = \"https://goo.gl/S46L3o\"\n        date = \"2015-05-14\"\n        hash = \"0953b6c2181249b94282ca5736471f85d80d41c9\"\n\n    ",
        "raw_strings": "strings:\n        $s0 = \"command= raw_input(\\\"Enter command: \\\").strip(''n'')\" fullword ascii\n        $s1 = \"print ''[-] (Failed to load moduli -- gex will be unsupported.)''\" fullword ascii\n        $s2 = \"print ''[-] Listen/bind/accept failed: '' + str(e)\" fullword ascii\n        $s3 = \"chan.send(command)\" fullword ascii\n        $s4 = \"print ''[-] SSH negotiation failed.''\" fullword ascii\n        $s5 = \"except paramiko.SSHException, x:\" fullword ascii\n\n    ",
        "rule_name": "custom_ssh_backdoor_server",
        "start_line": 6,
        "stop_line": 26,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s0",
                "type": "text",
                "value": "command= raw_input(\\\"Enter command: \\\").strip(''n'')"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "print ''[-] (Failed to load moduli -- gex will be unsupported.)''"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s2",
                "type": "text",
                "value": "print ''[-] Listen/bind/accept failed: '' + str(e)"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s3",
                "type": "text",
                "value": "chan.send(command)"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s4",
                "type": "text",
                "value": "print ''[-] SSH negotiation failed.''"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s5",
                "type": "text",
                "value": "except paramiko.SSHException, x:"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'marap', NULL, '{"date": "2018-08-19", "author": " J from THL <j@techhelplist.com>", "maltype": "Downloader", "version": 1, "filetype": "memory", "reference1": "https://www.virustotal.com/#/file/61dfc4d535d86359c2f09dbdd8f14c0a2e6367e5bb7377812f323a94d32341ba/detection", "reference2": "https://www.virustotal.com/#/file/c0c85f93a4f425a23c2659dce11e3b1c8b9353b566751b32fcb76b3d8b723b94/detection", "reference3": "https://threatpost.com/highly-flexible-marap-malware-enters-the-financial-scene/136623/", "reference4": "https://www.bleepingcomputer.com/news/security/necurs-botnet-pushing-new-marap-malware/"}', '[
    {
        "condition_terms": [
            "7",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": " J from THL <j@techhelplist.com>"
            },
            {
                "date": "2018-08-19"
            },
            {
                "reference1": "https://www.virustotal.com/#/file/61dfc4d535d86359c2f09dbdd8f14c0a2e6367e5bb7377812f323a94d32341ba/detection"
            },
            {
                "reference2": "https://www.virustotal.com/#/file/c0c85f93a4f425a23c2659dce11e3b1c8b9353b566751b32fcb76b3d8b723b94/detection"
            },
            {
                "reference3": "https://threatpost.com/highly-flexible-marap-malware-enters-the-financial-scene/136623/"
            },
            {
                "reference4": "https://www.bleepingcomputer.com/news/security/necurs-botnet-pushing-new-marap-malware/"
            },
            {
                "version": 1
            },
            {
                "maltype": "Downloader"
            },
            {
                "filetype": "memory"
            }
        ],
        "raw_condition": "condition:\n        7 of them\n",
        "raw_meta": "meta:\n        author = \" J from THL <j@techhelplist.com>\"\n        date = \"2018-08-19\"\n        reference1 = \"https://www.virustotal.com/#/file/61dfc4d535d86359c2f09dbdd8f14c0a2e6367e5bb7377812f323a94d32341ba/detection\"\n        reference2 = \"https://www.virustotal.com/#/file/c0c85f93a4f425a23c2659dce11e3b1c8b9353b566751b32fcb76b3d8b723b94/detection\"\n        reference3 = \"https://threatpost.com/highly-flexible-marap-malware-enters-the-financial-scene/136623/\"\n        reference4 = \"https://www.bleepingcomputer.com/news/security/necurs-botnet-pushing-new-marap-malware/\"\n        version = 1\n        maltype = \"Downloader\"\n        filetype = \"memory\"\n\n    ",
        "raw_strings": "strings:\n        $text01 = \"%02X-%02X-%02X-%02X-%02X-%02X\" wide\n        $text02 = \"%s, base=0x%p\" wide\n        $text03 = \"pid=%d\" wide\n        $text04 = \"%s %s\" wide\n        $text05 = \"%d|%d|%s|%s|%s\" wide\n        $text06 = \"%s|1|%d|%d|%d|%d|%d|%s\" wide\n        $text07 = \"%d#%s#%s#%s#%d#%s#%s#%d#%s#%s#%s#%s#%d\" wide\n        $text08 = \"%s|1|%d|%d|%d|%d|%d|%s#%s#%s#%s#%d#%d#%d\" wide\n        $text09 = \"%s|0|%d\" wide\n        $text10 = \"%llx\" wide\n        $text11 = \"%s -a\" wide\n\n    ",
        "rule_name": "marap",
        "start_line": 1,
        "stop_line": 30,
        "strings": [
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$text01",
                "type": "text",
                "value": "%02X-%02X-%02X-%02X-%02X-%02X"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$text02",
                "type": "text",
                "value": "%s, base=0x%p"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$text03",
                "type": "text",
                "value": "pid=%d"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$text04",
                "type": "text",
                "value": "%s %s"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$text05",
                "type": "text",
                "value": "%d|%d|%s|%s|%s"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$text06",
                "type": "text",
                "value": "%s|1|%d|%d|%d|%d|%d|%s"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$text07",
                "type": "text",
                "value": "%d#%s#%s#%s#%d#%s#%s#%d#%s#%s#%s#%s#%d"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$text08",
                "type": "text",
                "value": "%s|1|%d|%d|%d|%d|%d|%s#%s#%s#%s#%d#%d#%d"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$text09",
                "type": "text",
                "value": "%s|0|%d"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$text10",
                "type": "text",
                "value": "%llx"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$text11",
                "type": "text",
                "value": "%s -a"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Bolonyokte', '{rat}', '{"date": "2013-02-01", "author": "Jean-Philippe Teissier / @Jipe_", "version": "1.0", "filetype": "memory", "description": "UnknownDotNet RAT - Bolonyokte"}', '[
    {
        "condition_terms": [
            "any",
            "of",
            "(",
            "$campaign*",
            ")",
            "or",
            "2",
            "of",
            "(",
            "$decoy*",
            ")",
            "or",
            "2",
            "of",
            "(",
            "$artifact*",
            ")",
            "or",
            "all",
            "of",
            "(",
            "$func*",
            ")",
            "or",
            "3",
            "of",
            "(",
            "$ebanking*",
            ")"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "description": "UnknownDotNet RAT - Bolonyokte"
            },
            {
                "author": "Jean-Philippe Teissier / @Jipe_"
            },
            {
                "date": "2013-02-01"
            },
            {
                "filetype": "memory"
            },
            {
                "version": "1.0"
            }
        ],
        "raw_condition": "condition:\n\t\tany of ($campaign*) or 2 of ($decoy*) or 2 of ($artifact*) or all of ($func*) or 3 of ($ebanking*)\n",
        "raw_meta": "meta:\n\t\tdescription = \"UnknownDotNet RAT - Bolonyokte\"\n\t\tauthor = \"Jean-Philippe Teissier / @Jipe_\"\n\t\tdate = \"2013-02-01\"\n\t\tfiletype = \"memory\"\n\t\tversion = \"1.0\" \n\n\t",
        "raw_strings": "strings:\n\t\t$campaign1 = \"Bolonyokte\" ascii wide\n\t\t$campaign2 = \"donadoni\" ascii wide\n\t\t\n\t\t$decoy1 = \"nyse.com\" ascii wide\n\t\t$decoy2 = \"NYSEArca_Listing_Fees.pdf\" ascii wide\n\t\t$decoy3 = \"bf13-5d45cb40\" ascii wide\n\t\t\n\t\t$artifact1 = \"Backup.zip\"  ascii wide\n\t\t$artifact2 = \"updates.txt\" ascii wide\n\t\t$artifact3 = \"vdirs.dat\" ascii wide\n\t\t$artifact4 = \"default.dat\"\n\t\t$artifact5 = \"index.html\"\n\t\t$artifact6 = \"mime.dat\"\n\t\t\n\t\t$func1 = \"FtpUrl\"\n\t\t$func2 = \"ScreenCapture\"\n\t\t$func3 = \"CaptureMouse\"\n\t\t$func4 = \"UploadFile\"\n\n\t\t$ebanking1 = \"Internet Banking\" wide\n\t\t$ebanking2 = \"(Online Banking)|(Online banking)\"\n\t\t$ebanking3 = \"(e-banking)|(e-Banking)\" nocase\n\t\t$ebanking4 = \"login\"\n\t\t$ebanking5 = \"en ligne\" wide\n\t\t$ebanking6 = \"bancaires\" wide\n\t\t$ebanking7 = \"(eBanking)|(Ebanking)\" wide\n\t\t$ebanking8 = \"Anmeldung\" wide\n\t\t$ebanking9 = \"internet banking\" nocase wide\n\t\t$ebanking10 = \"Banking Online\" nocase wide\n\t\t$ebanking11 = \"Web Banking\" wide\n\t\t$ebanking12 = \"Power\"\n\n\t",
        "rule_name": "Bolonyokte",
        "start_line": 8,
        "stop_line": 52,
        "strings": [
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$campaign1",
                "type": "text",
                "value": "Bolonyokte"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$campaign2",
                "type": "text",
                "value": "donadoni"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$decoy1",
                "type": "text",
                "value": "nyse.com"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$decoy2",
                "type": "text",
                "value": "NYSEArca_Listing_Fees.pdf"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$decoy3",
                "type": "text",
                "value": "bf13-5d45cb40"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$artifact1",
                "type": "text",
                "value": "Backup.zip"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$artifact2",
                "type": "text",
                "value": "updates.txt"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$artifact3",
                "type": "text",
                "value": "vdirs.dat"
            },
            {
                "name": "$artifact4",
                "type": "text",
                "value": "default.dat"
            },
            {
                "name": "$artifact5",
                "type": "text",
                "value": "index.html"
            },
            {
                "name": "$artifact6",
                "type": "text",
                "value": "mime.dat"
            },
            {
                "name": "$func1",
                "type": "text",
                "value": "FtpUrl"
            },
            {
                "name": "$func2",
                "type": "text",
                "value": "ScreenCapture"
            },
            {
                "name": "$func3",
                "type": "text",
                "value": "CaptureMouse"
            },
            {
                "name": "$func4",
                "type": "text",
                "value": "UploadFile"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$ebanking1",
                "type": "text",
                "value": "Internet Banking"
            },
            {
                "name": "$ebanking2",
                "type": "text",
                "value": "(Online Banking)|(Online banking)"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$ebanking3",
                "type": "text",
                "value": "(e-banking)|(e-Banking)"
            },
            {
                "name": "$ebanking4",
                "type": "text",
                "value": "login"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$ebanking5",
                "type": "text",
                "value": "en ligne"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$ebanking6",
                "type": "text",
                "value": "bancaires"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$ebanking7",
                "type": "text",
                "value": "(eBanking)|(Ebanking)"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$ebanking8",
                "type": "text",
                "value": "Anmeldung"
            },
            {
                "modifiers": [
                    "nocase",
                    "wide"
                ],
                "name": "$ebanking9",
                "type": "text",
                "value": "internet banking"
            },
            {
                "modifiers": [
                    "nocase",
                    "wide"
                ],
                "name": "$ebanking10",
                "type": "text",
                "value": "Banking Online"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$ebanking11",
                "type": "text",
                "value": "Web Banking"
            },
            {
                "name": "$ebanking12",
                "type": "text",
                "value": "Power"
            }
        ],
        "tags": [
            "rat"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Bozok', '{RAT}', '{"ref": "http://malwareconfig.com/stats/Bozok", "date": "2014/04", "author": " Kevin Breen <kevin@techanarchy.net>", "maltype": "Remote Access Trojan", "filetype": "exe"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": " Kevin Breen <kevin@techanarchy.net>"
            },
            {
                "date": "2014/04"
            },
            {
                "ref": "http://malwareconfig.com/stats/Bozok"
            },
            {
                "maltype": "Remote Access Trojan"
            },
            {
                "filetype": "exe"
            }
        ],
        "raw_condition": "condition:\n\t\tall of them\n",
        "raw_meta": "meta:\n\t\tauthor = \" Kevin Breen <kevin@techanarchy.net>\"\n\t\tdate = \"2014/04\"\n\t\tref = \"http://malwareconfig.com/stats/Bozok\"\n\t\tmaltype = \"Remote Access Trojan\"\n\t\tfiletype = \"exe\"\n\n\t",
        "raw_strings": "strings:\n\t\t$a = \"getVer\" nocase\n\t\t$b = \"StartVNC\" nocase\n\t\t$c = \"SendCamList\" nocase\n\t\t$d = \"untPlugin\" nocase\n\t\t$e = \"gethostbyname\" nocase\n\n\t",
        "rule_name": "Bozok",
        "start_line": 5,
        "stop_line": 23,
        "strings": [
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$a",
                "type": "text",
                "value": "getVer"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$b",
                "type": "text",
                "value": "StartVNC"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$c",
                "type": "text",
                "value": "SendCamList"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$d",
                "type": "text",
                "value": "untPlugin"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$e",
                "type": "text",
                "value": "gethostbyname"
            }
        ],
        "tags": [
            "RAT"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'VisualDiscovery_Lonovo_Superfish_SSL_Hijack', NULL, '{"date": "2015/02/19", "hash1": "99af9cfc7ab47f847103b5497b746407dc566963", "hash2": "f0b0cd0227ba302ac9ab4f30d837422c7ae66c46", "hash3": "f12edf2598d8f0732009c5cd1df5d2c559455a0b", "hash4": "343af97d47582c8150d63cbced601113b14fcca6", "author": "Florian Roth / improved by kbandla", "reference": "https://twitter.com/4nc4p/status/568325493558272000", "description": "Lenovo Superfish SSL Interceptor - file VisualDiscovery.exe"}', '[
    {
        "condition_terms": [
            "(",
            "$mz",
            "at",
            "0",
            ")",
            "and",
            "filesize",
            "<",
            "2MB",
            "and",
            "all",
            "of",
            "(",
            "$s*",
            ")"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "description": "Lenovo Superfish SSL Interceptor - file VisualDiscovery.exe"
            },
            {
                "author": "Florian Roth / improved by kbandla"
            },
            {
                "reference": "https://twitter.com/4nc4p/status/568325493558272000"
            },
            {
                "date": "2015/02/19"
            },
            {
                "hash1": "99af9cfc7ab47f847103b5497b746407dc566963"
            },
            {
                "hash2": "f0b0cd0227ba302ac9ab4f30d837422c7ae66c46"
            },
            {
                "hash3": "f12edf2598d8f0732009c5cd1df5d2c559455a0b"
            },
            {
                "hash4": "343af97d47582c8150d63cbced601113b14fcca6"
            }
        ],
        "raw_condition": "condition:\n\t\t( $mz at 0 ) and filesize < 2MB and all of ($s*)\n",
        "raw_meta": "meta:\n\t\tdescription = \"Lenovo Superfish SSL Interceptor - file VisualDiscovery.exe\"\n\t\tauthor = \"Florian Roth / improved by kbandla\"\n\t\treference = \"https://twitter.com/4nc4p/status/568325493558272000\"\n\t\tdate = \"2015/02/19\"\n\t\thash1 = \"99af9cfc7ab47f847103b5497b746407dc566963\"\n\t\thash2 = \"f0b0cd0227ba302ac9ab4f30d837422c7ae66c46\"\n\t\thash3 = \"f12edf2598d8f0732009c5cd1df5d2c559455a0b\"\n\t\thash4 = \"343af97d47582c8150d63cbced601113b14fcca6\"\n\t",
        "raw_strings": "strings:\n\t\t$mz = { 4d 5a }\n\t\t//$s1 = \"VisualDiscovery.exe\" fullword wide\n\t\t$s2 = \"Invalid key length used to initialize BlowFish.\" fullword ascii\n\t\t$s3 = \"GetPCProxyHandler\" fullword ascii\n\t\t$s4 = \"StartPCProxy\" fullword ascii\n\t\t$s5 = \"SetPCProxyHandler\" fullword ascii\n\t",
        "rule_name": "VisualDiscovery_Lonovo_Superfish_SSL_Hijack",
        "start_line": 10,
        "stop_line": 29,
        "strings": [
            {
                "name": "$mz",
                "type": "byte",
                "value": "{ 4d 5a }"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s2",
                "type": "text",
                "value": "Invalid key length used to initialize BlowFish."
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s3",
                "type": "text",
                "value": "GetPCProxyHandler"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s4",
                "type": "text",
                "value": "StartPCProxy"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s5",
                "type": "text",
                "value": "SetPCProxyHandler"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'PoS_Malware_MalumPOS', NULL, '{"date": "2015-05-25", "author": "Trend Micro, Inc.", "description": "Used to detect MalumPOS memory dumper", "sample_filtype": "exe"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "(",
            "$string*",
            ")"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "author": "Trend Micro, Inc."
            },
            {
                "date": "2015-05-25"
            },
            {
                "description": "Used to detect MalumPOS memory dumper"
            },
            {
                "sample_filtype": "exe"
            }
        ],
        "raw_condition": "condition:\n        all of ($string*)\n",
        "raw_meta": "meta:\n        author = \"Trend Micro, Inc.\"\n        date = \"2015-05-25\"\n        description = \"Used to detect MalumPOS memory dumper\"\n        sample_filtype = \"exe\"\n    ",
        "raw_strings": "strings:\n        $string1 = \"SOFTWARE\\\\Borland\\\\Delphi\\\\RTL\"\n        $string2 = \"B)[0-9]{13,19}\\\\\"\n        $string3 = \"[A-Za-z\\\\s]{0,30}\\\\/[A-Za-z\\\\s]{0,30}\\\\\"\n        $string4 = \"TRegExpr(exec): ExecNext Without Exec[Pos]\"\n        $string5 = /Y:\\\\PROGRAMS\\\\.{20,300}\\.pas/ \n    ",
        "rule_name": "PoS_Malware_MalumPOS",
        "start_line": 8,
        "stop_line": 23,
        "strings": [
            {
                "name": "$string1",
                "type": "text",
                "value": "SOFTWARE\\\\Borland\\\\Delphi\\\\RTL"
            },
            {
                "name": "$string2",
                "type": "text",
                "value": "B)[0-9]{13,19}\\\\"
            },
            {
                "name": "$string3",
                "type": "text",
                "value": "[A-Za-z\\\\s]{0,30}\\\\/[A-Za-z\\\\s]{0,30}\\\\"
            },
            {
                "name": "$string4",
                "type": "text",
                "value": "TRegExpr(exec): ExecNext Without Exec[Pos]"
            },
            {
                "name": "$string5",
                "type": "regex",
                "value": "/Y:\\\\PROGRAMS\\\\.{20,300}\\.pas/"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Trojan_W32_Gh0stMiancha_1_0_0', NULL, '{"Date": "2014/01/27", "Author": "Context Threat Intelligence", "Reference": "http://www.contextis.com/documents/30/TA10009_20140127_-_CTI_Threat_Advisory_-_The_Monju_Incident1.pdf", "Description": "Bytes inside"}', '[
    {
        "condition_terms": [
            "any",
            "of",
            "them"
        ],
        "imports": [
            "pe"
        ],
        "metadata": [
            {
                "Author": "Context Threat Intelligence"
            },
            {
                "Date": "2014/01/27"
            },
            {
                "Description": "Bytes inside"
            },
            {
                "Reference": "http://www.contextis.com/documents/30/TA10009_20140127_-_CTI_Threat_Advisory_-_The_Monju_Incident1.pdf"
            }
        ],
        "raw_condition": "condition:\n       any of them\n",
        "raw_meta": "meta:\n        Author      = \"Context Threat Intelligence\"\n        Date        = \"2014/01/27\"\n        Description = \"Bytes inside\"\n        Reference   = \"http://www.contextis.com/documents/30/TA10009_20140127_-_CTI_Threat_Advisory_-_The_Monju_Incident1.pdf\"\n\n    ",
        "raw_strings": "strings:\n        $0x = { 57 5b 5a 5a 51 57 40 34 31 67 2e 31 70 34 5c 40 40 44 3b 25 3a 19 1e 5c 7b 67 60 2e 34 31 67 2e 31 70 19 1e 55 77 77 71 64 60 2e 34 3e 3b 3e 19 1e 57 7b 7a 60 71 7a 60 39 40 6d 64 71 2e 34 60 71 6c 60 3b 7c 60 79 78 19 1e 44 66 7b 6c 6d 39 57 7b 7a 7a 71 77 60 7d 7b 7a 2e 34 5f 71 71 64 39 55 78 7d 62 71 19 1e 57 7b 7a 60 71 7a 60 39 78 71 7a 73 60 7c 2e 34 24 19 1e 19 1e }\n        $1 = { 5c e7 99 bd e5 8a a0 e9 bb 91 5c }\n        $1x = { 48 f3 8d a9 f1 9e b4 fd af 85 48 }\n        $2 = \"DllCanLoadNow\"\n        $2x = { 50 78 78 57 75 7a 58 7b 75 70 5a 7b 63 }\n        $3x = { 5a 61 79 76 71 66 34 7b 72 34 67 61 76 7f 71 6d 67 2e 34 31 70 } \n        $4 = \"JXNcc2hlbGxcb3Blblxjb21tYW5k\"\n        $4x = { 5e 4c 5a 77 77 26 7c 78 76 53 6c 77 76 27 56 78 76 78 6c 7e 76 26 25 60 4d 43 21 7f }\n        $5 = \"SEFSRFdBUkVcREVTQ1JJUFRJT05cU3lzdGVtXENlbnRyYWxQcm9jZXNzb3JcMA==\"\n        $5x = { 47 51 52 47 46 52 70 56 41 7f 42 77 46 51 42 40 45 25 5e 5e 41 52 46 5e 40 24 21 77 41 27 78 6e 70 53 42 60 4c 51 5a 78 76 7a 46 6d 4d 43 6c 45 77 79 2d 7e 4e 4c 5a 6e 76 27 5e 77 59 55 29 29 }\n        $6 = \"C:\\\\Users\\\\why\\\\\"\n        $6x = { 57 2e 48 41 67 71 66 67 48 63 7c 6d 48 }\n        $7 = \"g:\\\\ykcx\\\\\"\n        $7x = { 73 2E 48 6D 7F 77 6C 48 }\n        $8 = \"(miansha)\"\n        $8x = { 3C 79 7D 75 7A 67 7C 75 3D }\n        $9 = \"server(\\xE5\\xA3\\xB3)\"\n        $9x = { 7C 2E 48 26 24 25 27 3A 25 25 3A 26 21 48 67 71 66 62 71 66 3C F1 B7 A7 3D 48 46 71 78 71 75 67 71 48 67 71 66 62 71 66 3A 64 70 76 }\n        $cfgDecode = { 8a ?? ?? 80 c2 7a 80 f2 19 88 ?? ?? 41 3b ce 7c ??}\n\n   ",
        "rule_name": "Trojan_W32_Gh0stMiancha_1_0_0",
        "start_line": 9,
        "stop_line": 40,
        "strings": [
            {
                "name": "$0x",
                "type": "byte",
                "value": "{ 57 5b 5a 5a 51 57 40 34 31 67 2e 31 70 34 5c 40 40 44 3b 25 3a 19 1e 5c 7b 67 60 2e 34 31 67 2e 31 70 19 1e 55 77 77 71 64 60 2e 34 3e 3b 3e 19 1e 57 7b 7a 60 71 7a 60 39 40 6d 64 71 2e 34 60 71 6c 60 3b 7c 60 79 78 19 1e 44 66 7b 6c 6d 39 57 7b 7a 7a 71 77 60 7d 7b 7a 2e 34 5f 71 71 64 39 55 78 7d 62 71 19 1e 57 7b 7a 60 71 7a 60 39 78 71 7a 73 60 7c 2e 34 24 19 1e 19 1e }"
            },
            {
                "name": "$1",
                "type": "byte",
                "value": "{ 5c e7 99 bd e5 8a a0 e9 bb 91 5c }"
            },
            {
                "name": "$1x",
                "type": "byte",
                "value": "{ 48 f3 8d a9 f1 9e b4 fd af 85 48 }"
            },
            {
                "name": "$2",
                "type": "text",
                "value": "DllCanLoadNow"
            },
            {
                "name": "$2x",
                "type": "byte",
                "value": "{ 50 78 78 57 75 7a 58 7b 75 70 5a 7b 63 }"
            },
            {
                "name": "$3x",
                "type": "byte",
                "value": "{ 5a 61 79 76 71 66 34 7b 72 34 67 61 76 7f 71 6d 67 2e 34 31 70 }"
            },
            {
                "name": "$4",
                "type": "text",
                "value": "JXNcc2hlbGxcb3Blblxjb21tYW5k"
            },
            {
                "name": "$4x",
                "type": "byte",
                "value": "{ 5e 4c 5a 77 77 26 7c 78 76 53 6c 77 76 27 56 78 76 78 6c 7e 76 26 25 60 4d 43 21 7f }"
            },
            {
                "name": "$5",
                "type": "text",
                "value": "SEFSRFdBUkVcREVTQ1JJUFRJT05cU3lzdGVtXENlbnRyYWxQcm9jZXNzb3JcMA=="
            },
            {
                "name": "$5x",
                "type": "byte",
                "value": "{ 47 51 52 47 46 52 70 56 41 7f 42 77 46 51 42 40 45 25 5e 5e 41 52 46 5e 40 24 21 77 41 27 78 6e 70 53 42 60 4c 51 5a 78 76 7a 46 6d 4d 43 6c 45 77 79 2d 7e 4e 4c 5a 6e 76 27 5e 77 59 55 29 29 }"
            },
            {
                "name": "$6",
                "type": "text",
                "value": "C:\\\\Users\\\\why\\\\"
            },
            {
                "name": "$6x",
                "type": "byte",
                "value": "{ 57 2e 48 41 67 71 66 67 48 63 7c 6d 48 }"
            },
            {
                "name": "$7",
                "type": "text",
                "value": "g:\\\\ykcx\\\\"
            },
            {
                "name": "$7x",
                "type": "byte",
                "value": "{ 73 2E 48 6D 7F 77 6C 48 }"
            },
            {
                "name": "$8",
                "type": "text",
                "value": "(miansha)"
            },
            {
                "name": "$8x",
                "type": "byte",
                "value": "{ 3C 79 7D 75 7A 67 7C 75 3D }"
            },
            {
                "name": "$9",
                "type": "text",
                "value": "server(\\xE5\\xA3\\xB3)"
            },
            {
                "name": "$9x",
                "type": "byte",
                "value": "{ 7C 2E 48 26 24 25 27 3A 25 25 3A 26 21 48 67 71 66 62 71 66 3C F1 B7 A7 3D 48 46 71 78 71 75 67 71 48 67 71 66 62 71 66 3A 64 70 76 }"
            },
            {
                "name": "$cfgDecode",
                "type": "byte",
                "value": "{ 8a ?? ?? 80 c2 7a 80 f2 19 88 ?? ?? 41 3b ce 7c ??}"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'TrumpBot', '{MALW}', '{"MD5": "77122e0e6fcf18df9572d80c4eedd88d", "SHA1": "108ee460d4c11ea373b7bba92086dd8023c0654f", "date": "2017-04-16", "author": "Joan Soriano / @joanbtl", "version": "1.0", "description": "TrumpBot"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "TrumpBot"
            },
            {
                "author": "Joan Soriano / @joanbtl"
            },
            {
                "date": "2017-04-16"
            },
            {
                "version": "1.0"
            },
            {
                "MD5": "77122e0e6fcf18df9572d80c4eedd88d"
            },
            {
                "SHA1": "108ee460d4c11ea373b7bba92086dd8023c0654f"
            }
        ],
        "raw_condition": "condition:\n\t\t all of them\n",
        "raw_meta": "meta:\n\t\tdescription = \"TrumpBot\"\n\t\tauthor = \"Joan Soriano / @joanbtl\"\n\t\tdate = \"2017-04-16\"\n\t\tversion = \"1.0\"\n\t\tMD5 = \"77122e0e6fcf18df9572d80c4eedd88d\"\n\t\tSHA1 = \"108ee460d4c11ea373b7bba92086dd8023c0654f\"\n\n\t",
        "raw_strings": "strings:\n\t\t$string = \"trumpisdaddy\"\n\t\t$ip = \"198.50.154.188\"\n\t",
        "rule_name": "TrumpBot",
        "start_line": 1,
        "stop_line": 16,
        "strings": [
            {
                "name": "$string",
                "type": "text",
                "value": "trumpisdaddy"
            },
            {
                "name": "$ip",
                "type": "text",
                "value": "198.50.154.188"
            }
        ],
        "tags": [
            "MALW"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'nkminer_monero', NULL, '{"tlp": "white", "author": "cdoman@alienvault.com", "license": "MIT License", "reference": "https://www.alienvault.com/blogs/labs-research/a-north-korean-monero-cryptocurrency-miner", "description": "Detects installer of Monero miner that points to a NK domain"}', '[
    {
        "condition_terms": [
            "any",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Detects installer of Monero miner that points to a NK domain"
            },
            {
                "author": "cdoman@alienvault.com"
            },
            {
                "reference": "https://www.alienvault.com/blogs/labs-research/a-north-korean-monero-cryptocurrency-miner"
            },
            {
                "tlp": "white"
            },
            {
                "license": "MIT License"
            }
        ],
        "raw_condition": "condition:\n\n any of them\n\n",
        "raw_meta": "meta:\n\n description = \"Detects installer of Monero miner that points to a NK domain\"\n\n author = \"cdoman@alienvault.com\"\n \n reference = \"https://www.alienvault.com/blogs/labs-research/a-north-korean-monero-cryptocurrency-miner\"\n\n tlp = \"white\"\n\n license = \"MIT License\"\n\n ",
        "raw_strings": "strings:\n\n $a = \"82e999fb-a6e0-4094-aa1f-1a306069d1a5\" nocase wide ascii\n\n $b = \"4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRy5YeFCqgoUMnzumvS\" nocase wide ascii\n\n $c = \"barjuok.ryongnamsan.edu.kp\" nocase wide ascii\n\n $d = \"C:\\\\SoftwaresInstall\\\\soft\" nocase wide ascii\n\n $e = \"C:\\\\Windows\\\\Sys64\\\\intelservice.exe\" nocase wide ascii\n\n $f = \"C:\\\\Windows\\\\Sys64\\\\updater.exe\" nocase wide ascii\n\n $g = \"C:\\\\Users\\\\Jawhar\\\\documents\\\\\" nocase wide ascii\n\n ",
        "rule_name": "nkminer_monero",
        "start_line": 1,
        "stop_line": 35,
        "strings": [
            {
                "modifiers": [
                    "nocase",
                    "wide",
                    "ascii"
                ],
                "name": "$a",
                "type": "text",
                "value": "82e999fb-a6e0-4094-aa1f-1a306069d1a5"
            },
            {
                "modifiers": [
                    "nocase",
                    "wide",
                    "ascii"
                ],
                "name": "$b",
                "type": "text",
                "value": "4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRy5YeFCqgoUMnzumvS"
            },
            {
                "modifiers": [
                    "nocase",
                    "wide",
                    "ascii"
                ],
                "name": "$c",
                "type": "text",
                "value": "barjuok.ryongnamsan.edu.kp"
            },
            {
                "modifiers": [
                    "nocase",
                    "wide",
                    "ascii"
                ],
                "name": "$d",
                "type": "text",
                "value": "C:\\\\SoftwaresInstall\\\\soft"
            },
            {
                "modifiers": [
                    "nocase",
                    "wide",
                    "ascii"
                ],
                "name": "$e",
                "type": "text",
                "value": "C:\\\\Windows\\\\Sys64\\\\intelservice.exe"
            },
            {
                "modifiers": [
                    "nocase",
                    "wide",
                    "ascii"
                ],
                "name": "$f",
                "type": "text",
                "value": "C:\\\\Windows\\\\Sys64\\\\updater.exe"
            },
            {
                "modifiers": [
                    "nocase",
                    "wide",
                    "ascii"
                ],
                "name": "$g",
                "type": "text",
                "value": "C:\\\\Users\\\\Jawhar\\\\documents\\\\"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'ATM_HelloWorld', '{malware}', '{"date": "2019-01-13", "author": "xylitol@temari.fr", "description": "Search strings and procedure in HelloWorld ATM Malware"}', '[
    {
        "condition_terms": [
            "(",
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5A4D",
            "and",
            "uint32",
            "(",
            "uint32",
            "(",
            "0x3C",
            ")",
            ")",
            "==",
            "0x00004550",
            ")",
            "and",
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Search strings and procedure in HelloWorld ATM Malware"
            },
            {
                "author": "xylitol@temari.fr"
            },
            {
                "date": "2019-01-13"
            }
        ],
        "raw_condition": "condition:\n        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and all of them\n",
        "raw_meta": "meta:\n        description = \"Search strings and procedure in HelloWorld ATM Malware\"\n        author = \"xylitol@temari.fr\"\n        date = \"2019-01-13\"\n\n    ",
        "raw_strings": "strings:\n        $api1 = \"CscCngOpen\" ascii wide\n        $api2 = \"CscCngClose\" ascii wide\n        $string1 = \"%d,%02d;\" ascii wide\n        $string2 = \"MAX_NOTES\" ascii wide\n        $hex_var1 = { FF 15 ?? ?? ?? ?? BF 00 80 00 00 85 C7 }\n\n    ",
        "rule_name": "ATM_HelloWorld",
        "start_line": 5,
        "stop_line": 21,
        "strings": [
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$api1",
                "type": "text",
                "value": "CscCngOpen"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$api2",
                "type": "text",
                "value": "CscCngClose"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$string1",
                "type": "text",
                "value": "%d,%02d;"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$string2",
                "type": "text",
                "value": "MAX_NOTES"
            },
            {
                "name": "$hex_var1",
                "type": "byte",
                "value": "{ FF 15 ?? ?? ?? ?? BF 00 80 00 00 85 C7 }"
            }
        ],
        "tags": [
            "malware"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'BlackWorm', NULL, '{"date": "2015-05-20", "author": "Brian Wallace @botnet_hunter", "description": "Identify BlackWorm", "author_email": "bwall@ballastsecurity.net"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Brian Wallace @botnet_hunter"
            },
            {
                "author_email": "bwall@ballastsecurity.net"
            },
            {
                "date": "2015-05-20"
            },
            {
                "description": "Identify BlackWorm"
            }
        ],
        "raw_condition": "condition:\n        all of them\n",
        "raw_meta": "meta:\n        author = \"Brian Wallace @botnet_hunter\"\n        author_email = \"bwall@ballastsecurity.net\"\n        date = \"2015-05-20\"\n        description = \"Identify BlackWorm\"\n\n    ",
        "raw_strings": "strings:\n        $str1 = \"m_ComputerObjectProvider\"\n        $str2 = \"MyWebServices\"\n        $str3 = \"get_ExecutablePath\"\n        $str4 = \"get_WebServices\"\n        $str5 = \"My.WebServices\"\n        $str6 = \"My.User\"\n        $str7 = \"m_UserObjectProvider\"\n        $str8 = \"DelegateCallback\"\n        $str9 = \"TargetMethod\"\n        $str10 = \"000004b0\" wide\n        $str11 = \"Microsoft Corporation\" wide\n\n    ",
        "rule_name": "BlackWorm",
        "start_line": 6,
        "stop_line": 30,
        "strings": [
            {
                "name": "$str1",
                "type": "text",
                "value": "m_ComputerObjectProvider"
            },
            {
                "name": "$str2",
                "type": "text",
                "value": "MyWebServices"
            },
            {
                "name": "$str3",
                "type": "text",
                "value": "get_ExecutablePath"
            },
            {
                "name": "$str4",
                "type": "text",
                "value": "get_WebServices"
            },
            {
                "name": "$str5",
                "type": "text",
                "value": "My.WebServices"
            },
            {
                "name": "$str6",
                "type": "text",
                "value": "My.User"
            },
            {
                "name": "$str7",
                "type": "text",
                "value": "m_UserObjectProvider"
            },
            {
                "name": "$str8",
                "type": "text",
                "value": "DelegateCallback"
            },
            {
                "name": "$str9",
                "type": "text",
                "value": "TargetMethod"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str10",
                "type": "text",
                "value": "000004b0"
            },
            {
                "modifiers": [
                    "wide"
                ],
                "name": "$str11",
                "type": "text",
                "value": "Microsoft Corporation"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'SeaDuke_Sample', NULL, '{"date": "2015-07-14", "hash": "d2e570129a12a47231a1ecb8176fa88a1bf415c51dabd885c513d98b15f75d4e", "score": 70, "author": "Florian Roth", "reference": "http://goo.gl/MJ0c2M", "description": "SeaDuke Malware - file 3eb86b7b067c296ef53e4857a74e09f12c2b84b666fc130d1f58aec18bc74b0d"}', '[
    {
        "condition_terms": [
            "uint16",
            "(",
            "0",
            ")",
            "==",
            "0x5a4d",
            "and",
            "filesize",
            "<",
            "4000KB",
            "and",
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "SeaDuke Malware - file 3eb86b7b067c296ef53e4857a74e09f12c2b84b666fc130d1f58aec18bc74b0d"
            },
            {
                "author": "Florian Roth"
            },
            {
                "reference": "http://goo.gl/MJ0c2M"
            },
            {
                "date": "2015-07-14"
            },
            {
                "score": 70
            },
            {
                "hash": "d2e570129a12a47231a1ecb8176fa88a1bf415c51dabd885c513d98b15f75d4e"
            }
        ],
        "raw_condition": "condition:\n        uint16(0) == 0x5a4d and filesize < 4000KB and all of them\n",
        "raw_meta": "meta:\n        description = \"SeaDuke Malware - file 3eb86b7b067c296ef53e4857a74e09f12c2b84b666fc130d1f58aec18bc74b0d\"\n        author = \"Florian Roth\"\n        reference = \"http://goo.gl/MJ0c2M\"\n        date = \"2015-07-14\"\n        score = 70\n        hash = \"d2e570129a12a47231a1ecb8176fa88a1bf415c51dabd885c513d98b15f75d4e\"\n\n    ",
        "raw_strings": "strings:\n        $s0 = \"bpython27.dll\" fullword ascii\n        $s1 = \"email.header(\" fullword ascii /* PEStudio Blacklist: strings */\n        $s2 = \"LogonUI.exe\" fullword wide /* PEStudio Blacklist: strings */\n        $s3 = \"Crypto.Cipher.AES(\" fullword ascii /* PEStudio Blacklist: strings */\n        $s4 = \"mod is NULL - %s\" fullword ascii\n\n    ",
        "rule_name": "SeaDuke_Sample",
        "start_line": 6,
        "stop_line": 26,
        "strings": [
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s0",
                "type": "text",
                "value": "bpython27.dll"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s1",
                "type": "text",
                "value": "email.header("
            },
            {
                "modifiers": [
                    "fullword",
                    "wide"
                ],
                "name": "$s2",
                "type": "text",
                "value": "LogonUI.exe"
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s3",
                "type": "text",
                "value": "Crypto.Cipher.AES("
            },
            {
                "modifiers": [
                    "fullword",
                    "ascii"
                ],
                "name": "$s4",
                "type": "text",
                "value": "mod is NULL - %s"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'SnakeRansomware', NULL, '{"Data": "15th May 2020", "Author": "Nishan Maharjan", "Reference": "https://medium.com/@nishanmaharjan17/malware-analysis-snake-ransomware-a0e66f487017", "Description": "A yara rule to catch snake ransomware"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "Author": "Nishan Maharjan"
            },
            {
                "Description": "A yara rule to catch snake ransomware"
            },
            {
                "Reference": "https://medium.com/@nishanmaharjan17/malware-analysis-snake-ransomware-a0e66f487017"
            },
            {
                "Data": "15th May 2020"
            }
        ],
        "raw_condition": "condition:\n        all of them     \n",
        "raw_meta": "meta:\n        Author = \"Nishan Maharjan\"\n        Description = \"A yara rule to catch snake ransomware\"\n        Reference = \"https://medium.com/@nishanmaharjan17/malware-analysis-snake-ransomware-a0e66f487017\"\n        Data = \"15th May 2020\"\n    ",
        "raw_strings": "strings:\n        $go_build_id = \"Go build ID: \\\"X6lNEpDhc_qgQl56x4du/fgVJOqLlPCCIekQhFnHL/rkxe6tXCg56Ez88otHrz/Y-lXW-OhiIbzg3-ioGRz\\\"\"\n        $math_rand_seed_calling = { 89 C8 BB 00 CA 9A 3B 89 D1 F7 E3 81 E1 FF FF FF 3F 89 C3 01 C8 89 C6 05 00 00 1A 3D 89 04 24 69 ED 00 CA 9A 3B 01 EA 89 CD C1 F9 1F 01 EB 11 CA 81 C6 00 00 1A 3D 81 D2 EB 03 B2 A1 89 54 24 04 E8 10 62 F6 FF }\n        $encryption_function = {64 8B 0D 14 00 00 00 8B 89 00 00 00 00 3B 61 08 0F 86 38 01 00 00 83 EC 3C E8 32 1A F3 FF 8D 7C 24 28 89 E6 E8 25 EA F0 FF 8B 44 24 2C 8B 4C 24 28 89 C2 C1 E8 1F C1 E0 1F 85 C0 0F 84 FC 00 00 00 D1 E2 89 CB C1 E9 1F 09 D1 89 DA D1 E3 C1 EB 1F 89 CD D1 E1 09 D9 89 CB 81 C1 80 7F B1 D7 C1 ED 1F 81 C3 80 7F B1 D7 83 D5 0D 89 C8 BB 00 CA 9A 3B 89 D1 F7 E3 81 E1 FF FF FF 3F 89 C3 01 C8 89 C6 05 00 00 1A 3D 89 04 24 69 ED 00 CA 9A 3B 01 EA 89 CD C1 F9 1F 01 EB 11 CA 81 C6 00 00 1A 3D 81 D2 EB 03 B2 A1 89 54 24 04 E8 10 62 F6 FF 31 C0 EB 79 89 44 24 20 8B 4C 24 40 8D 14 C1 8B 1A 89 5C 24 24 8B 52 04 89 54 24 1C C7 04 24 05 00 00 00 E8 48 FE FF FF 8B 44 24 08 8B 4C 24 04 C7 04 24 00 00 00 00 8B 54 24 24 89 54 24 04 8B 5C 24 1C 89 5C 24 08 89 4C 24 0C 89 44 24 10 E8 EC DD EF FF 8B 44 24 18 8B 4C 24 14 89 4C 24 08 89 44 24 0C 8B 44 24 24 89 04 24 8B 44 24 1C 89 44 24 04 E8 68 BB F3 FF 8B 44 24 20 40}\n    ",
        "rule_name": "SnakeRansomware",
        "start_line": 1,
        "stop_line": 14,
        "strings": [
            {
                "name": "$go_build_id",
                "type": "text",
                "value": "Go build ID: \\\"X6lNEpDhc_qgQl56x4du/fgVJOqLlPCCIekQhFnHL/rkxe6tXCg56Ez88otHrz/Y-lXW-OhiIbzg3-ioGRz\\\""
            },
            {
                "name": "$math_rand_seed_calling",
                "type": "byte",
                "value": "{ 89 C8 BB 00 CA 9A 3B 89 D1 F7 E3 81 E1 FF FF FF 3F 89 C3 01 C8 89 C6 05 00 00 1A 3D 89 04 24 69 ED 00 CA 9A 3B 01 EA 89 CD C1 F9 1F 01 EB 11 CA 81 C6 00 00 1A 3D 81 D2 EB 03 B2 A1 89 54 24 04 E8 10 62 F6 FF }"
            },
            {
                "name": "$encryption_function",
                "type": "byte",
                "value": "{64 8B 0D 14 00 00 00 8B 89 00 00 00 00 3B 61 08 0F 86 38 01 00 00 83 EC 3C E8 32 1A F3 FF 8D 7C 24 28 89 E6 E8 25 EA F0 FF 8B 44 24 2C 8B 4C 24 28 89 C2 C1 E8 1F C1 E0 1F 85 C0 0F 84 FC 00 00 00 D1 E2 89 CB C1 E9 1F 09 D1 89 DA D1 E3 C1 EB 1F 89 CD D1 E1 09 D9 89 CB 81 C1 80 7F B1 D7 C1 ED 1F 81 C3 80 7F B1 D7 83 D5 0D 89 C8 BB 00 CA 9A 3B 89 D1 F7 E3 81 E1 FF FF FF 3F 89 C3 01 C8 89 C6 05 00 00 1A 3D 89 04 24 69 ED 00 CA 9A 3B 01 EA 89 CD C1 F9 1F 01 EB 11 CA 81 C6 00 00 1A 3D 81 D2 EB 03 B2 A1 89 54 24 04 E8 10 62 F6 FF 31 C0 EB 79 89 44 24 20 8B 4C 24 40 8D 14 C1 8B 1A 89 5C 24 24 8B 52 04 89 54 24 1C C7 04 24 05 00 00 00 E8 48 FE FF FF 8B 44 24 08 8B 4C 24 04 C7 04 24 00 00 00 00 8B 54 24 24 89 54 24 04 8B 5C 24 1C 89 5C 24 08 89 4C 24 0C 89 44 24 10 E8 EC DD EF FF 8B 44 24 18 8B 4C 24 14 89 4C 24 08 89 44 24 0C 8B 44 24 24 89 04 24 8B 44 24 1C 89 44 24 04 E8 68 BB F3 FF 8B 44 24 20 40}"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'sendsafe', NULL, '{"date": "2016/09", "author": " J from THL <j@techhelplist.com>", "maltype": "Spammer", "version": 2, "filetype": "memory", "reference": "http://pastebin.com/WPWWs406"}', '[
    {
        "condition_terms": [
            "13",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": " J from THL <j@techhelplist.com>"
            },
            {
                "date": "2016/09"
            },
            {
                "reference": "http://pastebin.com/WPWWs406"
            },
            {
                "version": 2
            },
            {
                "maltype": "Spammer"
            },
            {
                "filetype": "memory"
            }
        ],
        "raw_condition": "condition:\n        13 of them\n",
        "raw_meta": "meta:\n        author = \" J from THL <j@techhelplist.com>\"\n        date = \"2016/09\"\n        reference = \"http://pastebin.com/WPWWs406\"\n\t\tversion = 2\n        maltype = \"Spammer\"\n        filetype = \"memory\"\n\n    ",
        "raw_strings": "strings:\n        $a = \"Enterprise Mailing Service\"\n        $b = \"Blacklisted by rule: %s:%s\"\n        $c = \"/SuccessMails?CampaignNum=%ld\"\n        $d = \"/TimedOutMails?CampaignNum=%ld\"\n        $e = \"/InvalidMails?CampaignNum=%ld\"\n        $f = \"Failed to download maillist, retrying\"\n        $g = \"No maillist loaded\"\n        $h = \"Successfully sent using SMTP account %s (%d of %ld messages to %s)\"\n        $i = \"Successfully sent %d of %ld messages to %s\"\n        $j = \"Sending to %s in the same connection\"\n        $k = \"New connection required, will send to %s\"\n\t\t$l = \"Mail transaction for %s is over.\"\n\t\t$m = \"Domain %s is bad (found in cache)\"\n\t\t$n = \"Domain %s found in cache\"\n\t\t$o = \"Domain %s isn''t found in cache, resolving it\"\n\t\t$p = \"All tries to resolve %s failed.\"\n\t\t$q = \"Failed to receive response for %s from DNS server\"\n\t\t$r = \"Got DNS server response: domain %s is bad\"\n\t\t$s = \"Got error %d in response for %s from DNS server\"\n\t\t$t = \"MX''s IP for domain %s found in cache:\"\n\t\t$u = \"Timeout waiting for domain %s to be resolved\"\n\t\t$v = \"No valid MXes for domain %s. Marking it as bad\"\n\t\t$w = \"Resolving MX %s using existing connection to DNS server\"\n\t\t$x = \"All tries to resolve MX for %s are failed\"\n\t\t$y = \"Resolving MX %s using DNS server\"\n\t\t$z = \"Failed to receive response for MX %s from DNS server\"\n\n    ",
        "rule_name": "sendsafe",
        "start_line": 8,
        "stop_line": 48,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "Enterprise Mailing Service"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "Blacklisted by rule: %s:%s"
            },
            {
                "name": "$c",
                "type": "text",
                "value": "/SuccessMails?CampaignNum=%ld"
            },
            {
                "name": "$d",
                "type": "text",
                "value": "/TimedOutMails?CampaignNum=%ld"
            },
            {
                "name": "$e",
                "type": "text",
                "value": "/InvalidMails?CampaignNum=%ld"
            },
            {
                "name": "$f",
                "type": "text",
                "value": "Failed to download maillist, retrying"
            },
            {
                "name": "$g",
                "type": "text",
                "value": "No maillist loaded"
            },
            {
                "name": "$h",
                "type": "text",
                "value": "Successfully sent using SMTP account %s (%d of %ld messages to %s)"
            },
            {
                "name": "$i",
                "type": "text",
                "value": "Successfully sent %d of %ld messages to %s"
            },
            {
                "name": "$j",
                "type": "text",
                "value": "Sending to %s in the same connection"
            },
            {
                "name": "$k",
                "type": "text",
                "value": "New connection required, will send to %s"
            },
            {
                "name": "$l",
                "type": "text",
                "value": "Mail transaction for %s is over."
            },
            {
                "name": "$m",
                "type": "text",
                "value": "Domain %s is bad (found in cache)"
            },
            {
                "name": "$n",
                "type": "text",
                "value": "Domain %s found in cache"
            },
            {
                "name": "$o",
                "type": "text",
                "value": "Domain %s isn''t found in cache, resolving it"
            },
            {
                "name": "$p",
                "type": "text",
                "value": "All tries to resolve %s failed."
            },
            {
                "name": "$q",
                "type": "text",
                "value": "Failed to receive response for %s from DNS server"
            },
            {
                "name": "$r",
                "type": "text",
                "value": "Got DNS server response: domain %s is bad"
            },
            {
                "name": "$s",
                "type": "text",
                "value": "Got error %d in response for %s from DNS server"
            },
            {
                "name": "$t",
                "type": "text",
                "value": "MX''s IP for domain %s found in cache:"
            },
            {
                "name": "$u",
                "type": "text",
                "value": "Timeout waiting for domain %s to be resolved"
            },
            {
                "name": "$v",
                "type": "text",
                "value": "No valid MXes for domain %s. Marking it as bad"
            },
            {
                "name": "$w",
                "type": "text",
                "value": "Resolving MX %s using existing connection to DNS server"
            },
            {
                "name": "$x",
                "type": "text",
                "value": "All tries to resolve MX for %s are failed"
            },
            {
                "name": "$y",
                "type": "text",
                "value": "Resolving MX %s using DNS server"
            },
            {
                "name": "$z",
                "type": "text",
                "value": "Failed to receive response for MX %s from DNS server"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'fire2013', '{webshell}', '{"date": "2016/07/18", "author": "Vlad https://github.com/vlad-s", "description": "Catches a webshell"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Vlad https://github.com/vlad-s"
            },
            {
                "date": "2016/07/18"
            },
            {
                "description": "Catches a webshell"
            }
        ],
        "raw_condition": "condition:\n        all of them\n",
        "raw_meta": "meta:\n        author      = \"Vlad https://github.com/vlad-s\"\n        date        = \"2016/07/18\"\n        description = \"Catches a webshell\"\n    ",
        "raw_strings": "strings:\n        $a = \"eval(\\\"\\\\x65\\\\x76\\\\x61\\\\x6C\\\\x28\\\\x67\\\\x7A\\\\x69\\\\x6E\\\\x66\\\\x6C\\\\x61\"\n        $b = \"yc0CJYb+O//Xgj9/y+U/dd//vkf''\\\\x29\\\\x29\\\\x29\\\\x3B\\\")\"\n    ",
        "rule_name": "fire2013",
        "start_line": 15,
        "stop_line": 26,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "eval(\\\"\\\\x65\\\\x76\\\\x61\\\\x6C\\\\x28\\\\x67\\\\x7A\\\\x69\\\\x6E\\\\x66\\\\x6C\\\\x61"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "yc0CJYb+O//Xgj9/y+U/dd//vkf''\\\\x29\\\\x29\\\\x29\\\\x3B\\\")"
            }
        ],
        "tags": [
            "webshell"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Backdoor_WebShell_asp', '{ASPXSpy}', '{"date": "2019-02-26", "author": "xylitol@temari.fr", "description": "Detect ASPXSpy"}', '[
    {
        "comments": [
            "// May only the challenge guide you"
        ],
        "condition_terms": [
            "3",
            "of",
            "(",
            "$string*",
            ")",
            "or",
            "$plugin"
        ],
        "metadata": [
            {
                "description": "Detect ASPXSpy"
            },
            {
                "author": "xylitol@temari.fr"
            },
            {
                "date": "2019-02-26"
            }
        ],
        "raw_condition": "condition:\n    3 of ($string*) or $plugin\n",
        "raw_meta": "meta:\n    description= \"Detect ASPXSpy\"\n    author = \"xylitol@temari.fr\"\n    date = \"2019-02-26\"\n    // May only the challenge guide you\n    ",
        "raw_strings": "strings:\n    $string1 = \"CmdShell\" wide ascii\n    $string2 = \"ADSViewer\" wide ascii\n    $string3 = \"ASPXSpy.Bin\" wide ascii\n    $string4 = \"PortScan\" wide ascii\n    $plugin = \"Test.AspxSpyPlugins\" wide ascii\n \n    ",
        "rule_name": "Backdoor_WebShell_asp",
        "start_line": 5,
        "stop_line": 21,
        "strings": [
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$string1",
                "type": "text",
                "value": "CmdShell"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$string2",
                "type": "text",
                "value": "ADSViewer"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$string3",
                "type": "text",
                "value": "ASPXSpy.Bin"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$string4",
                "type": "text",
                "value": "PortScan"
            },
            {
                "modifiers": [
                    "wide",
                    "ascii"
                ],
                "name": "$plugin",
                "type": "text",
                "value": "Test.AspxSpyPlugins"
            }
        ],
        "tags": [
            "ASPXSpy"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'php_anuna', NULL, '{"date": "2016/07/18", "author": "Vlad https://github.com/vlad-s", "description": "Catches a PHP Trojan"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Vlad https://github.com/vlad-s"
            },
            {
                "date": "2016/07/18"
            },
            {
                "description": "Catches a PHP Trojan"
            }
        ],
        "raw_condition": "condition:\n        all of them\n",
        "raw_meta": "meta:\n        author      = \"Vlad https://github.com/vlad-s\"\n        date        = \"2016/07/18\"\n        description = \"Catches a PHP Trojan\"\n    ",
        "raw_strings": "strings:\n        $a = /<\\?php \\$[a-z]+ = ''/\n        $b = /\\$[a-z]+=explode\\(chr\\(\\([0-9]+[-+][0-9]+\\)\\)/\n        $c = /\\$[a-z]+=\\([0-9]+[-+][0-9]+\\)/\n        $d = /if \\(!function_exists\\(''[a-z]+''\\)\\)/\n    ",
        "rule_name": "php_anuna",
        "start_line": 8,
        "stop_line": 21,
        "strings": [
            {
                "name": "$a",
                "type": "regex",
                "value": "/<\\?php \\$[a-z]+ = ''/"
            },
            {
                "name": "$b",
                "type": "regex",
                "value": "/\\$[a-z]+=explode\\(chr\\(\\([0-9]+[-+][0-9]+\\)\\)/"
            },
            {
                "name": "$c",
                "type": "regex",
                "value": "/\\$[a-z]+=\\([0-9]+[-+][0-9]+\\)/"
            },
            {
                "name": "$d",
                "type": "regex",
                "value": "/if \\(!function_exists\\(''[a-z]+''\\)\\)/"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Dotico_PHP_webshell', '{webshell}', '{"date": "2019/12/04", "author": "Luis Fueris", "reference": "https://rankinstudio.com/Drupal_ico_index_hack", "description": ".ico PHP webshell - file <eight-num-letter-chars>.ico"}', '[
    {
        "condition_terms": [
            "$php",
            "at",
            "0",
            "and",
            "$regexp",
            "and",
            "filesize",
            ">",
            "70KB",
            "and",
            "filesize",
            "<",
            "110KB"
        ],
        "metadata": [
            {
                "description": ".ico PHP webshell - file <eight-num-letter-chars>.ico"
            },
            {
                "author": "Luis Fueris"
            },
            {
                "reference": "https://rankinstudio.com/Drupal_ico_index_hack"
            },
            {
                "date": "2019/12/04"
            }
        ],
        "raw_condition": "condition:\n        $php at 0 and $regexp and filesize > 70KB and filesize < 110KB\n",
        "raw_meta": "meta:\n        description = \".ico PHP webshell - file <eight-num-letter-chars>.ico\"\n        author = \"Luis Fueris\"\n        reference = \"https://rankinstudio.com/Drupal_ico_index_hack\"\n        date = \"2019/12/04\"\n    ",
        "raw_strings": "strings:\n        $php = \"<?php\" ascii\n        $regexp = /basename\\/\\*[a-z0-9]{,6}\\*\\/\\(\\/\\*[a-z0-9]{,5}\\*\\/trim\\/\\*[a-z0-9]{,5}\\*\\/\\(\\/\\*[a-z0-9]{,5}\\*\\//\n    ",
        "rule_name": "Dotico_PHP_webshell",
        "start_line": 15,
        "stop_line": 26,
        "strings": [
            {
                "modifiers": [
                    "ascii"
                ],
                "name": "$php",
                "type": "text",
                "value": "<?php"
            },
            {
                "name": "$regexp",
                "type": "regex",
                "value": "/basename\\/\\*[a-z0-9]{,6}\\*\\/\\(\\/\\*[a-z0-9]{,5}\\*\\/trim\\/\\*[a-z0-9]{,5}\\*\\/\\(\\/\\*[a-z0-9]{,5}\\*\\//"
            }
        ],
        "tags": [
            "webshell"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'php_in_image', NULL, '{"date": "2016/07/18", "author": "Vlad https://github.com/vlad-s", "description": "Finds image files w/ PHP code in images"}', '[
    {
        "condition_terms": [
            "(",
            "(",
            "$gif",
            "at",
            "0",
            ")",
            "or",
            "(",
            "$jfif",
            "at",
            "0",
            ")",
            "or",
            "(",
            "$png",
            "at",
            "0",
            ")",
            ")",
            "and",
            "$php_tag"
        ],
        "metadata": [
            {
                "author": "Vlad https://github.com/vlad-s"
            },
            {
                "date": "2016/07/18"
            },
            {
                "description": "Finds image files w/ PHP code in images"
            }
        ],
        "raw_condition": "condition:\n        (($gif at 0) or\n        ($jfif at 0) or\n        ($png at 0)) and\n\n        $php_tag\n",
        "raw_meta": "meta:\n        author      = \"Vlad https://github.com/vlad-s\"\n        date        = \"2016/07/18\"\n        description = \"Finds image files w/ PHP code in images\"\n    ",
        "raw_strings": "strings:\n        $gif = /^GIF8[79]a/\n        $jfif = { ff d8 ff e? 00 10 4a 46 49 46 }\n        $png = { 89 50 4e 47 0d 0a 1a 0a }\n\n        $php_tag = \"<?php\"\n    ",
        "rule_name": "php_in_image",
        "start_line": 5,
        "stop_line": 23,
        "strings": [
            {
                "name": "$gif",
                "type": "regex",
                "value": "/^GIF8[79]a/"
            },
            {
                "name": "$jfif",
                "type": "byte",
                "value": "{ ff d8 ff e? 00 10 4a 46 49 46 }"
            },
            {
                "name": "$png",
                "type": "byte",
                "value": "{ 89 50 4e 47 0d 0a 1a 0a }"
            },
            {
                "name": "$php_tag",
                "type": "text",
                "value": "<?php"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Android_Dogspectus', NULL, '{"date": "20-July-2016", "author": "Jacob Soo Lead Re", "source": "https://www.bluecoat.com/security-blog/2016-04-25/android-exploit-delivers-dogspectus-ransomware", "description": "This rule try to detects Dogspectus"}', '[
    {
        "condition_terms": [
            "androguard.activity",
            "(",
            "/PanickedActivity/i",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.RECEIVE_BOOT_COMPLETED/i",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.INTERNET/i",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.WAKE_LOCK/i",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "Jacob Soo Lead Re"
            },
            {
                "date": "20-July-2016"
            },
            {
                "description": "This rule try to detects Dogspectus"
            },
            {
                "source": "https://www.bluecoat.com/security-blog/2016-04-25/android-exploit-delivers-dogspectus-ransomware"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.activity(/PanickedActivity/i) and \n\t\tandroguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/i) and \n\t\tandroguard.permission(/android.permission.INTERNET/i) and\n\t\tandroguard.permission(/android.permission.WAKE_LOCK/i)\n",
        "raw_meta": "meta:\n\t\tauthor = \"Jacob Soo Lead Re\"\n\t\tdate = \"20-July-2016\"\n\t\tdescription = \"This rule try to detects Dogspectus\"\n\t\tsource = \"https://www.bluecoat.com/security-blog/2016-04-25/android-exploit-delivers-dogspectus-ransomware\"\n\n\t",
        "rule_name": "Android_Dogspectus",
        "start_line": 8,
        "stop_line": 21
    }
]
');
INSERT INTO public.rule VALUES (default, 'andr_tordow', NULL, '{"author": "https://twitter.com/5h1vang", "source": "https://securelist.com/blog/mobile/76101/the-banker-that-can-steal-anything/", "description": "Yara for variants of Trojan-Banker.AndroidOS.Tordow. Test rule"}', '[
    {
        "comments": [
            "//Certificate check based on @stevenchan''s comment"
        ],
        "condition_terms": [
            "androguard.package_name",
            "(",
            "\"com.di2.two\"",
            ")",
            "or",
            "(",
            "androguard.activity",
            "(",
            "/API2Service/i",
            ")",
            "and",
            "androguard.activity",
            "(",
            "/CryptoUtil/i",
            ")",
            "and",
            "androguard.activity",
            "(",
            "/Loader/i",
            ")",
            "and",
            "androguard.activity",
            "(",
            "/Logger/i",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.INTERNET/",
            ")",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"78F162D2CC7366754649A806CF17080682FE538C\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"BBA26351CE41ACBE5FA84C9CF331D768CEDD768F\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"0B7C3BC97B6D7C228F456304F5E1B75797B7265E\"",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "description": "Yara for variants of Trojan-Banker.AndroidOS.Tordow. Test rule"
            },
            {
                "source": "https://securelist.com/blog/mobile/76101/the-banker-that-can-steal-anything/"
            },
            {
                "author": "https://twitter.com/5h1vang"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.package_name(\"com.di2.two\") or\t\t\n\t\t(androguard.activity(/API2Service/i) and\n\t\tandroguard.activity(/CryptoUtil/i) and\n\t\tandroguard.activity(/Loader/i) and\n\t\tandroguard.activity(/Logger/i) and \n\t\tandroguard.permission(/android.permission.INTERNET/)) or\n\t\t\n\t\t//Certificate check based on @stevenchan''s comment\n\t\tandroguard.certificate.sha1(\"78F162D2CC7366754649A806CF17080682FE538C\") or\n\t\tandroguard.certificate.sha1(\"BBA26351CE41ACBE5FA84C9CF331D768CEDD768F\") or\n\t\tandroguard.certificate.sha1(\"0B7C3BC97B6D7C228F456304F5E1B75797B7265E\")\n",
        "raw_meta": "meta:\n\t\tdescription = \"Yara for variants of Trojan-Banker.AndroidOS.Tordow. Test rule\"\n\t\tsource = \"https://securelist.com/blog/mobile/76101/the-banker-that-can-steal-anything/\"\n\t\tauthor = \"https://twitter.com/5h1vang\"\n\n\t",
        "rule_name": "andr_tordow",
        "start_line": 13,
        "stop_line": 32
    }
]
');
INSERT INTO public.rule VALUES (default, 'Banker_Acecard', NULL, '{"author": "https://twitter.com/SadFud75", "samples_sha1": "ad9fff7fd019cf2a2684db650ea542fdeaaeaebb 53cca0a642d2f120dea289d4c7bd0d644a121252", "more_information": "https://threats.kaspersky.com/en/threat/Trojan-Banker.AndroidOS.Acecard/"}', '[
    {
        "condition_terms": [
            "(",
            "(",
            "androguard.package_name",
            "(",
            "\"starter.fl\"",
            ")",
            "and",
            "androguard.service",
            "(",
            "\"starter.CosmetiqFlServicesCallHeadlessSmsSendService\"",
            ")",
            ")",
            "or",
            "androguard.package_name",
            "(",
            "\"cosmetiq.fl\"",
            ")",
            "or",
            "all",
            "of",
            "(",
            "$str_*",
            ")",
            ")",
            "and",
            "androguard.permissions_number",
            ">",
            "19"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "https://twitter.com/SadFud75"
            },
            {
                "more_information": "https://threats.kaspersky.com/en/threat/Trojan-Banker.AndroidOS.Acecard/"
            },
            {
                "samples_sha1": "ad9fff7fd019cf2a2684db650ea542fdeaaeaebb 53cca0a642d2f120dea289d4c7bd0d644a121252"
            }
        ],
        "raw_condition": "condition:\n((androguard.package_name(\"starter.fl\") and androguard.service(\"starter.CosmetiqFlServicesCallHeadlessSmsSendService\")) or androguard.package_name(\"cosmetiq.fl\") or all of ($str_*)) and androguard.permissions_number > 19\n",
        "raw_meta": "meta:\nauthor = \"https://twitter.com/SadFud75\"\nmore_information = \"https://threats.kaspersky.com/en/threat/Trojan-Banker.AndroidOS.Acecard/\"\nsamples_sha1 = \"ad9fff7fd019cf2a2684db650ea542fdeaaeaebb 53cca0a642d2f120dea289d4c7bd0d644a121252\"\n",
        "raw_strings": "strings:\n$str_1 = \"Cardholder name\"\n$str_2 = \"instagram.php\"\n",
        "rule_name": "Banker_Acecard",
        "start_line": 12,
        "stop_line": 23,
        "strings": [
            {
                "name": "$str_1",
                "type": "text",
                "value": "Cardholder name"
            },
            {
                "name": "$str_2",
                "type": "text",
                "value": "instagram.php"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'android_tempting_cedar_spyware', NULL, '{"Date": "2018-03-06", "Author": "@X0RC1SM", "Reference": "https://blog.avast.com/avast-tracks-down-tempting-cedar-spyware"}', '[
    {
        "condition_terms": [
            "$PK_HEADER",
            "in",
            "(",
            "0",
            "..",
            "4",
            ")",
            "and",
            "$MANIFEST",
            "and",
            "$DEX_FILE",
            "and",
            "any",
            "of",
            "(",
            "$string*",
            ")"
        ],
        "metadata": [
            {
                "Author": "@X0RC1SM"
            },
            {
                "Date": "2018-03-06"
            },
            {
                "Reference": "https://blog.avast.com/avast-tracks-down-tempting-cedar-spyware"
            }
        ],
        "raw_condition": "condition:\n    \t$PK_HEADER in (0..4) and $MANIFEST and $DEX_FILE and any of ($string*)\n",
        "raw_meta": "meta:\n    \tAuthor = \"@X0RC1SM\"\n        Date = \"2018-03-06\"\n        Reference = \"https://blog.avast.com/avast-tracks-down-tempting-cedar-spyware\"\n\t",
        "raw_strings": "strings:\n\t\t$PK_HEADER = {50 4B 03 04}\n\t\t$MANIFEST = \"META-INF/MANIFEST.MF\"\n\t\t$DEX_FILE = \"classes.dex\"\n\t\t$string = \"rsdroid.crt\"\n\t\n\t",
        "rule_name": "android_tempting_cedar_spyware",
        "start_line": 1,
        "stop_line": 15,
        "strings": [
            {
                "name": "$PK_HEADER",
                "type": "byte",
                "value": "{50 4B 03 04}"
            },
            {
                "name": "$MANIFEST",
                "type": "text",
                "value": "META-INF/MANIFEST.MF"
            },
            {
                "name": "$DEX_FILE",
                "type": "text",
                "value": "classes.dex"
            },
            {
                "name": "$string",
                "type": "text",
                "value": "rsdroid.crt"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'xbot007', '{android}', '{"reference": "https://github.com/maldroid/maldrolyzer/blob/master/plugins/xbot007.py"}', '[
    {
        "condition_terms": [
            "any",
            "of",
            "them"
        ],
        "metadata": [
            {
                "reference": "https://github.com/maldroid/maldrolyzer/blob/master/plugins/xbot007.py"
            }
        ],
        "raw_condition": "condition:\n\t\tany of them\n",
        "raw_meta": "meta:\n\t\treference = \"https://github.com/maldroid/maldrolyzer/blob/master/plugins/xbot007.py\"\n\n\t",
        "raw_strings": "strings:\n\t\t$a = \"xbot007\"\n\n\t",
        "rule_name": "xbot007",
        "start_line": 6,
        "stop_line": 16,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "xbot007"
            }
        ],
        "tags": [
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'backdoor', '{dropper}', '{"author": "Antonio Sanchez <asanchez@koodous.com>", "sample": "0c3bc51952c71e5bb05c35346005da3baa098faf3911b9b45c3487844de9f539", "source": "https://koodous.com/rulesets/1765", "description": "This rule detects fake samples with a backdoor/dropper"}', '[
    {
        "condition_terms": [
            "androguard.url",
            "(",
            "\"http://sys.wksnkys7.com\"",
            ")",
            "or",
            "androguard.url",
            "(",
            "\"http://sys.hdyfhpoi.com\"",
            ")",
            "or",
            "androguard.url",
            "(",
            "\"http://sys.syllyq1n.com\"",
            ")",
            "or",
            "androguard.url",
            "(",
            "\"http://sys.aedxdrcb.com\"",
            ")",
            "or",
            "androguard.url",
            "(",
            "\"http://sys.aedxdrcb.com\"",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "Antonio Sanchez <asanchez@koodous.com>"
            },
            {
                "description": "This rule detects fake samples with a backdoor/dropper"
            },
            {
                "sample": "0c3bc51952c71e5bb05c35346005da3baa098faf3911b9b45c3487844de9f539"
            },
            {
                "source": "https://koodous.com/rulesets/1765"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.url(\"http://sys.wksnkys7.com\") \n\t\tor androguard.url(\"http://sys.hdyfhpoi.com\") \n\t\tor androguard.url(\"http://sys.syllyq1n.com\") \n\t\tor androguard.url(\"http://sys.aedxdrcb.com\")\n\t\tor androguard.url(\"http://sys.aedxdrcb.com\")\n",
        "raw_meta": "meta:\n\t\tauthor = \"Antonio Sanchez <asanchez@koodous.com>\"\n\t\tdescription = \"This rule detects fake samples with a backdoor/dropper\"\n\t\tsample = \"0c3bc51952c71e5bb05c35346005da3baa098faf3911b9b45c3487844de9f539\"\n\t\tsource = \"https://koodous.com/rulesets/1765\"\n\n\t",
        "rule_name": "backdoor",
        "start_line": 13,
        "stop_line": 27,
        "tags": [
            "dropper"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'finspy', '{cdshide,android}', '{"date": "2020/01/07", "author": "Thorsten Schröder - ths @ ccc.de (https://twitter.com/__ths__)", "sample": "c2ce202e6e08c41e8f7a0b15e7d0781704e17f8ed52d1b2ad7212ac29926436e", "reference1": "https://github.com/devio/FinSpy-Tools", "reference2": "https://github.com/Linuzifer/FinSpy-Dokumentation", "reference3": "https://www.ccc.de/de/updates/2019/finspy", "description": "Detect Gamma/FinFisher FinSpy for Android #GovWare"}', '[
    {
        "condition_terms": [
            "$re",
            "and",
            "(",
            "#re",
            ">",
            "50",
            ")"
        ],
        "metadata": [
            {
                "description": "Detect Gamma/FinFisher FinSpy for Android #GovWare"
            },
            {
                "date": "2020/01/07"
            },
            {
                "author": "Thorsten Schr\u00f6der - ths @ ccc.de (https://twitter.com/__ths__)"
            },
            {
                "reference1": "https://github.com/devio/FinSpy-Tools"
            },
            {
                "reference2": "https://github.com/Linuzifer/FinSpy-Dokumentation"
            },
            {
                "reference3": "https://www.ccc.de/de/updates/2019/finspy"
            },
            {
                "sample": "c2ce202e6e08c41e8f7a0b15e7d0781704e17f8ed52d1b2ad7212ac29926436e"
            }
        ],
        "raw_condition": "condition:\n\t\t$re and (#re > 50)\n",
        "raw_meta": "meta:\n\t\tdescription = \"Detect Gamma/FinFisher FinSpy for Android #GovWare\"\n\t\tdate = \"2020/01/07\"\n\t\tauthor = \"Thorsten Schr\u00f6der - ths @ ccc.de (https://twitter.com/__ths__)\"\n\t\treference1 = \"https://github.com/devio/FinSpy-Tools\"\n\t\treference2 = \"https://github.com/Linuzifer/FinSpy-Dokumentation\"\n\t\treference3 = \"https://www.ccc.de/de/updates/2019/finspy\"\n\t\tsample = \"c2ce202e6e08c41e8f7a0b15e7d0781704e17f8ed52d1b2ad7212ac29926436e\"\n\t\n\t",
        "raw_strings": "strings:\n\t\t$re = /\\x50\\x4B\\x01\\x02[\\x00-\\xff]{32}[A-Za-z0-9+\\/]{6}/\n\t\n\t",
        "rule_name": "finspy",
        "start_line": 4,
        "stop_line": 21,
        "strings": [
            {
                "name": "$re",
                "type": "regex",
                "value": "/\\x50\\x4B\\x01\\x02[\\x00-\\xff]{32}[A-Za-z0-9+\\/]{6}/"
            }
        ],
        "tags": [
            "cdshide",
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'adware', '{ads,android}', '{"author": "Fernando Denis Ramirez https://twitter.com/fdrg21", "sample": "5a331231f997decca388ba2d73b7dec1554e966a0795b0cb8447a336bdafd71b", "reference": "https://koodous.com/", "description": "Adware"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "(",
            "$string_*",
            ")"
        ],
        "metadata": [
            {
                "author": "Fernando Denis Ramirez https://twitter.com/fdrg21"
            },
            {
                "reference": "https://koodous.com/"
            },
            {
                "description": "Adware"
            },
            {
                "sample": "5a331231f997decca388ba2d73b7dec1554e966a0795b0cb8447a336bdafd71b"
            }
        ],
        "raw_condition": "condition:\n\t\tall of ($string_*)\n\t\t\n",
        "raw_meta": "meta:\n\t\tauthor = \"Fernando Denis Ramirez https://twitter.com/fdrg21\"\n\t\treference = \"https://koodous.com/\"\n\t\tdescription = \"Adware\"\n\t\tsample = \"5a331231f997decca388ba2d73b7dec1554e966a0795b0cb8447a336bdafd71b\"\n\n\t",
        "raw_strings": "strings:\n\t\t$string_a = \"banner_layout\"\n\t\t$string_b = \"activity_adpath_sms\"\n\t\t$string_c = \"adpath_title_one\"\n\t\t$string_d = \"7291-2ec9362bd699d0cd6f53a5ca6cd\"\n\n\t",
        "rule_name": "adware",
        "start_line": 5,
        "stop_line": 22,
        "strings": [
            {
                "name": "$string_a",
                "type": "text",
                "value": "banner_layout"
            },
            {
                "name": "$string_b",
                "type": "text",
                "value": "activity_adpath_sms"
            },
            {
                "name": "$string_c",
                "type": "text",
                "value": "adpath_title_one"
            },
            {
                "name": "$string_d",
                "type": "text",
                "value": "7291-2ec9362bd699d0cd6f53a5ca6cd"
            }
        ],
        "tags": [
            "ads",
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Android_pinkLocker', '{android}', '{"ref1": "https://www.virustotal.com/es/file/388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d/analysis/", "ref2": "https://analyst.koodous.com/rulesets/1186", "author": "@5h1vang", "sample": "388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d", "description": "Yara detection for Android Locker app named Pink Club"}', '[
    {
        "condition_terms": [
            "androguard.url",
            "(",
            "/lineout\\.pw/",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"D88B53449F6CAC93E65CA5E224A5EAD3E990921E\"",
            ")",
            "or",
            "androguard.permission",
            "(",
            "/android.permission.INTERNET/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.DISABLE_KEYGUARD/",
            ")",
            "and",
            "all",
            "of",
            "(",
            "$str_*",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "description": "Yara detection for Android Locker app named Pink Club"
            },
            {
                "author": "@5h1vang"
            },
            {
                "ref1": "https://www.virustotal.com/es/file/388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d/analysis/"
            },
            {
                "ref2": "https://analyst.koodous.com/rulesets/1186"
            },
            {
                "sample": "388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.url(/lineout\\.pw/) or \n\t\tandroguard.certificate.sha1(\"D88B53449F6CAC93E65CA5E224A5EAD3E990921E\") or\n\t\tandroguard.permission(/android.permission.INTERNET/) and\n\t\tandroguard.permission(/android.permission.DISABLE_KEYGUARD/) and\n\t\tall of ($str_*)\n\t\t\n",
        "raw_meta": "meta:\n\t\tdescription = \"Yara detection for Android Locker app named Pink Club\"\n\t\tauthor = \"@5h1vang\"\n\t\tref1 = \"https://www.virustotal.com/es/file/388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d/analysis/\"\n\t\tref2 = \"https://analyst.koodous.com/rulesets/1186\"\n\t\tsample = \"388799cbbe2c8ddc0768c4b994379508e602f68503888a001635c3be2c8c350d\"\n\t\t\n\t",
        "raw_strings": "strings:\n\t\t$str_1 = \"arnrsiec sisani\"\n\t\t$str_2 = \"rhguecisoijng ts\"\n\t\t$str_3 = \"assets/data.db\"\n\t\t$str_4 = \"res/xml/device_admin_sample.xmlPK\" \n\n\t",
        "rule_name": "Android_pinkLocker",
        "start_line": 12,
        "stop_line": 34,
        "strings": [
            {
                "name": "$str_1",
                "type": "text",
                "value": "arnrsiec sisani"
            },
            {
                "name": "$str_2",
                "type": "text",
                "value": "rhguecisoijng ts"
            },
            {
                "name": "$str_3",
                "type": "text",
                "value": "assets/data.db"
            },
            {
                "name": "$str_4",
                "type": "text",
                "value": "res/xml/device_admin_sample.xmlPK"
            }
        ],
        "tags": [
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'android_overlayer', NULL, '{"author": "https://twitter.com/5h1vang", "source": "https://www.zscaler.com/blogs/research/android-banker-malware-goes-social", "description": "This rule detects the banker trojan with overlaying functionality"}', '[
    {
        "condition_terms": [
            "androguard.certificate.sha1",
            "(",
            "\"6994ED892E7F0019BCA74B5847C6D5113391D127\"",
            ")",
            "or",
            "(",
            "androguard.permission",
            "(",
            "/android.permission.INTERNET/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.READ_SMS/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.READ_PHONE_STATE/",
            ")",
            "and",
            "all",
            "of",
            "(",
            "$str_*",
            ")",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "description": "This rule detects the banker trojan with overlaying functionality"
            },
            {
                "source": "https://www.zscaler.com/blogs/research/android-banker-malware-goes-social"
            },
            {
                "author": "https://twitter.com/5h1vang"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.certificate.sha1(\"6994ED892E7F0019BCA74B5847C6D5113391D127\") or \n\t\t\n\t\t(androguard.permission(/android.permission.INTERNET/) and\n\t\tandroguard.permission(/android.permission.READ_SMS/) and\n\t\tandroguard.permission(/android.permission.READ_PHONE_STATE/) and \n\t\tall of ($str_*))\n",
        "raw_meta": "meta:\n\t\tdescription = \"This rule detects the banker trojan with overlaying functionality\"\n\t\tsource =  \"https://www.zscaler.com/blogs/research/android-banker-malware-goes-social\"\n\t\tauthor = \"https://twitter.com/5h1vang\"\n\n\t",
        "raw_strings": "strings:\n\t\t$str_1 = \"tel:\"\n\t\t$str_2 = \"lockNow\" nocase\n\t\t$str_3 = \"android.app.action.ADD_DEVICE_ADMIN\"\n\t\t$str_4 = \"Cmd_conf\" nocase\n\t\t$str_5 = \"Sms_conf\" nocase\n\t\t$str_6 = \"filter2\" \n\n\t",
        "rule_name": "android_overlayer",
        "start_line": 8,
        "stop_line": 30,
        "strings": [
            {
                "name": "$str_1",
                "type": "text",
                "value": "tel:"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$str_2",
                "type": "text",
                "value": "lockNow"
            },
            {
                "name": "$str_3",
                "type": "text",
                "value": "android.app.action.ADD_DEVICE_ADMIN"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$str_4",
                "type": "text",
                "value": "Cmd_conf"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$str_5",
                "type": "text",
                "value": "Sms_conf"
            },
            {
                "name": "$str_6",
                "type": "text",
                "value": "filter2"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'SlemBunk', '{android}', '{"author": "@plutec_net", "sample": "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b", "source": "https://www.fireeye.com/blog/threat-research/2015/12/slembunk_an_evolvin.html", "description": "Rule to detect trojans imitating banks of North America, Eurpope and Asia"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Rule to detect trojans imitating banks of North America, Eurpope and Asia"
            },
            {
                "author": "@plutec_net"
            },
            {
                "sample": "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
            },
            {
                "source": "https://www.fireeye.com/blog/threat-research/2015/12/slembunk_an_evolvin.html"
            }
        ],
        "raw_condition": "condition:\n\t\tall of them\n\t\t\n",
        "raw_meta": "meta:\n\t\tdescription = \"Rule to detect trojans imitating banks of North America, Eurpope and Asia\"\n\t\tauthor = \"@plutec_net\"\n\t\tsample = \"e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b\"\n\t\tsource = \"https://www.fireeye.com/blog/threat-research/2015/12/slembunk_an_evolvin.html\"\n\n\t",
        "raw_strings": "strings:\n\t\t$a = \"#intercept_sms_start\"\n\t\t$b = \"#intercept_sms_stop\"\n\t\t$c = \"#block_numbers\"\n\t\t$d = \"#wipe_data\"\n\t\t$e = \"Visa Electron\"\n\n\t",
        "rule_name": "SlemBunk",
        "start_line": 6,
        "stop_line": 24,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "#intercept_sms_start"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "#intercept_sms_stop"
            },
            {
                "name": "$c",
                "type": "text",
                "value": "#block_numbers"
            },
            {
                "name": "$d",
                "type": "text",
                "value": "#wipe_data"
            },
            {
                "name": "$e",
                "type": "text",
                "value": "Visa Electron"
            }
        ],
        "tags": [
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Android_Switcher', NULL, '{"author": "https://twitter.com/5h1vang", "sample": "d3aee0e8fa264a33f77bdd59d95759de8f6d4ed6790726e191e39bcfd7b5e150", "source": "https://securelist.com/blog/mobile/76969/switcher-android-joins-the-attack-the-router-club/", "source2": "https://koodous.com/rulesets/2049", "description": "This rule detects Android wifi Switcher variants"}', '[
    {
        "condition_terms": [
            "androguard.certificate.sha1",
            "(",
            "\"2421686AE7D976D19AB72DA1BDE273C537D2D4F9\"",
            ")",
            "or",
            "(",
            "androguard.permission",
            "(",
            "/android.permission.INTERNET/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.ACCESS_WIFI_STATE/",
            ")",
            "and",
            "(",
            "$dns_2",
            "or",
            "$dns_3",
            "or",
            "$dns_4",
            ")",
            "and",
            "all",
            "of",
            "(",
            "$str_*",
            ")",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "description": "This rule detects Android wifi Switcher variants"
            },
            {
                "sample": "d3aee0e8fa264a33f77bdd59d95759de8f6d4ed6790726e191e39bcfd7b5e150"
            },
            {
                "source": "https://securelist.com/blog/mobile/76969/switcher-android-joins-the-attack-the-router-club/"
            },
            {
                "source2": "https://koodous.com/rulesets/2049"
            },
            {
                "author": "https://twitter.com/5h1vang"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.certificate.sha1(\"2421686AE7D976D19AB72DA1BDE273C537D2D4F9\") or \n\t\t(androguard.permission(/android.permission.INTERNET/) and\n\t\tandroguard.permission(/android.permission.ACCESS_WIFI_STATE/) and \n\t\t($dns_2 or $dns_3 or $dns_4) and all of ($str_*))\n",
        "raw_meta": "meta:\n\t\tdescription = \"This rule detects Android wifi Switcher variants\"\n\t\tsample = \"d3aee0e8fa264a33f77bdd59d95759de8f6d4ed6790726e191e39bcfd7b5e150\"\n\t\tsource = \"https://securelist.com/blog/mobile/76969/switcher-android-joins-the-attack-the-router-club/\"\n    source2 = \"https://koodous.com/rulesets/2049\"\n    author = \"https://twitter.com/5h1vang\"\n\n\t",
        "raw_strings": "strings:\n\t\t$str_1 = \"javascript:scrollTo\"\t\t\n\t\t$str_5 = \"javascript:document.getElementById(''dns1'')\"\n\t\t$str_6 = \"admin:\"\n\n\t\t$dns_2 = \"101.200.147.153\"\n\t\t$dns_3 = \"112.33.13.11\"\n\t\t$dns_4 = \"120.76.249.59\"\n\n\n\t",
        "rule_name": "Android_Switcher",
        "start_line": 14,
        "stop_line": 38,
        "strings": [
            {
                "name": "$str_1",
                "type": "text",
                "value": "javascript:scrollTo"
            },
            {
                "name": "$str_5",
                "type": "text",
                "value": "javascript:document.getElementById(''dns1'')"
            },
            {
                "name": "$str_6",
                "type": "text",
                "value": "admin:"
            },
            {
                "name": "$dns_2",
                "type": "text",
                "value": "101.200.147.153"
            },
            {
                "name": "$dns_3",
                "type": "text",
                "value": "112.33.13.11"
            },
            {
                "name": "$dns_4",
                "type": "text",
                "value": "120.76.249.59"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Android_AliPay_smsStealer', '{android}', '{"ref": "https://analyst.koodous.com/rulesets/1192", "author": "https://twitter.com/5h1vang", "sample": "f4794dd02d35d4ea95c51d23ba182675cc3528f42f4fa9f50e2d245c08ecf06b", "source": "http://research.zscaler.com/2016/02/fake-security-app-for-alipay-customers.html", "description": "Yara rule for detection of Fake AliPay Sms Stealer"}', '[
    {
        "condition_terms": [
            "androguard.certificate.sha1",
            "(",
            "\"0CDFC700D0BDDC3EA50D71B54594BF3711D0F5B2\"",
            ")",
            "or",
            "androguard.permission",
            "(",
            "/android.permission.RECEIVE_SMS/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.INTERNET/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.RECEIVE_BOOT_COMPLETED/",
            ")",
            "and",
            "all",
            "of",
            "(",
            "$str_*",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "description": "Yara rule for detection of Fake AliPay Sms Stealer"
            },
            {
                "sample": "f4794dd02d35d4ea95c51d23ba182675cc3528f42f4fa9f50e2d245c08ecf06b"
            },
            {
                "source": "http://research.zscaler.com/2016/02/fake-security-app-for-alipay-customers.html"
            },
            {
                "ref": "https://analyst.koodous.com/rulesets/1192"
            },
            {
                "author": "https://twitter.com/5h1vang"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.certificate.sha1(\"0CDFC700D0BDDC3EA50D71B54594BF3711D0F5B2\") or\n\t\tandroguard.permission(/android.permission.RECEIVE_SMS/) and\n\t\tandroguard.permission(/android.permission.INTERNET/) and\n\t\tandroguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and \t\t\n\t\tall of ($str_*)\n",
        "raw_meta": "meta:\n\t\tdescription = \"Yara rule for detection of Fake AliPay Sms Stealer\"\n\t\tsample = \"f4794dd02d35d4ea95c51d23ba182675cc3528f42f4fa9f50e2d245c08ecf06b\"\n\t\tsource = \"http://research.zscaler.com/2016/02/fake-security-app-for-alipay-customers.html\"\n\t\tref = \"https://analyst.koodous.com/rulesets/1192\"\n\t\tauthor = \"https://twitter.com/5h1vang\"\n\n\t",
        "raw_strings": "strings:\n\t\t$str_1 = \"START_SERVICE\"\n\t\t$str_2 = \"extra_key_sms\"\n\t\t$str_3 = \"android.provider.Telephony.SMS_RECEIVED\"\n\t\t$str_4 = \"mPhoneNumber\"\n\n\t",
        "rule_name": "Android_AliPay_smsStealer",
        "start_line": 13,
        "stop_line": 34,
        "strings": [
            {
                "name": "$str_1",
                "type": "text",
                "value": "START_SERVICE"
            },
            {
                "name": "$str_2",
                "type": "text",
                "value": "extra_key_sms"
            },
            {
                "name": "$str_3",
                "type": "text",
                "value": "android.provider.Telephony.SMS_RECEIVED"
            },
            {
                "name": "$str_4",
                "type": "text",
                "value": "mPhoneNumber"
            }
        ],
        "tags": [
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Trojan_Droidjack', NULL, '{"author": "https://twitter.com/SadFud75"}', '[
    {
        "condition_terms": [
            "androguard.package_name",
            "(",
            "\"net.droidjack.server\"",
            ")",
            "or",
            "androguard.activity",
            "(",
            "/net.droidjack.server/i",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "https://twitter.com/SadFud75"
            }
        ],
        "raw_condition": "condition:\nandroguard.package_name(\"net.droidjack.server\") or androguard.activity(/net.droidjack.server/i)\n",
        "raw_meta": "meta:\nauthor = \"https://twitter.com/SadFud75\"\n",
        "rule_name": "Trojan_Droidjack",
        "start_line": 13,
        "stop_line": 19
    }
]
');
INSERT INTO public.rule VALUES (default, 'Android_DeathRing', NULL, '{"date": "06-June-2016", "author": "Jacob Soo Lead Re", "source": "https://blog.lookout.com/blog/2014/12/04/deathring/", "description": "DeathRing is a Chinese Trojan that is pre-installed on a number of smartphones most popular in Asian and African countries. Detection volumes are moderate, though we consider this a concerning threat given its pre-loaded nature and the fact that we are actively seeing detections of it around the world."}', '[
    {
        "condition_terms": [
            "androguard.service",
            "(",
            "/MainOsService/i",
            ")",
            "and",
            "androguard.receiver",
            "(",
            "/ApkUninstallReceiver/i",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "Jacob Soo Lead Re"
            },
            {
                "date": "06-June-2016"
            },
            {
                "description": "DeathRing is a Chinese Trojan that is pre-installed on a number of smartphones most popular in Asian and African countries. Detection volumes are moderate, though we consider this a concerning threat given its pre-loaded nature and the fact that we are actively seeing detections of it around the world."
            },
            {
                "source": "https://blog.lookout.com/blog/2014/12/04/deathring/"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.service(/MainOsService/i) and\n        androguard.receiver(/ApkUninstallReceiver/i)\n",
        "raw_meta": "meta:\n\t\tauthor = \"Jacob Soo Lead Re\"\n\t\tdate = \"06-June-2016\"\n\t\tdescription = \"DeathRing is a Chinese Trojan that is pre-installed on a number of smartphones most popular in Asian and African countries. Detection volumes are moderate, though we consider this a concerning threat given its pre-loaded nature and the fact that we are actively seeing detections of it around the world.\"\n\t\tsource = \"https://blog.lookout.com/blog/2014/12/04/deathring/\"\n\n\t",
        "rule_name": "Android_DeathRing",
        "start_line": 3,
        "stop_line": 14
    }
]
');
INSERT INTO public.rule VALUES (default, 'SpyNet', '{malware}', '{"sample": "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b", "description": "Ruleset to detect SpyNetV2 samples. "}', '[
    {
        "condition_terms": [
            "4",
            "of",
            "them"
        ],
        "metadata": [
            {
                "description": "Ruleset to detect SpyNetV2 samples. "
            },
            {
                "sample": "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"
            }
        ],
        "raw_condition": "condition:\n\t\t4 of them \n",
        "raw_meta": "meta:\n\t\tdescription = \"Ruleset to detect SpyNetV2 samples. \"\n\t\tsample = \"e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b\"\n\n\t",
        "raw_strings": "strings:\n\t$a = \"odNotice.txt\"\n\t$b = \"camera This device has camera!\"\n\t$c = \"camera This device has Nooo camera!\"\n\t$d = \"send|1sBdBBbbBBF|K|\"\n\t$e = \"send|372|ScreamSMS|senssd\"\n\t$f = \"send|5ms5gs5annc\"\n\t$g = \"send|45CLCLCa01\"\n\t$h = \"send|999SAnd|TimeStart\"\n\t$i = \"!s!c!r!e!a!m!\"\n\t",
        "rule_name": "SpyNet",
        "start_line": 6,
        "stop_line": 24,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "odNotice.txt"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "camera This device has camera!"
            },
            {
                "name": "$c",
                "type": "text",
                "value": "camera This device has Nooo camera!"
            },
            {
                "name": "$d",
                "type": "text",
                "value": "send|1sBdBBbbBBF|K|"
            },
            {
                "name": "$e",
                "type": "text",
                "value": "send|372|ScreamSMS|senssd"
            },
            {
                "name": "$f",
                "type": "text",
                "value": "send|5ms5gs5annc"
            },
            {
                "name": "$g",
                "type": "text",
                "value": "send|45CLCLCa01"
            },
            {
                "name": "$h",
                "type": "text",
                "value": "send|999SAnd|TimeStart"
            },
            {
                "name": "$i",
                "type": "text",
                "value": "!s!c!r!e!a!m!"
            }
        ],
        "tags": [
            "malware"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'hacking_team', '{stcert,android}', '{"author": "Fernando Denis https://twitter.com/fdrg21", "samples": "c605df5dbb9d9fb1d687d59e4d90eba55b3201f8dd4fa51ec80aa3780d6e3e6e", "reference": "https://koodous.com/", "description": "This rule detects the apk related to hackingteam - These certificates are presents in mailboxes od hackingteam"}', '[
    {
        "comments": [
            "//B8D5E3F0BCAD2EB03BB34AEE2B3F63FC5162C56B this certification could be stolen",
            "//03EA873D5D13707B0C278A0055E452416054E27B this certification could be stolen",
            "//97257C6D8F6DA60EA27D2388D9AE252657FF3304 this certification could be stolen"
        ],
        "condition_terms": [
            "(",
            "any",
            "of",
            "(",
            "$string_a_*",
            ")",
            "and",
            "any",
            "of",
            "(",
            "$string_b_*",
            ")",
            "and",
            "$string_c",
            "and",
            "$string_d",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"B1BC968BD4F49D622AA89A81F2150152A41D829C\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"3FEC88BA49773680E2A3040483806F56E6E8502E\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"B0A4A4880FA5345D6B3B00C0C588A39815D3872E\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"EC2184676D4AE153E63987326666BA0C554A4A60\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"A7394CBAB09D35C69DA7FABB1A7870BE987A5F77\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"A1131C7F816D65670567D6C7041F30E380754022\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"4E40663CC29C1FE7A436810C79CAB8F52474133B\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"159B4F6C03D43F27339E06ABFD2DE8D8D65516BC\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"3EEE4E45B174405D64F877EFC7E5905DCCD73816\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"9CE815802A672B75C078D920A5D506BBBAC0D5C9\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"C4CF31DBEF79393FD2AD617E79C27BFCF19EFBB3\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"2125821BC97CF4B7591E5C771C06C9C96D24DF8F\"",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "Fernando Denis https://twitter.com/fdrg21"
            },
            {
                "reference": "https://koodous.com/"
            },
            {
                "description": "This rule detects the apk related to hackingteam - These certificates are presents in mailboxes od hackingteam"
            },
            {
                "samples": "c605df5dbb9d9fb1d687d59e4d90eba55b3201f8dd4fa51ec80aa3780d6e3e6e"
            }
        ],
        "raw_condition": "condition:\n\t\t(any of ($string_a_*) and any of ($string_b_*) and $string_c and $string_d) or\n\t\tandroguard.certificate.sha1(\"B1BC968BD4F49D622AA89A81F2150152A41D829C\") or \t  \n\t\tandroguard.certificate.sha1(\"3FEC88BA49773680E2A3040483806F56E6E8502E\") or \n\t\tandroguard.certificate.sha1(\"B0A4A4880FA5345D6B3B00C0C588A39815D3872E\") or \n\t\tandroguard.certificate.sha1(\"EC2184676D4AE153E63987326666BA0C554A4A60\") or \n\t\tandroguard.certificate.sha1(\"A7394CBAB09D35C69DA7FABB1A7870BE987A5F77\")\tor\n\t\tandroguard.certificate.sha1(\"A1131C7F816D65670567D6C7041F30E380754022\") or\n\t\tandroguard.certificate.sha1(\"4E40663CC29C1FE7A436810C79CAB8F52474133B\") or\n\t\tandroguard.certificate.sha1(\"159B4F6C03D43F27339E06ABFD2DE8D8D65516BC\") or\n\t\tandroguard.certificate.sha1(\"3EEE4E45B174405D64F877EFC7E5905DCCD73816\") or\n\t\tandroguard.certificate.sha1(\"9CE815802A672B75C078D920A5D506BBBAC0D5C9\") or\n\t\tandroguard.certificate.sha1(\"C4CF31DBEF79393FD2AD617E79C27BFCF19EFBB3\") or\n\t\tandroguard.certificate.sha1(\"2125821BC97CF4B7591E5C771C06C9C96D24DF8F\")\n\t\t//97257C6D8F6DA60EA27D2388D9AE252657FF3304 this certification could be stolen\n\t\t//03EA873D5D13707B0C278A0055E452416054E27B this certification could be stolen\n\t\t//B8D5E3F0BCAD2EB03BB34AEE2B3F63FC5162C56B this certification could be stolen\n",
        "raw_meta": "meta:\n\t\tauthor = \"Fernando Denis https://twitter.com/fdrg21\"\n\t\treference = \"https://koodous.com/\"\n\t\tdescription = \"This rule detects the apk related to hackingteam - These certificates are presents in mailboxes od hackingteam\"\n\t\tsamples = \"c605df5dbb9d9fb1d687d59e4d90eba55b3201f8dd4fa51ec80aa3780d6e3e6e\"\n\n\t",
        "raw_strings": "strings:\n\t\t$string_a_1 = \"280128120000Z0W1\"\n\t\t$string_a_2 = \"E6FFF4C5062FBDC9\"\n\t\t$string_a_3 = \"886FEC93A75D2AC1\"\n\t\t$string_a_4 = \"121120104150Z\"\n\t\t\n\t\t$string_b_1 = \"&inbox_timestamp > 0 and is_permanent=1\"\n\t\t$string_b_2 = \"contact_id = ? AND mimetype = ?\"\n\t\t\n\t\t$string_c = \"863d9effe70187254d3c5e9c76613a99\"\n\t\t\n\t\t$string_d = \"nv-sa1\"\n\n\t",
        "rule_name": "hacking_team",
        "start_line": 13,
        "stop_line": 51,
        "strings": [
            {
                "name": "$string_a_1",
                "type": "text",
                "value": "280128120000Z0W1"
            },
            {
                "name": "$string_a_2",
                "type": "text",
                "value": "E6FFF4C5062FBDC9"
            },
            {
                "name": "$string_a_3",
                "type": "text",
                "value": "886FEC93A75D2AC1"
            },
            {
                "name": "$string_a_4",
                "type": "text",
                "value": "121120104150Z"
            },
            {
                "name": "$string_b_1",
                "type": "text",
                "value": "&inbox_timestamp > 0 and is_permanent=1"
            },
            {
                "name": "$string_b_2",
                "type": "text",
                "value": "contact_id = ? AND mimetype = ?"
            },
            {
                "name": "$string_c",
                "type": "text",
                "value": "863d9effe70187254d3c5e9c76613a99"
            },
            {
                "name": "$string_d",
                "type": "text",
                "value": "nv-sa1"
            }
        ],
        "tags": [
            "stcert",
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'spyAgent', NULL, '{"author": "@koodous_project", "sample": "7cbf61fbb31c26530cafb46282f5c90bc10fe5c724442b8d1a0b87a8125204cb", "reference": "https://blogs.mcafee.com/mcafee-labs/android-spyware-targets-security-job-seekers-in-saudi-arabia/", "description": "This rule detects arabian spyware which records call and gathers user information which is later sent to a remote c&c"}', '[
    {
        "condition_terms": [
            "androguard.url",
            "(",
            "/ksa-sef\\.com/",
            ")",
            "or",
            "(",
            "$phone",
            "and",
            "$caption",
            ")",
            "or",
            "(",
            "$cc",
            "and",
            "$cc_alt",
            "and",
            "$cc_alt2",
            "and",
            "$cc_alt3",
            "and",
            "$cc_alt4",
            "and",
            "$cc_alt5",
            "and",
            "$cc_alt6",
            "and",
            "$cc_alt7",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "description": "This rule detects arabian spyware which records call and gathers user information which is later sent to a remote c&c"
            },
            {
                "sample": "7cbf61fbb31c26530cafb46282f5c90bc10fe5c724442b8d1a0b87a8125204cb"
            },
            {
                "reference": "https://blogs.mcafee.com/mcafee-labs/android-spyware-targets-security-job-seekers-in-saudi-arabia/"
            },
            {
                "author": "@koodous_project"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.url(/ksa-sef\\.com/) or ($phone and $caption) or ($cc and $cc_alt and $cc_alt2 and $cc_alt3 and $cc_alt4 and $cc_alt5 and $cc_alt6 and $cc_alt7)\n\t\t\n",
        "raw_meta": "meta:\n\t\tdescription = \"This rule detects arabian spyware which records call and gathers user information which is later sent to a remote c&c\"\n\t\tsample = \"7cbf61fbb31c26530cafb46282f5c90bc10fe5c724442b8d1a0b87a8125204cb\"\n\t\treference = \"https://blogs.mcafee.com/mcafee-labs/android-spyware-targets-security-job-seekers-in-saudi-arabia/\"\n\t\tauthor = \"@koodous_project\"\n\n\t",
        "raw_strings": "strings:\n\t\t$phone = \"0597794205\"\n\t\t$caption = \"New victim arrived\"\n\t\t$cc = \"http://ksa-sef.com/Hack%20Mobaile/ADDNewSMS.php\"\n\t\t$cc_alt = \"http://ksa-sef.com/Hack%20Mobaile/AddAllLogCall.php\"\n\t\t$cc_alt2= \"http://ksa-sef.com/Hack%20Mobaile/addScreenShot.php\"\n\t\t$cc_alt3= \"http://ksa-sef.com/Hack%20Mobaile/ADDSMS.php\"\n\t\t$cc_alt4 = \"http://ksa-sef.com/Hack%20Mobaile/ADDVCF.php\"\n\t\t$cc_alt5 = \"http://ksa-sef.com/Hack%20Mobaile/ADDIMSI.php\"\n\t\t$cc_alt6 = \"http://ksa-sef.com/Hack%20Mobaile/ADDHISTORYINTERNET.php\"\n\t\t$cc_alt7 = \"http://ksa-sef.com/Hack%20Mobaile/addInconingLogs.php\"\n\n\t",
        "rule_name": "spyAgent",
        "start_line": 9,
        "stop_line": 32,
        "strings": [
            {
                "name": "$phone",
                "type": "text",
                "value": "0597794205"
            },
            {
                "name": "$caption",
                "type": "text",
                "value": "New victim arrived"
            },
            {
                "name": "$cc",
                "type": "text",
                "value": "http://ksa-sef.com/Hack%20Mobaile/ADDNewSMS.php"
            },
            {
                "name": "$cc_alt",
                "type": "text",
                "value": "http://ksa-sef.com/Hack%20Mobaile/AddAllLogCall.php"
            },
            {
                "name": "$cc_alt2",
                "type": "text",
                "value": "http://ksa-sef.com/Hack%20Mobaile/addScreenShot.php"
            },
            {
                "name": "$cc_alt3",
                "type": "text",
                "value": "http://ksa-sef.com/Hack%20Mobaile/ADDSMS.php"
            },
            {
                "name": "$cc_alt4",
                "type": "text",
                "value": "http://ksa-sef.com/Hack%20Mobaile/ADDVCF.php"
            },
            {
                "name": "$cc_alt5",
                "type": "text",
                "value": "http://ksa-sef.com/Hack%20Mobaile/ADDIMSI.php"
            },
            {
                "name": "$cc_alt6",
                "type": "text",
                "value": "http://ksa-sef.com/Hack%20Mobaile/ADDHISTORYINTERNET.php"
            },
            {
                "name": "$cc_alt7",
                "type": "text",
                "value": "http://ksa-sef.com/Hack%20Mobaile/addInconingLogs.php"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'moscow_fake', '{banker,androoid}', '{"author": "Fernando Denis", "reference": "https://koodous.com/ https://twitter.com/fdrg21", "description": "Moskow Droid Development", "in_the_wild": true, "thread_level": 3}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "(",
            "$string_*",
            ")"
        ],
        "metadata": [
            {
                "author": "Fernando Denis"
            },
            {
                "reference": "https://koodous.com/ https://twitter.com/fdrg21"
            },
            {
                "description": "Moskow Droid Development"
            },
            {
                "thread_level": 3
            },
            {
                "in_the_wild": true
            }
        ],
        "raw_condition": "condition:\n\t\tall of ($string_*)\n",
        "raw_meta": "meta:\n\t  author = \"Fernando Denis\"\n\t\treference = \"https://koodous.com/ https://twitter.com/fdrg21\"\n\t\tdescription = \"Moskow Droid Development\"\n\t\tthread_level = 3\n\t\tin_the_wild = true\n\n\t",
        "raw_strings": "strings:\n\t\t$string_a = \"%ioperator%\"\n\t\t$string_b = \"%imodel%\"\n\t\t$string_c = \"%ideviceid%\"\n\t\t$string_d = \"%ipackname%\"\n\t\t$string_e = \"VILLLLLL\"\n\n\t",
        "rule_name": "moscow_fake",
        "start_line": 9,
        "stop_line": 27,
        "strings": [
            {
                "name": "$string_a",
                "type": "text",
                "value": "%ioperator%"
            },
            {
                "name": "$string_b",
                "type": "text",
                "value": "%imodel%"
            },
            {
                "name": "$string_c",
                "type": "text",
                "value": "%ideviceid%"
            },
            {
                "name": "$string_d",
                "type": "text",
                "value": "%ipackname%"
            },
            {
                "name": "$string_e",
                "type": "text",
                "value": "VILLLLLL"
            }
        ],
        "tags": [
            "banker",
            "androoid"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'assd_developer', '{official,android}', '{"author": "Fernando Denis Ramirez https://twitter.com/fdrg21", "sample": "cb9721c524f155478e9402d213e240b9f99eaba86fcbce0571cd7da4e258a79e", "reference": "https://koodous.com/", "description": "This rule detects apks fom ASSD developer"}', '[
    {
        "condition_terms": [
            "androguard.certificate.sha1",
            "(",
            "\"ED9A1CE1F18A1097DCCC5C0CB005E3861DA9C34A\"",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "Fernando Denis Ramirez https://twitter.com/fdrg21"
            },
            {
                "reference": "https://koodous.com/"
            },
            {
                "description": "This rule detects apks fom ASSD developer"
            },
            {
                "sample": "cb9721c524f155478e9402d213e240b9f99eaba86fcbce0571cd7da4e258a79e"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.certificate.sha1(\"ED9A1CE1F18A1097DCCC5C0CB005E3861DA9C34A\")\n\t\t\n",
        "raw_meta": "meta:\n\t\tauthor = \"Fernando Denis Ramirez https://twitter.com/fdrg21\"\n\t\treference = \"https://koodous.com/\"\n\t\tdescription = \"This rule detects apks fom ASSD developer\"\n\t\tsample = \"cb9721c524f155478e9402d213e240b9f99eaba86fcbce0571cd7da4e258a79e\"\n\n\t",
        "rule_name": "assd_developer",
        "start_line": 13,
        "stop_line": 24,
        "tags": [
            "official",
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'spynote_variants', NULL, '{"author": "5h1vang https://analyst.koodous.com/analysts/5h1vang", "source": " http://researchcenter.paloaltonetworks.com/2016/07/unit42-spynote-android-trojan-builder-leaked/", "description": "Yara rule for detection of different Spynote Variants", "rule_source": "https://analyst.koodous.com/rulesets/1710"}', '[
    {
        "condition_terms": [
            "androguard.package_name",
            "(",
            "\"dell.scream.application\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"219D542F901D8DB85C729B0F7AE32410096077CB\"",
            ")",
            "or",
            "all",
            "of",
            "(",
            "$str_*",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "5h1vang https://analyst.koodous.com/analysts/5h1vang"
            },
            {
                "description": "Yara rule for detection of different Spynote Variants"
            },
            {
                "source": " http://researchcenter.paloaltonetworks.com/2016/07/unit42-spynote-android-trojan-builder-leaked/"
            },
            {
                "rule_source": "https://analyst.koodous.com/rulesets/1710"
            }
        ],
        "raw_condition": "condition:\n        androguard.package_name(\"dell.scream.application\") or \n        androguard.certificate.sha1(\"219D542F901D8DB85C729B0F7AE32410096077CB\") or\n        all of ($str_*)\n",
        "raw_meta": "meta:\n        author = \"5h1vang https://analyst.koodous.com/analysts/5h1vang\"\n        description = \"Yara rule for detection of different Spynote Variants\"\n        source = \" http://researchcenter.paloaltonetworks.com/2016/07/unit42-spynote-android-trojan-builder-leaked/\"\n        rule_source = \"https://analyst.koodous.com/rulesets/1710\"\n\n    ",
        "raw_strings": "strings:\n        $str_1 = \"SERVER_IP\" nocase\n        $str_2 = \"SERVER_NAME\" nocase\n        $str_3 = \"content://sms/inbox\"\n        $str_4 = \"screamHacker\" \n        $str_5 = \"screamon\"\n    ",
        "rule_name": "spynote_variants",
        "start_line": 14,
        "stop_line": 32,
        "strings": [
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$str_1",
                "type": "text",
                "value": "SERVER_IP"
            },
            {
                "modifiers": [
                    "nocase"
                ],
                "name": "$str_2",
                "type": "text",
                "value": "SERVER_NAME"
            },
            {
                "name": "$str_3",
                "type": "text",
                "value": "content://sms/inbox"
            },
            {
                "name": "$str_4",
                "type": "text",
                "value": "screamHacker"
            },
            {
                "name": "$str_5",
                "type": "text",
                "value": "screamon"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'android_spywaller', '{android}', '{"sample": "7b31656b9722f288339cb2416557241cfdf69298a749e49f07f912aeb1e5931b", "source": "http://blog.fortinet.com/post/android-spywaller-firewall-style-antivirus-blocking", "description": "Rule for detection of Android Spywaller samples"}', '[
    {
        "condition_terms": [
            "androguard.certificate.sha1",
            "(",
            "\"165F84B05BD33DA1BA0A8E027CEF6026B7005978\"",
            ")",
            "or",
            "androguard.permission",
            "(",
            "/android.permission.INTERNET/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.READ_PHONE_STATE/",
            ")",
            "and",
            "all",
            "of",
            "(",
            "$str_*",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "description": "Rule for detection of Android Spywaller samples"
            },
            {
                "sample": "7b31656b9722f288339cb2416557241cfdf69298a749e49f07f912aeb1e5931b"
            },
            {
                "source": "http://blog.fortinet.com/post/android-spywaller-firewall-style-antivirus-blocking"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.certificate.sha1(\"165F84B05BD33DA1BA0A8E027CEF6026B7005978\") or\n\t\tandroguard.permission(/android.permission.INTERNET/) and\n\t\tandroguard.permission(/android.permission.READ_PHONE_STATE/) and \n\t\tall of ($str_*)\n",
        "raw_meta": "meta:\n\t\tdescription = \"Rule for detection of Android Spywaller samples\"\n\t\tsample = \"7b31656b9722f288339cb2416557241cfdf69298a749e49f07f912aeb1e5931b\"\n\t\tsource = \"http://blog.fortinet.com/post/android-spywaller-firewall-style-antivirus-blocking\"\n\n\t",
        "raw_strings": "strings:\n\t\t$str_1 = \"droid.png\"\n\t\t$str_2 = \"getSrvAddr\"\n\t\t$str_3 = \"getSrvPort\"\t\t\n\t\t$str_4 = \"android.intent.action.START_GOOGLE_SERVICE\"\n\n\t",
        "rule_name": "android_spywaller",
        "start_line": 13,
        "stop_line": 31,
        "strings": [
            {
                "name": "$str_1",
                "type": "text",
                "value": "droid.png"
            },
            {
                "name": "$str_2",
                "type": "text",
                "value": "getSrvAddr"
            },
            {
                "name": "$str_3",
                "type": "text",
                "value": "getSrvPort"
            },
            {
                "name": "$str_4",
                "type": "text",
                "value": "android.intent.action.START_GOOGLE_SERVICE"
            }
        ],
        "tags": [
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Android_Dogspectus_rswm', NULL, '{"author": "https://twitter.com/5h1vang", "sample": "197588be3e8ba5c779696d864121aff188901720dcda796759906c17473d46fe", "source": "https://www.bluecoat.com/security-blog/2016-04-25/android-exploit-delivers-dogspectus-ransomware", "description": "Yara rule for Dogspectus intial ransomware apk"}', '[
    {
        "condition_terms": [
            "(",
            "androguard.package_name",
            "(",
            "\"net.prospectus\"",
            ")",
            "and",
            "androguard.app_name",
            "(",
            "\"System update\"",
            ")",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"180ADFC5DE49C0D7F643BD896E9AAC4B8941E44E\"",
            ")",
            "or",
            "(",
            "androguard.activity",
            "(",
            "/Loganberry/i",
            ")",
            "or",
            "androguard.activity",
            "(",
            "\"net.prospectus.pu\"",
            ")",
            "or",
            "androguard.activity",
            "(",
            "\"PanickedActivity\"",
            ")",
            ")",
            "or",
            "(",
            "androguard.permission",
            "(",
            "/android.permission.INTERNET/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.WAKE_LOCK/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.RECEIVE_BOOT_COMPLETED/",
            ")",
            "and",
            "all",
            "of",
            "(",
            "$str_*",
            ")",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "https://twitter.com/5h1vang"
            },
            {
                "description": "Yara rule for Dogspectus intial ransomware apk"
            },
            {
                "sample": "197588be3e8ba5c779696d864121aff188901720dcda796759906c17473d46fe"
            },
            {
                "source": "https://www.bluecoat.com/security-blog/2016-04-25/android-exploit-delivers-dogspectus-ransomware"
            }
        ],
        "raw_condition": "condition:\n\t\t(androguard.package_name(\"net.prospectus\") and\n\t\t androguard.app_name(\"System update\")) or\n\t\t \n\t\tandroguard.certificate.sha1(\"180ADFC5DE49C0D7F643BD896E9AAC4B8941E44E\") or\n\t\t\n\t\t(androguard.activity(/Loganberry/i) or \n\t\tandroguard.activity(\"net.prospectus.pu\") or \n\t\tandroguard.activity(\"PanickedActivity\")) or \n\t\t\n\t\t(androguard.permission(/android.permission.INTERNET/) and\n\t\t androguard.permission(/android.permission.WAKE_LOCK/) and \n\t\t androguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and\n\t\t all of ($str_*))\n\t\t \t\n\t\t\n",
        "raw_meta": "meta:\n\t\tauthor = \"https://twitter.com/5h1vang\"\n\t\tdescription = \"Yara rule for Dogspectus intial ransomware apk\"\n\t\tsample = \"197588be3e8ba5c779696d864121aff188901720dcda796759906c17473d46fe\"\n\t\tsource = \"https://www.bluecoat.com/security-blog/2016-04-25/android-exploit-delivers-dogspectus-ransomware\"\n\n\t",
        "raw_strings": "strings:\n\t\t$str_1 = \"android.app.action.ADD_DEVICE_ADMIN\"\n\t\t$str_2 = \"Tap ACTIVATE to continue with software update\"\n\t\t\n\t\t\n\t",
        "rule_name": "Android_Dogspectus_rswm",
        "start_line": 13,
        "stop_line": 42,
        "strings": [
            {
                "name": "$str_1",
                "type": "text",
                "value": "android.app.action.ADD_DEVICE_ADMIN"
            },
            {
                "name": "$str_2",
                "type": "text",
                "value": "Tap ACTIVATE to continue with software update"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'BaDoink', '{official,android}', '{"author": "Fernando Denis https://twitter.com/fdrg21", "sample": "9bc0fb0f05bbf25507104a4eb74e8066b194a8e6a57670957c0ad1af92189921", "reference": "https://koodous.com/", "description": "Virus de la Policia - android"}', '[
    {
        "comments": [
            "//\t\tall of ($type_c_*)",
            "//all of ($url_string_*) or",
            "//\t\t$type_c_4 = \"FLAG_REQUEST_ENHANCED_WEB_ACCESSIBILITY\"",
            "//\t\t$type_c_3 = \"TYPE_VIEW_TEXT_SELECTION_CHANGED\"",
            "//\t\t$type_c_2 = \"TYPE_VIEW_ACCESSIBILITY_FOCUSED\"",
            "//$url_string_2 = \"http://mobile-policeblock.com\"",
            "//$url_string_1 = \"http://police-mobile-stop.com\""
        ],
        "condition_terms": [
            "androguard.app_name",
            "(",
            "\"BaDoink\"",
            ")",
            "or",
            "$type_a_1",
            "or",
            "all",
            "of",
            "(",
            "$type_b*",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "Fernando Denis https://twitter.com/fdrg21"
            },
            {
                "reference": "https://koodous.com/"
            },
            {
                "description": "Virus de la Policia - android"
            },
            {
                "sample": "9bc0fb0f05bbf25507104a4eb74e8066b194a8e6a57670957c0ad1af92189921"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.app_name(\"BaDoink\") or\n\t\t//all of ($url_string_*) or\n\t\t$type_a_1 or\n\t\tall of ($type_b*) \n//\t\tall of ($type_c_*)\n\t\t\n",
        "raw_meta": "meta:\n\t\tauthor = \"Fernando Denis https://twitter.com/fdrg21\"\n\t\treference = \"https://koodous.com/\"\n\t\tdescription = \"Virus de la Policia - android\"\n\t\tsample = \"9bc0fb0f05bbf25507104a4eb74e8066b194a8e6a57670957c0ad1af92189921\"\n\n\t",
        "raw_strings": "strings:\n\t\t\n\t\t//$url_string_1 = \"http://police-mobile-stop.com\"\n\t\t//$url_string_2 = \"http://mobile-policeblock.com\"\n\t\t\n\t\t$type_a_1 =\"6589y459gj4058rt\"\n\t\n\t\t$type_b_1 = \"Q,hu4P#hT;U!XO7T,uD\"\n\t\t$type_b_2 = \"+Gkwg#M!lf>Laq&+J{lg\"\n\n//\t\t$type_c_1 = \"ANIM_STYLE_CLOSE_ENTER\"\n//\t\t$type_c_2 = \"TYPE_VIEW_ACCESSIBILITY_FOCUSED\"\n//\t\t$type_c_3 = \"TYPE_VIEW_TEXT_SELECTION_CHANGED\"\n//\t\t$type_c_4 = \"FLAG_REQUEST_ENHANCED_WEB_ACCESSIBILITY\"\n\n\t",
        "rule_name": "BaDoink",
        "start_line": 13,
        "stop_line": 43,
        "strings": [
            {
                "name": "$type_a_1",
                "type": "text",
                "value": "6589y459gj4058rt"
            },
            {
                "name": "$type_b_1",
                "type": "text",
                "value": "Q,hu4P#hT;U!XO7T,uD"
            },
            {
                "name": "$type_b_2",
                "type": "text",
                "value": "+Gkwg#M!lf>Laq&+J{lg"
            }
        ],
        "tags": [
            "official",
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'koodous', '{official}', '{"Reference": "https://github.com/dana-at-cp/backdoor-apk", "description": "Detects samples repackaged by backdoor-apk shell script"}', '[
    {
        "condition_terms": [
            "$str_1",
            "and",
            "androguard.receiver",
            "(",
            "/\\.AppBoot$/",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "description": "Detects samples repackaged by backdoor-apk shell script"
            },
            {
                "Reference": "https://github.com/dana-at-cp/backdoor-apk"
            }
        ],
        "raw_condition": "condition:\n\t\t$str_1 and \n\t\tandroguard.receiver(/\\.AppBoot$/)\t\t\n",
        "raw_meta": "meta:\n\t\tdescription = \"Detects samples repackaged by backdoor-apk shell script\"\n\t\tReference = \"https://github.com/dana-at-cp/backdoor-apk\"\n\t\t\n\t",
        "raw_strings": "strings:\n\t\t$str_1 = \"cnlybnq.qrk\" // encrypted string \"payload.dex\"\n\n\t",
        "rule_name": "koodous",
        "start_line": 13,
        "stop_line": 25,
        "strings": [
            {
                "name": "$str_1",
                "type": "text",
                "value": "cnlybnq.qrk"
            }
        ],
        "tags": [
            "official"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Metasploit_Payload', NULL, '{"author": "https://www.twitter.com/SadFud75", "information": "Detection of payloads generated with metasploit"}', '[
    {
        "condition_terms": [
            "androguard.package_name",
            "(",
            "\"com.metasploit.stage\"",
            ")",
            "or",
            "any",
            "of",
            "them"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "https://www.twitter.com/SadFud75"
            },
            {
                "information": "Detection of payloads generated with metasploit"
            }
        ],
        "raw_condition": "condition:\nandroguard.package_name(\"com.metasploit.stage\") or any of them\n",
        "raw_meta": "meta:\nauthor = \"https://www.twitter.com/SadFud75\"\ninformation = \"Detection of payloads generated with metasploit\"\n",
        "raw_strings": "strings:\n$s1 = \"-com.metasploit.meterpreter.AndroidMeterpreter\"\n$s2 = \",Lcom/metasploit/stage/MainBroadcastReceiver;\"\n$s3 = \"#Lcom/metasploit/stage/MainActivity;\"\n$s4 = \"Lcom/metasploit/stage/Payload;\"\n$s5 = \"Lcom/metasploit/stage/a;\"\n$s6 = \"Lcom/metasploit/stage/c;\"\n$s7 = \"Lcom/metasploit/stage/b;\"\n",
        "rule_name": "Metasploit_Payload",
        "start_line": 3,
        "stop_line": 18,
        "strings": [
            {
                "name": "$s1",
                "type": "text",
                "value": "-com.metasploit.meterpreter.AndroidMeterpreter"
            },
            {
                "name": "$s2",
                "type": "text",
                "value": ",Lcom/metasploit/stage/MainBroadcastReceiver;"
            },
            {
                "name": "$s3",
                "type": "text",
                "value": "#Lcom/metasploit/stage/MainActivity;"
            },
            {
                "name": "$s4",
                "type": "text",
                "value": "Lcom/metasploit/stage/Payload;"
            },
            {
                "name": "$s5",
                "type": "text",
                "value": "Lcom/metasploit/stage/a;"
            },
            {
                "name": "$s6",
                "type": "text",
                "value": "Lcom/metasploit/stage/c;"
            },
            {
                "name": "$s7",
                "type": "text",
                "value": "Lcom/metasploit/stage/b;"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'trojan', '{pornClicker}', '{"author": "Koodous Project", "sample": "5a863fe4b141e14ba3d9d0de3a9864c1339b2358386e10ba3b4caec73b5d06ca", "reference": "https://blog.malwarebytes.org/cybercrime/2016/06/trojan-clickers-gaze-cast-upon-google-play-store/?utm_source=facebook&utm_medium=social", "description": "Ruleset to detect android pornclicker trojan, connects to a remote host and obtains javascript and a list from urls generated, leading to porn in the end."}', '[
    {
        "condition_terms": [
            "(",
            "$a",
            "and",
            "$b",
            "and",
            "$c",
            "and",
            "$api",
            ")",
            "or",
            "androguard.url",
            "(",
            "/mayis24\\.4tubetv\\.xyz/",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "description": "Ruleset to detect android pornclicker trojan, connects to a remote host and obtains javascript and a list from urls generated, leading to porn in the end."
            },
            {
                "sample": "5a863fe4b141e14ba3d9d0de3a9864c1339b2358386e10ba3b4caec73b5d06ca"
            },
            {
                "reference": "https://blog.malwarebytes.org/cybercrime/2016/06/trojan-clickers-gaze-cast-upon-google-play-store/?utm_source=facebook&utm_medium=social"
            },
            {
                "author": "Koodous Project"
            }
        ],
        "raw_condition": "condition:\n\t\t($a and $b and $c and $api) or androguard.url(/mayis24\\.4tubetv\\.xyz/)\n",
        "raw_meta": "meta:\n\t\tdescription = \"Ruleset to detect android pornclicker trojan, connects to a remote host and obtains javascript and a list from urls generated, leading to porn in the end.\"\n\t\tsample = \"5a863fe4b141e14ba3d9d0de3a9864c1339b2358386e10ba3b4caec73b5d06ca\"\n \t\treference = \"https://blog.malwarebytes.org/cybercrime/2016/06/trojan-clickers-gaze-cast-upon-google-play-store/?utm_source=facebook&utm_medium=social\"\n    author = \"Koodous Project\"\n    \n\t",
        "raw_strings": "strings:\n\t\t$a = \"SELEN3333\"\n\t\t$b = \"SELEN33\"\n\t\t$c = \"SELEN333\"\n\t\t$api = \"http://mayis24.4tubetv.xyz/dmr/ya\"\n\t\t\n\t",
        "rule_name": "trojan",
        "start_line": 10,
        "stop_line": 26,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "SELEN3333"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "SELEN33"
            },
            {
                "name": "$c",
                "type": "text",
                "value": "SELEN333"
            },
            {
                "name": "$api",
                "type": "text",
                "value": "http://mayis24.4tubetv.xyz/dmr/ya"
            }
        ],
        "tags": [
            "pornClicker"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Android_Triada', '{android}', '{"date": "2016/03/04", "author": "reverseShell - https://twitter.com/JReyCastro", "sample": "4656aa68ad30a5cf9bcd2b63f21fba7cfa0b70533840e771bd7d6680ef44794b", "source": "https://securelist.com/analysis/publications/74032/attack-on-zygote-a-new-twist-in-the-evolution-of-mobile-threats/", "description": "This rule try to detects Android.Triada.Malware"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "(",
            "$string_*",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.KILL_BACKGROUND_PROCESSES/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.SYSTEM_ALERT_WINDOW/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.GET_TASKS/",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "reverseShell - https://twitter.com/JReyCastro"
            },
            {
                "date": "2016/03/04"
            },
            {
                "description": "This rule try to detects Android.Triada.Malware"
            },
            {
                "sample": "4656aa68ad30a5cf9bcd2b63f21fba7cfa0b70533840e771bd7d6680ef44794b"
            },
            {
                "source": "https://securelist.com/analysis/publications/74032/attack-on-zygote-a-new-twist-in-the-evolution-of-mobile-threats/"
            }
        ],
        "raw_condition": "condition:\n\t\tall of ($string_*) and\n\t\tandroguard.permission(/android.permission.KILL_BACKGROUND_PROCESSES/) and\n\t\tandroguard.permission(/android.permission.SYSTEM_ALERT_WINDOW/) and\n\t\tandroguard.permission(/android.permission.GET_TASKS/)\n",
        "raw_meta": "meta:\n\t\tauthor = \"reverseShell - https://twitter.com/JReyCastro\"\n\t\tdate = \"2016/03/04\"\n\t\tdescription = \"This rule try to detects Android.Triada.Malware\"\n\t\tsample = \"4656aa68ad30a5cf9bcd2b63f21fba7cfa0b70533840e771bd7d6680ef44794b\"\n\t\tsource = \"https://securelist.com/analysis/publications/74032/attack-on-zygote-a-new-twist-in-the-evolution-of-mobile-threats/\"\n\t\t\n\t",
        "raw_strings": "strings:\n\t\t$string_1 = \"android/system/PopReceiver\"\n\t",
        "rule_name": "Android_Triada",
        "start_line": 13,
        "stop_line": 29,
        "strings": [
            {
                "name": "$string_1",
                "type": "text",
                "value": "android/system/PopReceiver"
            }
        ],
        "tags": [
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'tinhvan', '{android}', '{"author": "https://twitter.com/plutec_net", "sample": "0f7e995ff7075af2d0f8d60322975d610e888884922a89fda9a61c228374c5c5", "reference": "https://koodous.com/"}', '[
    {
        "condition_terms": [
            "androguard.certificate.sha1",
            "(",
            "\"0DFBBDB7735517748C3DEF3B6DEC2A800182D1D5\"",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "https://twitter.com/plutec_net"
            },
            {
                "reference": "https://koodous.com/"
            },
            {
                "sample": "0f7e995ff7075af2d0f8d60322975d610e888884922a89fda9a61c228374c5c5"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.certificate.sha1(\"0DFBBDB7735517748C3DEF3B6DEC2A800182D1D5\")\n\t\t\n",
        "raw_meta": "meta:\n\t  author = \"https://twitter.com/plutec_net\"\n\t\treference = \"https://koodous.com/\"\n\t\tsample = \"0f7e995ff7075af2d0f8d60322975d610e888884922a89fda9a61c228374c5c5\"\n\n\t",
        "rule_name": "tinhvan",
        "start_line": 14,
        "stop_line": 24,
        "tags": [
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Trojan_Dendroid', NULL, '{"author": "https://www.twitter.com/SadFud75", "description": "Detection of dendroid trojan"}', '[
    {
        "condition_terms": [
            "3",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "https://www.twitter.com/SadFud75"
            },
            {
                "description": "Detection of dendroid trojan"
            }
        ],
        "raw_condition": "condition:\n3 of them\n",
        "raw_meta": "meta:\nauthor = \"https://www.twitter.com/SadFud75\"\ndescription = \"Detection of dendroid trojan\"\n",
        "raw_strings": "strings:\n$s1 = \"/upload-pictures.php?\"\n$s2 = \"/get-functions.php?\"\n$s3 = \"/new-upload.php?\"\n$s4 = \"/message.php?\"\n$s5 = \"/get.php?\"\n",
        "rule_name": "Trojan_Dendroid",
        "start_line": 11,
        "stop_line": 24,
        "strings": [
            {
                "name": "$s1",
                "type": "text",
                "value": "/upload-pictures.php?"
            },
            {
                "name": "$s2",
                "type": "text",
                "value": "/get-functions.php?"
            },
            {
                "name": "$s3",
                "type": "text",
                "value": "/new-upload.php?"
            },
            {
                "name": "$s4",
                "type": "text",
                "value": "/message.php?"
            },
            {
                "name": "$s5",
                "type": "text",
                "value": "/get.php?"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'bankbot_polish_banks', '{banker}', '{"hash0": "86aaed9017e3af5d1d9c8460f2d8164f14e14db01b1a278b4b93859d3cf982f5", "author": "Eternal", "reference": "https://www.cert.pl/en/news/single/analysis-of-a-polish-bankbot/", "description": "BankBot/Mazain attacking polish banks"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "(",
            "$s*",
            ")",
            "and",
            "1",
            "of",
            "(",
            "$bank*",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.INTERNET/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.WAKE_LOCK/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.READ_EXTERNAL_STORAGE/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.RECEIVE_MMS/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.READ_SMS/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.RECEIVE_SMS/",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "Eternal"
            },
            {
                "hash0": "86aaed9017e3af5d1d9c8460f2d8164f14e14db01b1a278b4b93859d3cf982f5"
            },
            {
                "description": "BankBot/Mazain attacking polish banks"
            },
            {
                "reference": "https://www.cert.pl/en/news/single/analysis-of-a-polish-bankbot/"
            }
        ],
        "raw_condition": "condition:\n        all of ($s*) and 1 of ($bank*) and \n        androguard.permission(/android.permission.INTERNET/) and \n        androguard.permission(/android.permission.WAKE_LOCK/) and\n        androguard.permission(/android.permission.READ_EXTERNAL_STORAGE/) and\n        androguard.permission(/android.permission.RECEIVE_MMS/) and\n        androguard.permission(/android.permission.READ_SMS/) and\n        androguard.permission(/android.permission.RECEIVE_SMS/)\n",
        "raw_meta": "meta:\n        author = \"Eternal\"\n        hash0 = \"86aaed9017e3af5d1d9c8460f2d8164f14e14db01b1a278b4b93859d3cf982f5\"\n        description = \"BankBot/Mazain attacking polish banks\"\n        reference = \"https://www.cert.pl/en/news/single/analysis-of-a-polish-bankbot/\"\n    ",
        "raw_strings": "strings:\n        $bank1 = \"com.comarch.mobile\"\n        $bank2 = \"eu.eleader.mobilebanking.pekao\"\n        $bank3 = \"eu.eleader.mobilebanking.raiffeisen\"\n        $bank4 = \"pl.fmbank.smart\"\n        $bank5 = \"pl.mbank\"\n        $bank6 = \"wit.android.bcpBankingApp.millenniumPL\"\n        $bank7 = \"pl.pkobp.iko\"\n        $bank8 = \"pl.plus.plusonline\"\n        $bank9 = \"pl.ing.mojeing\"\n        $bank10 = \"pl.bzwbk.bzwbk24\"\n        $bank11 = \"com.getingroup.mobilebanking\"\n        $bank12 = \"eu.eleader.mobilebanking.invest\"\n        $bank13 = \"pl.bph\"\n        $bank14 = \"com.konylabs.cbplpat\"\n        $bank15 = \"eu.eleader.mobilebanking.pekao.firm\"\n\n        $s1 = \"IMEI\"\n        $s2 = \"/:/\"\n        $s3 = \"p=\"\n        $s4 = \"SMS From:\"\n\n    ",
        "rule_name": "bankbot_polish_banks",
        "start_line": 3,
        "stop_line": 40,
        "strings": [
            {
                "name": "$bank1",
                "type": "text",
                "value": "com.comarch.mobile"
            },
            {
                "name": "$bank2",
                "type": "text",
                "value": "eu.eleader.mobilebanking.pekao"
            },
            {
                "name": "$bank3",
                "type": "text",
                "value": "eu.eleader.mobilebanking.raiffeisen"
            },
            {
                "name": "$bank4",
                "type": "text",
                "value": "pl.fmbank.smart"
            },
            {
                "name": "$bank5",
                "type": "text",
                "value": "pl.mbank"
            },
            {
                "name": "$bank6",
                "type": "text",
                "value": "wit.android.bcpBankingApp.millenniumPL"
            },
            {
                "name": "$bank7",
                "type": "text",
                "value": "pl.pkobp.iko"
            },
            {
                "name": "$bank8",
                "type": "text",
                "value": "pl.plus.plusonline"
            },
            {
                "name": "$bank9",
                "type": "text",
                "value": "pl.ing.mojeing"
            },
            {
                "name": "$bank10",
                "type": "text",
                "value": "pl.bzwbk.bzwbk24"
            },
            {
                "name": "$bank11",
                "type": "text",
                "value": "com.getingroup.mobilebanking"
            },
            {
                "name": "$bank12",
                "type": "text",
                "value": "eu.eleader.mobilebanking.invest"
            },
            {
                "name": "$bank13",
                "type": "text",
                "value": "pl.bph"
            },
            {
                "name": "$bank14",
                "type": "text",
                "value": "com.konylabs.cbplpat"
            },
            {
                "name": "$bank15",
                "type": "text",
                "value": "eu.eleader.mobilebanking.pekao.firm"
            },
            {
                "name": "$s1",
                "type": "text",
                "value": "IMEI"
            },
            {
                "name": "$s2",
                "type": "text",
                "value": "/:/"
            },
            {
                "name": "$s3",
                "type": "text",
                "value": "p="
            },
            {
                "name": "$s4",
                "type": "text",
                "value": "SMS From:"
            }
        ],
        "tags": [
            "banker"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'SandroRat', NULL, '{"date": "21-May-2016", "author": "Jacob Soo Lead Re", "source": "https://blogs.mcafee.com/mcafee-labs/sandrorat-android-rat-targeting-polish-banking-users-via-e-mail-phishing/", "description": "This rule detects SandroRat"}', '[
    {
        "condition_terms": [
            "androguard.activity",
            "(",
            "/net.droidjack.server/i",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "Jacob Soo Lead Re"
            },
            {
                "date": "21-May-2016"
            },
            {
                "description": "This rule detects SandroRat"
            },
            {
                "source": "https://blogs.mcafee.com/mcafee-labs/sandrorat-android-rat-targeting-polish-banking-users-via-e-mail-phishing/"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.activity(/net.droidjack.server/i) \n",
        "raw_meta": "meta:\n\t\tauthor = \"Jacob Soo Lead Re\"\n\t\tdate = \"21-May-2016\"\n\t\tdescription = \"This rule detects SandroRat\"\n\t\tsource = \"https://blogs.mcafee.com/mcafee-labs/sandrorat-android-rat-targeting-polish-banking-users-via-e-mail-phishing/\"\n\n\t",
        "rule_name": "SandroRat",
        "start_line": 4,
        "stop_line": 14
    }
]
');
INSERT INTO public.rule VALUES (default, 'dropper', '{realshell,android}', '{"author": "https://twitter.com/plutec_net", "source": "https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/", "reference": "https://koodous.com/"}', '[
    {
        "condition_terms": [
            "$b"
        ],
        "metadata": [
            {
                "author": "https://twitter.com/plutec_net"
            },
            {
                "reference": "https://koodous.com/"
            },
            {
                "source": "https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/"
            }
        ],
        "raw_condition": "condition:\n        $b\n",
        "raw_meta": "meta:\n        author = \"https://twitter.com/plutec_net\"\n        reference = \"https://koodous.com/\"\n        source = \"https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/\"\n    ",
        "raw_strings": "strings:\n        $b = \"Decrypt.malloc.memset.free.pluginSMS_encrypt.Java_com_skymobi_pay_common_util_LocalDataDecrpty_Encrypt.strcpy\"\n    \n    ",
        "rule_name": "dropper",
        "start_line": 6,
        "stop_line": 16,
        "strings": [
            {
                "name": "$b",
                "type": "text",
                "value": "Decrypt.malloc.memset.free.pluginSMS_encrypt.Java_com_skymobi_pay_common_util_LocalDataDecrpty_Encrypt.strcpy"
            }
        ],
        "tags": [
            "realshell",
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Android_FakeBank_Fanta', NULL, '{"date": "14-July-2016", "author": "Jacob Soo Lead Re", "source": "https://blog.trendmicro.com/trendlabs-security-intelligence/fake-bank-app-phishes-credentials-locks-users-out/", "description": "This rule try to detects Android FakeBank_Fanta"}', '[
    {
        "condition_terms": [
            "androguard.service",
            "(",
            "/SocketService/i",
            ")",
            "and",
            "androguard.receiver",
            "(",
            "/MyAdmin/i",
            ")",
            "and",
            "androguard.receiver",
            "(",
            "/Receiver/i",
            ")",
            "and",
            "androguard.receiver",
            "(",
            "/NetworkChangeReceiver/i",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "Jacob Soo Lead Re"
            },
            {
                "date": "14-July-2016"
            },
            {
                "description": "This rule try to detects Android FakeBank_Fanta"
            },
            {
                "source": "https://blog.trendmicro.com/trendlabs-security-intelligence/fake-bank-app-phishes-credentials-locks-users-out/"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.service(/SocketService/i) and \n\t\tandroguard.receiver(/MyAdmin/i) and \n\t\tandroguard.receiver(/Receiver/i) and \n\t\tandroguard.receiver(/NetworkChangeReceiver/i)\n\t\t\n",
        "raw_meta": "meta:\n\t\tauthor = \"Jacob Soo Lead Re\"\n\t\tdate = \"14-July-2016\"\n\t\tdescription = \"This rule try to detects Android FakeBank_Fanta\"\n\t\tsource = \"https://blog.trendmicro.com/trendlabs-security-intelligence/fake-bank-app-phishes-credentials-locks-users-out/\"\n\n\t",
        "rule_name": "Android_FakeBank_Fanta",
        "start_line": 8,
        "stop_line": 22
    }
]
');
INSERT INTO public.rule VALUES (default, 'VikingBotnet', NULL, '{"author": "https://twitter.com/koodous_project", "sample": "85e6d5b3569e5b22a16245215a2f31df1ea3a1eb4d53b4c286a6ad2a46517b0c", "description": "Rule to detect Viking Order Botnet."}', '[
    {
        "condition_terms": [
            "(",
            "$a",
            "and",
            "$c",
            ")",
            "or",
            "(",
            "$b",
            "and",
            "$d",
            ")"
        ],
        "imports": [
            "androguard",
            "cuckoo"
        ],
        "metadata": [
            {
                "author": "https://twitter.com/koodous_project"
            },
            {
                "description": "Rule to detect Viking Order Botnet."
            },
            {
                "sample": "85e6d5b3569e5b22a16245215a2f31df1ea3a1eb4d53b4c286a6ad2a46517b0c"
            }
        ],
        "raw_condition": "condition:\n\t\t($a and $c) or ($b and $d) \n",
        "raw_meta": "meta:\n\t  author = \"https://twitter.com/koodous_project\"\n\t\tdescription = \"Rule to detect Viking Order Botnet.\"\n\t\tsample = \"85e6d5b3569e5b22a16245215a2f31df1ea3a1eb4d53b4c286a6ad2a46517b0c\"\n\n\t",
        "raw_strings": "strings:\n\t\t$a = \"cv7obBkPVC2pvJmWSfHzXh\"\n\t\t$b = \"http://joyappstech.biz:11111/knock/\"\n\t\t$c = \"I HATE TESTERS onGlobalLayout\"\n\t\t$d = \"http://144.76.70.213:7777/ecspectapatronum/\"\n\t\t\n\t",
        "rule_name": "VikingBotnet",
        "start_line": 9,
        "stop_line": 24,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "cv7obBkPVC2pvJmWSfHzXh"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "http://joyappstech.biz:11111/knock/"
            },
            {
                "name": "$c",
                "type": "text",
                "value": "I HATE TESTERS onGlobalLayout"
            },
            {
                "name": "$d",
                "type": "text",
                "value": "http://144.76.70.213:7777/ecspectapatronum/"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'andr_sk_bank', NULL, '{"author": "https://twitter.com/5h1vang", "sample": "0af5c4c2f39aba06f6793f26d6caae134564441b2134e0b72536e65a62bcbfad", "source": "https://www.zscaler.com/blogs/research/android-malware-targeting-south-korean-mobile-users", "description": "Yara rule for Banking trojan targeting South Korean banks"}', '[
    {
        "condition_terms": [
            "androguard.package_name",
            "(",
            "\"com.qbjkyd.rhsxa\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"543382EDDAFC05B435F13BBE97037BB335C2948B\"",
            ")",
            "or",
            "(",
            "androguard.permission",
            "(",
            "/android.permission.RECEIVE_SMS/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.INTERNET/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.RECEIVE_BOOT_COMPLETED/",
            ")",
            "and",
            "all",
            "of",
            "(",
            "$str_*",
            ")",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "description": "Yara rule for Banking trojan targeting South Korean banks"
            },
            {
                "sample": "0af5c4c2f39aba06f6793f26d6caae134564441b2134e0b72536e65a62bcbfad"
            },
            {
                "source": "https://www.zscaler.com/blogs/research/android-malware-targeting-south-korean-mobile-users"
            },
            {
                "author": "https://twitter.com/5h1vang"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.package_name(\"com.qbjkyd.rhsxa\") or\n\t\tandroguard.certificate.sha1(\"543382EDDAFC05B435F13BBE97037BB335C2948B\") or\n\t\t(androguard.permission(/android.permission.RECEIVE_SMS/) and\n\t\tandroguard.permission(/android.permission.INTERNET/) and \n\t\tandroguard.permission(/android.permission.RECEIVE_BOOT_COMPLETED/) and \n\t\tall of ($str_*))\n",
        "raw_meta": "meta:\n\t\tdescription = \"Yara rule for Banking trojan targeting South Korean banks\"\n\t\tsample = \"0af5c4c2f39aba06f6793f26d6caae134564441b2134e0b72536e65a62bcbfad\"\n\t\tsource = \"https://www.zscaler.com/blogs/research/android-malware-targeting-south-korean-mobile-users\"\n\t\tauthor = \"https://twitter.com/5h1vang\"\n\n\t",
        "raw_strings": "strings:\n\t\t$str_1 = \"NPKI\"\n\t\t$str_2 = \"portraitCallBack(\"\n\t\t$str_3 = \"android.app.extra.DEVICE_ADMIN\"\n\t\t$str_4 = \"SMSReceiver&imsi=\"\n\t\t$str_5 = \"com.ahnlab.v3mobileplus\"\n\n\t",
        "rule_name": "andr_sk_bank",
        "start_line": 13,
        "stop_line": 35,
        "strings": [
            {
                "name": "$str_1",
                "type": "text",
                "value": "NPKI"
            },
            {
                "name": "$str_2",
                "type": "text",
                "value": "portraitCallBack("
            },
            {
                "name": "$str_3",
                "type": "text",
                "value": "android.app.extra.DEVICE_ADMIN"
            },
            {
                "name": "$str_4",
                "type": "text",
                "value": "SMSReceiver&imsi="
            },
            {
                "name": "$str_5",
                "type": "text",
                "value": "com.ahnlab.v3mobileplus"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'tachi', '{android}', '{"author": "https://twitter.com/plutec_net", "sample": "10acdf7db989c3acf36be814df4a95f00d370fe5b5fda142f9fd94acf46149ec", "source": "https://analyst.koodous.com/rulesets/1332", "description": "This rule detects tachi apps (not all malware)"}', '[
    {
        "condition_terms": [
            "$a",
            "and",
            "4",
            "of",
            "(",
            "$xml_*",
            ")"
        ],
        "metadata": [
            {
                "author": "https://twitter.com/plutec_net"
            },
            {
                "source": "https://analyst.koodous.com/rulesets/1332"
            },
            {
                "description": "This rule detects tachi apps (not all malware)"
            },
            {
                "sample": "10acdf7db989c3acf36be814df4a95f00d370fe5b5fda142f9fd94acf46149ec"
            }
        ],
        "raw_condition": "condition:\n\t\t$a and 4 of ($xml_*)\n",
        "raw_meta": "meta:\n\t\tauthor = \"https://twitter.com/plutec_net\"\n\t\tsource = \"https://analyst.koodous.com/rulesets/1332\"\n\t\tdescription = \"This rule detects tachi apps (not all malware)\"\n\t\tsample = \"10acdf7db989c3acf36be814df4a95f00d370fe5b5fda142f9fd94acf46149ec\"\n\n\t",
        "raw_strings": "strings:\n\t\t$a = \"svcdownload\"\n\t\t$xml_1 = \"<config>\"\n\t\t$xml_2 = \"<apptitle>\"\n\t\t$xml_3 = \"<txinicio>\"\n\t\t$xml_4 = \"<txiniciotitulo>\"\n\t\t$xml_5 = \"<txnored>\"\n\t\t$xml_6 = \"<txnoredtitulo>\"\n\t\t$xml_7 = \"<txnoredretry>\"\n\t\t$xml_8 = \"<txnoredsalir>\"\n\t\t$xml_9 = \"<laurl>\"\n\t\t$xml_10 = \"<txquieresalir>\"\n\t\t$xml_11 = \"<txquieresalirtitulo>\"\n\t\t$xml_12 = \"<txquieresalirsi>\"\n\t\t$xml_13 = \"<txquieresalirno>\"\n\t\t$xml_14 = \"<txfiltro>\"\n\t\t$xml_15 = \"<txfiltrourl>\"\n\t\t$xml_16 = \"<posicion>\"\n\n\n\t",
        "rule_name": "tachi",
        "start_line": 1,
        "stop_line": 31,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "svcdownload"
            },
            {
                "name": "$xml_1",
                "type": "text",
                "value": "<config>"
            },
            {
                "name": "$xml_2",
                "type": "text",
                "value": "<apptitle>"
            },
            {
                "name": "$xml_3",
                "type": "text",
                "value": "<txinicio>"
            },
            {
                "name": "$xml_4",
                "type": "text",
                "value": "<txiniciotitulo>"
            },
            {
                "name": "$xml_5",
                "type": "text",
                "value": "<txnored>"
            },
            {
                "name": "$xml_6",
                "type": "text",
                "value": "<txnoredtitulo>"
            },
            {
                "name": "$xml_7",
                "type": "text",
                "value": "<txnoredretry>"
            },
            {
                "name": "$xml_8",
                "type": "text",
                "value": "<txnoredsalir>"
            },
            {
                "name": "$xml_9",
                "type": "text",
                "value": "<laurl>"
            },
            {
                "name": "$xml_10",
                "type": "text",
                "value": "<txquieresalir>"
            },
            {
                "name": "$xml_11",
                "type": "text",
                "value": "<txquieresalirtitulo>"
            },
            {
                "name": "$xml_12",
                "type": "text",
                "value": "<txquieresalirsi>"
            },
            {
                "name": "$xml_13",
                "type": "text",
                "value": "<txquieresalirno>"
            },
            {
                "name": "$xml_14",
                "type": "text",
                "value": "<txfiltro>"
            },
            {
                "name": "$xml_15",
                "type": "text",
                "value": "<txfiltrourl>"
            },
            {
                "name": "$xml_16",
                "type": "text",
                "value": "<posicion>"
            }
        ],
        "tags": [
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Android_Clicker_G', NULL, '{"date": "01-July-2016", "author": "Jacob Soo Lead Re", "reference": "https://blogs.mcafee.com/mcafee-labs/android-malware-clicker-dgen-found-google-play/", "description": "This rule try to detects Clicker.G samples"}', '[
    {
        "condition_terms": [
            "androguard.receiver",
            "(",
            "/MyBroadCastReceiver/i",
            ")",
            "and",
            "$a"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "Jacob Soo Lead Re"
            },
            {
                "date": "01-July-2016"
            },
            {
                "description": "This rule try to detects Clicker.G samples"
            },
            {
                "reference": "https://blogs.mcafee.com/mcafee-labs/android-malware-clicker-dgen-found-google-play/"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.receiver(/MyBroadCastReceiver/i) and $a\n",
        "raw_meta": "meta:\n\t\tauthor = \"Jacob Soo Lead Re\"\n\t\tdate = \"01-July-2016\"\n\t\tdescription = \"This rule try to detects Clicker.G samples\"\n\t\treference = \"https://blogs.mcafee.com/mcafee-labs/android-malware-clicker-dgen-found-google-play/\"\n\t",
        "raw_strings": "strings:\n\t\t$a = \"upd.php?text=\"\n\t",
        "rule_name": "Android_Clicker_G",
        "start_line": 8,
        "stop_line": 19,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "upd.php?text="
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'dowgin', '{adware,android}', '{"author": "https://twitter.com/plutec_net", "sample": "4d7f2d6ff4ed8ced6f8f7f96e9899273cc3090ea108f2cc3b32dd1a06e63cf70", "sample2": "cde8160d09c486bdd6d96b2ed81bd52390d77094d13ff9cfbc6949ed00206a83", "sample3": "d2e81e6db5f4964246d10241588e0e97cde524815c4de7c0ea1c34a48da1bcaf", "sample4": "cc2d0b3d8f00690298b0e5813f6ace8f4d4b04c9704292407c2b83a12c69617b", "reference": "https://koodous.com/"}', '[
    {
        "condition_terms": [
            "all",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "https://twitter.com/plutec_net"
            },
            {
                "reference": "https://koodous.com/"
            },
            {
                "sample": "4d7f2d6ff4ed8ced6f8f7f96e9899273cc3090ea108f2cc3b32dd1a06e63cf70"
            },
            {
                "sample2": "cde8160d09c486bdd6d96b2ed81bd52390d77094d13ff9cfbc6949ed00206a83"
            },
            {
                "sample3": "d2e81e6db5f4964246d10241588e0e97cde524815c4de7c0ea1c34a48da1bcaf"
            },
            {
                "sample4": "cc2d0b3d8f00690298b0e5813f6ace8f4d4b04c9704292407c2b83a12c69617b"
            }
        ],
        "raw_condition": "condition:\n        all of them\n        \n",
        "raw_meta": "meta:\n        author = \"https://twitter.com/plutec_net\"\n        reference = \"https://koodous.com/\"\n        sample = \"4d7f2d6ff4ed8ced6f8f7f96e9899273cc3090ea108f2cc3b32dd1a06e63cf70\"\n        sample2 = \"cde8160d09c486bdd6d96b2ed81bd52390d77094d13ff9cfbc6949ed00206a83\"\n        sample3 = \"d2e81e6db5f4964246d10241588e0e97cde524815c4de7c0ea1c34a48da1bcaf\"\n        sample4 = \"cc2d0b3d8f00690298b0e5813f6ace8f4d4b04c9704292407c2b83a12c69617b\"\n\n    ",
        "raw_strings": "strings:\n        $a = \"http://112.74.111.42:8000\"\n        $b = \"SHA1-Digest: oIx4iYWeTtKib4fBH7hcONeHuaE=\"\n        $c = \"ONLINEGAMEPROCEDURE_WHICH_WAP_ID\"\n        $d = \"http://da.mmarket.com/mmsdk/mmsdk?func=mmsdk:posteventlog\"\n\n    ",
        "rule_name": "dowgin",
        "start_line": 1,
        "stop_line": 20,
        "strings": [
            {
                "name": "$a",
                "type": "text",
                "value": "http://112.74.111.42:8000"
            },
            {
                "name": "$b",
                "type": "text",
                "value": "SHA1-Digest: oIx4iYWeTtKib4fBH7hcONeHuaE="
            },
            {
                "name": "$c",
                "type": "text",
                "value": "ONLINEGAMEPROCEDURE_WHICH_WAP_ID"
            },
            {
                "name": "$d",
                "type": "text",
                "value": "http://da.mmarket.com/mmsdk/mmsdk?func=mmsdk:posteventlog"
            }
        ],
        "tags": [
            "adware",
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'fraudulents_2', '{certificates,android}', '{"author": "https://twitter.com/fdrg21", "description": "This rule automatically adds certificates present in malware"}', '[
    {
        "condition_terms": [
            "androguard.certificate.sha1",
            "(",
            "\"A5D9C9A40A3786D631210E8FCB9CF7A1BC5B3062\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"B4142B617997345809736842147F97F46059FDE3\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"950A545EA156A0E44B3BAB5F432DCD35005A9B70\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"DE18FA0C68E6C9E167262F1F4ED984A5F00FD78C\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"81E8E202C539F7AEDF6138804BE870338F81B356\"",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"5A051047F2434DDB2CAA65898D9B19ED9665F759\"",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "description": "This rule automatically adds certificates present in malware"
            },
            {
                "author": "https://twitter.com/fdrg21"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.certificate.sha1(\"A5D9C9A40A3786D631210E8FCB9CF7A1BC5B3062\") or\n\t\tandroguard.certificate.sha1(\"B4142B617997345809736842147F97F46059FDE3\") or\n\t\tandroguard.certificate.sha1(\"950A545EA156A0E44B3BAB5F432DCD35005A9B70\") or\n\t\tandroguard.certificate.sha1(\"DE18FA0C68E6C9E167262F1F4ED984A5F00FD78C\") or\n\t\tandroguard.certificate.sha1(\"81E8E202C539F7AEDF6138804BE870338F81B356\") or\n\t\tandroguard.certificate.sha1(\"5A051047F2434DDB2CAA65898D9B19ED9665F759\")\n\t\t\n",
        "raw_meta": "meta:\n\t\tdescription = \"This rule automatically adds certificates present in malware\"\n\t\tauthor = \"https://twitter.com/fdrg21\"\n\n\t",
        "rule_name": "fraudulents_2",
        "start_line": 13,
        "stop_line": 27,
        "tags": [
            "certificates",
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Android_BadMirror', NULL, '{"date": "06-June-2016", "author": "Jacob Soo Lead Re", "source": "https://blog.fortinet.com/post/badmirror-new-android-malware-family-spotted-by-sherlockdroid", "description": "BadMirror is Android malware. The malware sends information to its remote CnC (phone number, MAC adddress, list of installed applications...) but it also has the capability to execute a few commands such as \\\"app\\\" (download an APK) or \\\"page\\\" (display a given URL)."}', '[
    {
        "condition_terms": [
            "androguard.service",
            "(",
            "/SimInsService/i",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.READ_PHONE_STATE/i",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "Jacob Soo Lead Re"
            },
            {
                "date": "06-June-2016"
            },
            {
                "description": "BadMirror is Android malware. The malware sends information to its remote CnC (phone number, MAC adddress, list of installed applications...) but it also has the capability to execute a few commands such as \\\"app\\\" (download an APK) or \\\"page\\\" (display a given URL)."
            },
            {
                "source": "https://blog.fortinet.com/post/badmirror-new-android-malware-family-spotted-by-sherlockdroid"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.service(/SimInsService/i) and\n        androguard.permission(/android.permission.READ_PHONE_STATE/i)\n",
        "raw_meta": "meta:\n\t\tauthor = \"Jacob Soo Lead Re\"\n\t\tdate = \"06-June-2016\"\n\t\tdescription = \"BadMirror is Android malware. The malware sends information to its remote CnC (phone number, MAC adddress, list of installed applications...) but it also has the capability to execute a few commands such as \\\"app\\\" (download an APK) or \\\"page\\\" (display a given URL).\"\n\t\tsource = \"https://blog.fortinet.com/post/badmirror-new-android-malware-family-spotted-by-sherlockdroid\"\n\n\t",
        "rule_name": "Android_BadMirror",
        "start_line": 8,
        "stop_line": 19
    }
]
');
INSERT INTO public.rule VALUES (default, 'HackingTeam_Android', '{Android,Implant}', '{"date": "2016-11-14", "author": "Tim ''diff'' Strazzere <strazz@gmail.com>", "version": "1.0", "reference": "http://rednaga.io/2016/11/14/hackingteam_back_for_your_androids/", "description": "HackingTeam Android implant, known to detect version v4 - v7"}', '[
    {
        "comments": [
            "// Lcom/google/android/global/Settings;"
        ],
        "condition_terms": [
            "$decryptor",
            "and",
            "(",
            "$settings",
            "and",
            "$getSmsInputNumbers",
            ")"
        ],
        "metadata": [
            {
                "description": "HackingTeam Android implant, known to detect version v4 - v7"
            },
            {
                "author": "Tim ''diff'' Strazzere <strazz@gmail.com>"
            },
            {
                "reference": "http://rednaga.io/2016/11/14/hackingteam_back_for_your_androids/"
            },
            {
                "date": "2016-11-14"
            },
            {
                "version": "1.0"
            }
        ],
        "raw_condition": "condition:\n        $decryptor and ($settings and $getSmsInputNumbers)\n",
        "raw_meta": "meta:\n\t\tdescription = \"HackingTeam Android implant, known to detect version v4 - v7\"\n\t\tauthor = \"Tim ''diff'' Strazzere <strazz@gmail.com>\"\n                reference = \"http://rednaga.io/2016/11/14/hackingteam_back_for_your_androids/\"\n\t\tdate = \"2016-11-14\"\n\t\tversion = \"1.0\"\n        ",
        "raw_strings": "strings:\n        $decryptor = {  12 01               // const/4 v1, 0x0\n                        D8 00 ?? ??         // add-int/lit8 ??, ??, ??\n                        6E 10 ?? ?? ?? 00   // invoke-virtual {??} -> String.toCharArray()\n                        0C 04               // move-result-object v4\n                        21 45               // array-length v5, v4\n                        01 02               // move v2, v0\n                        01 10               // move v0, v1\n                        32 50 11 00         // if-eq v0, v5, 0xb\n                        49 03 04 00         // aget-char v3, v4, v0\n                        DD 06 02 5F         // and-int/lit8 v6, v2, 0x5f <- potentially change the hardcoded xor bit to ??\n                        B7 36               // xor-int/2addr v6, v3\n                        D8 03 02 ??         // and-int/lit8 v3, v2, ??\n                        D8 02 00 01         // and-int/lit8 v2, v0, 0x1\n                        8E 66               // int-to-char v6, v6\n                        50 06 04 00         // aput-char v6, v4, v0\n                        01 20               // move v0, v2\n                        01 32               // move v2, v3\n                        28 F0               // goto 0xa\n                        71 30 ?? ?? 14 05   // invoke-static {v4, v1, v5}, ?? -> String.valueOf()\n                        0C 00               // move-result-object v0\n                        6E 10 ?? ?? 00 00   // invoke-virtual {v0} ?? -> String.intern()\n                        0C 00               // move-result-object v0\n                        11 00               // return-object v0\n                     }\n        // Below is the following string, however encoded as it would appear in the string table (length encoded, null byte padded)\n        // Lcom/google/android/global/Settings;\n        $settings = {\n                        00 24 4C 63 6F 6D 2F 67 6F 6F 67 6C 65 2F 61 6E\n                        64 72 6F 69 64 2F 67 6C 6F 62 61 6C 2F 53 65 74\n                        74 69 6E 67 73 3B 00\n                    }\n        // getSmsInputNumbers (Same encoded described above)\n        $getSmsInputNumbers = {\n                                00 12 67 65 74 53 6D 73 49 6E 70 75 74 4E 75 6D\n                                62 65 72 73 00\n                              }\n      ",
        "rule_name": "HackingTeam_Android",
        "start_line": 5,
        "stop_line": 52,
        "strings": [
            {
                "name": "$decryptor",
                "type": "byte",
                "value": "{  12 01               // const/4 v1, 0x0\n                        D8 00 ?? ??         // add-int/lit8 ??, ??, ??\n                        6E 10 ?? ?? ?? 00   // invoke-virtual {??} -> String.toCharArray()\n                        0C 04               // move-result-object v4\n                        21 45               // array-length v5, v4\n                        01 02               // move v2, v0\n                        01 10               // move v0, v1\n                        32 50 11 00         // if-eq v0, v5, 0xb\n                        49 03 04 00         // aget-char v3, v4, v0\n                        DD 06 02 5F         // and-int/lit8 v6, v2, 0x5f <- potentially change the hardcoded xor bit to ??\n                        B7 36               // xor-int/2addr v6, v3\n                        D8 03 02 ??         // and-int/lit8 v3, v2, ??\n                        D8 02 00 01         // and-int/lit8 v2, v0, 0x1\n                        8E 66               // int-to-char v6, v6\n                        50 06 04 00         // aput-char v6, v4, v0\n                        01 20               // move v0, v2\n                        01 32               // move v2, v3\n                        28 F0               // goto 0xa\n                        71 30 ?? ?? 14 05   // invoke-static {v4, v1, v5}, ?? -> String.valueOf()\n                        0C 00               // move-result-object v0\n                        6E 10 ?? ?? 00 00   // invoke-virtual {v0} ?? -> String.intern()\n                        0C 00               // move-result-object v0\n                        11 00               // return-object v0\n                     }"
            },
            {
                "name": "$settings",
                "type": "byte",
                "value": "{\n                        00 24 4C 63 6F 6D 2F 67 6F 6F 67 6C 65 2F 61 6E\n                        64 72 6F 69 64 2F 67 6C 6F 62 61 6C 2F 53 65 74\n                        74 69 6E 67 73 3B 00\n                    }"
            },
            {
                "name": "$getSmsInputNumbers",
                "type": "byte",
                "value": "{\n                                00 12 67 65 74 53 6D 73 49 6E 70 75 74 4E 75 6D\n                                62 65 72 73 00\n                              }"
            }
        ],
        "tags": [
            "Android",
            "Implant"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'libyan_scorpions', NULL, '{"sample": "9d8e5ccd4cf543b4b41e4c6a1caae1409076a26ee74c61c148dffd3ce87d7787", "source": "https://cyberkov.com/wp-content/uploads/2016/09/Hunting-Libyan-Scorpions-EN.pdf"}', '[
    {
        "condition_terms": [
            "androguard.url",
            "(",
            "/41\\.208\\.110\\.46/",
            ")",
            "or",
            "cuckoo.network.http_request",
            "(",
            "/41\\.208\\.110\\.46/",
            ")",
            "or",
            "androguard.url",
            "(",
            "/winmeif.myq-see.com/i",
            ")",
            "or",
            "cuckoo.network.dns_lookup",
            "(",
            "/winmeif.myq-see.com/i",
            ")",
            "or",
            "androguard.url",
            "(",
            "/wininit.myq-see.com/i",
            ")",
            "or",
            "cuckoo.network.dns_lookup",
            "(",
            "/wininit.myq-see.com/i",
            ")",
            "or",
            "androguard.url",
            "(",
            "/samsung.ddns.me/i",
            ")",
            "or",
            "cuckoo.network.dns_lookup",
            "(",
            "/samsung.ddns.me/i",
            ")",
            "or",
            "androguard.url",
            "(",
            "/collge.myq-see.com/i",
            ")",
            "or",
            "cuckoo.network.dns_lookup",
            "(",
            "/collge.myq-see.com/i",
            ")",
            "or",
            "androguard.url",
            "(",
            "/sara2011.no-ip.biz/i",
            ")",
            "or",
            "cuckoo.network.dns_lookup",
            "(",
            "/sara2011.no-ip.biz/i",
            ")",
            "or",
            "any",
            "of",
            "(",
            "$domain_*",
            ")",
            "or",
            "any",
            "of",
            "(",
            "$ip_*",
            ")",
            "or",
            "androguard.certificate.sha1",
            "(",
            "\"DFFDD3C42FA06BCEA9D65B8A2E980851383BD1E3\"",
            ")"
        ],
        "imports": [
            "cuckoo",
            "androguard"
        ],
        "metadata": [
            {
                "source": "https://cyberkov.com/wp-content/uploads/2016/09/Hunting-Libyan-Scorpions-EN.pdf"
            },
            {
                "sample": "9d8e5ccd4cf543b4b41e4c6a1caae1409076a26ee74c61c148dffd3ce87d7787"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.url(/41\\.208\\.110\\.46/) or cuckoo.network.http_request(/41\\.208\\.110\\.46/) or\n\t\tandroguard.url(/winmeif.myq-see.com/i) or cuckoo.network.dns_lookup(/winmeif.myq-see.com/i) or\n\t\tandroguard.url(/wininit.myq-see.com/i) or cuckoo.network.dns_lookup(/wininit.myq-see.com/i) or\n\t\tandroguard.url(/samsung.ddns.me/i) or cuckoo.network.dns_lookup(/samsung.ddns.me/i) or\n\t\tandroguard.url(/collge.myq-see.com/i) or cuckoo.network.dns_lookup(/collge.myq-see.com/i) or\n\t\tandroguard.url(/sara2011.no-ip.biz/i) or cuckoo.network.dns_lookup(/sara2011.no-ip.biz/i) or\n\t\tany of ($domain_*) or any of ($ip_*) or\n\t\tandroguard.certificate.sha1(\"DFFDD3C42FA06BCEA9D65B8A2E980851383BD1E3\")\n\t\t\n",
        "raw_meta": "meta:\n\t\tsource = \"https://cyberkov.com/wp-content/uploads/2016/09/Hunting-Libyan-Scorpions-EN.pdf\"\n\t\tsample = \"9d8e5ccd4cf543b4b41e4c6a1caae1409076a26ee74c61c148dffd3ce87d7787\"\n\n\t",
        "raw_strings": "strings:\n\t\t$ip_1 = \"41.208.110.46\" ascii wide\n\t\t$domain_1 = \"winmeif.myq-see.com\" ascii wide nocase\n\t\t$domain_2 = \"wininit.myq-see.com\" ascii wide nocase\n\t\t$domain_3 = \"samsung.ddns.me\" ascii wide nocase\n\t\t$domain_4 = \"collge.myq-see.com\" ascii wide nocase\n\t\t$domain_5 = \"sara2011.no-ip.biz\" ascii wide nocase\n\n\t",
        "rule_name": "libyan_scorpions",
        "start_line": 15,
        "stop_line": 39,
        "strings": [
            {
                "modifiers": [
                    "ascii",
                    "wide"
                ],
                "name": "$ip_1",
                "type": "text",
                "value": "41.208.110.46"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide",
                    "nocase"
                ],
                "name": "$domain_1",
                "type": "text",
                "value": "winmeif.myq-see.com"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide",
                    "nocase"
                ],
                "name": "$domain_2",
                "type": "text",
                "value": "wininit.myq-see.com"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide",
                    "nocase"
                ],
                "name": "$domain_3",
                "type": "text",
                "value": "samsung.ddns.me"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide",
                    "nocase"
                ],
                "name": "$domain_4",
                "type": "text",
                "value": "collge.myq-see.com"
            },
            {
                "modifiers": [
                    "ascii",
                    "wide",
                    "nocase"
                ],
                "name": "$domain_5",
                "type": "text",
                "value": "sara2011.no-ip.biz"
            }
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'batterybotpro', '{ClickFraud,AdFraud,SMS,Downloader_Trojan,android}', '{"author": "https://twitter.com/fdrg21", "sample": "cc4e024db858d7fa9b03d7422e760996de6a4674161efbba22d05f8b826e69d5", "description": "http://research.zscaler.com/2015/07/fake-batterybotpro-clickfraud-adfruad.html"}', '[
    {
        "condition_terms": [
            "androguard.activity",
            "(",
            "/com\\.polaris\\.BatteryIndicatorPro\\.BatteryInfoActivity/i",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android\\.permission\\.SEND_SMS/",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "description": "http://research.zscaler.com/2015/07/fake-batterybotpro-clickfraud-adfruad.html"
            },
            {
                "sample": "cc4e024db858d7fa9b03d7422e760996de6a4674161efbba22d05f8b826e69d5"
            },
            {
                "author": "https://twitter.com/fdrg21"
            }
        ],
        "raw_condition": "condition:\n\n\t\tandroguard.activity(/com\\.polaris\\.BatteryIndicatorPro\\.BatteryInfoActivity/i) and\n\t\tandroguard.permission(/android\\.permission\\.SEND_SMS/)\n\t\t\n",
        "raw_meta": "meta:\n\t\tdescription = \"http://research.zscaler.com/2015/07/fake-batterybotpro-clickfraud-adfruad.html\"\n\t\tsample = \"cc4e024db858d7fa9b03d7422e760996de6a4674161efbba22d05f8b826e69d5\"\n\t\tauthor = \"https://twitter.com/fdrg21\"\n\n\t",
        "rule_name": "batterybotpro",
        "start_line": 13,
        "stop_line": 25,
        "tags": [
            "ClickFraud",
            "AdFraud",
            "SMS",
            "Downloader_Trojan",
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'Android_Copy9', NULL, '{"date": "06-June-2016", "author": "Jacob Soo Lead Re", "source": "http://copy9.com/", "description": "This rule try to detect commercial spyware from Copy9"}', '[
    {
        "condition_terms": [
            "androguard.service",
            "(",
            "/com.ispyoo/i",
            ")",
            "and",
            "androguard.receiver",
            "(",
            "/com.ispyoo/i",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "Jacob Soo Lead Re"
            },
            {
                "date": "06-June-2016"
            },
            {
                "description": "This rule try to detect commercial spyware from Copy9"
            },
            {
                "source": "http://copy9.com/"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.service(/com.ispyoo/i) and\n        androguard.receiver(/com.ispyoo/i)\n",
        "raw_meta": "meta:\n\t\tauthor = \"Jacob Soo Lead Re\"\n\t\tdate = \"06-June-2016\"\n\t\tdescription = \"This rule try to detect commercial spyware from Copy9\"\n\t\tsource = \"http://copy9.com/\"\n\n\t",
        "rule_name": "Android_Copy9",
        "start_line": 3,
        "stop_line": 14
    }
]
');
INSERT INTO public.rule VALUES (default, 'leadbolt', '{advertising,android}', '{"author": "https://twitter.com/plutec_net", "reference": "https://koodous.com/", "description": "Leadbolt"}', '[
    {
        "condition_terms": [
            "androguard.url",
            "(",
            "/http:\\/\\/ad.leadbolt.net/",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "https://twitter.com/plutec_net"
            },
            {
                "reference": "https://koodous.com/"
            },
            {
                "description": "Leadbolt"
            }
        ],
        "raw_condition": "condition:\n\t\tandroguard.url(/http:\\/\\/ad.leadbolt.net/)\n",
        "raw_meta": "meta:\n\t  author = \"https://twitter.com/plutec_net\"\n\t\treference = \"https://koodous.com/\"\n\t\tdescription = \"Leadbolt\"\n\t\t\n\t",
        "rule_name": "leadbolt",
        "start_line": 13,
        "stop_line": 22,
        "tags": [
            "advertising",
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'android_mazarBot_z', '{android}', '{"author": "https://twitter.com/5h1vang", "sample": "73c9bf90cb8573db9139d028fa4872e93a528284c02616457749d40878af8cf8", "description": "Yara detection for MazarBOT", "reference_1": "https://heimdalsecurity.com/blog/security-alert-mazar-bot-active-attacks-android-malware/"}', '[
    {
        "condition_terms": [
            "androguard.certificate.sha1",
            "(",
            "\"50FD99C06C2EE360296DCDA9896AD93CAE32266B\"",
            ")",
            "or",
            "(",
            "androguard.package_name",
            "(",
            "\"com.mazar\"",
            ")",
            "and",
            "androguard.activity",
            "(",
            "/\\.DevAdminDisabler/",
            ")",
            "and",
            "androguard.receiver",
            "(",
            "/\\.DevAdminReceiver/",
            ")",
            "and",
            "androguard.service",
            "(",
            "/\\.WorkerService/i",
            ")",
            ")",
            "or",
            "androguard.permission",
            "(",
            "/android.permission.INTERNET/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.SEND_SMS/",
            ")",
            "and",
            "androguard.permission",
            "(",
            "/android.permission.CALL_PHONE/",
            ")",
            "and",
            "all",
            "of",
            "(",
            "$str_*",
            ")"
        ],
        "imports": [
            "androguard"
        ],
        "metadata": [
            {
                "author": "https://twitter.com/5h1vang"
            },
            {
                "reference_1": "https://heimdalsecurity.com/blog/security-alert-mazar-bot-active-attacks-android-malware/"
            },
            {
                "description": "Yara detection for MazarBOT"
            },
            {
                "sample": "73c9bf90cb8573db9139d028fa4872e93a528284c02616457749d40878af8cf8"
            }
        ],
        "raw_condition": "condition:\t\t\n\t\tandroguard.certificate.sha1(\"50FD99C06C2EE360296DCDA9896AD93CAE32266B\") or\n\t\t\n\t\t(androguard.package_name(\"com.mazar\") and\n\t\tandroguard.activity(/\\.DevAdminDisabler/) and \n\t\tandroguard.receiver(/\\.DevAdminReceiver/) and \n\t\tandroguard.service(/\\.WorkerService/i)) or \n\t\t\n\t\tandroguard.permission(/android.permission.INTERNET/) and\n\t\tandroguard.permission(/android.permission.SEND_SMS/) and\n\t\tandroguard.permission(/android.permission.CALL_PHONE/) and\n\t\tall of ($str_*)\n",
        "raw_meta": "meta:\n\t  author = \"https://twitter.com/5h1vang\"\n\t  reference_1 = \"https://heimdalsecurity.com/blog/security-alert-mazar-bot-active-attacks-android-malware/\"\n\t  description = \"Yara detection for MazarBOT\"\n\t  sample = \"73c9bf90cb8573db9139d028fa4872e93a528284c02616457749d40878af8cf8\"\n\n\t",
        "raw_strings": "strings:\n\t\t$str_1 = \"android.app.extra.ADD_EXPLANATION\"\n\t\t$str_2 = \"device_policy\"\n\t\t$str_3 = \"content://sms/\"\n\t\t$str_4 = \"#admin_start\"\n\t\t$str_5 = \"kill call\"\n\t\t$str_6 = \"unstop all numbers\"\n\t\t\n\t",
        "rule_name": "android_mazarBot_z",
        "start_line": 14,
        "stop_line": 42,
        "strings": [
            {
                "name": "$str_1",
                "type": "text",
                "value": "android.app.extra.ADD_EXPLANATION"
            },
            {
                "name": "$str_2",
                "type": "text",
                "value": "device_policy"
            },
            {
                "name": "$str_3",
                "type": "text",
                "value": "content://sms/"
            },
            {
                "name": "$str_4",
                "type": "text",
                "value": "#admin_start"
            },
            {
                "name": "$str_5",
                "type": "text",
                "value": "kill call"
            },
            {
                "name": "$str_6",
                "type": "text",
                "value": "unstop all numbers"
            }
        ],
        "tags": [
            "android"
        ]
    }
]
');
INSERT INTO public.rule VALUES (default, 'zeus_js', '{EK}', '{"date": "2016-06-26", "hash0": "c87ac7a25168df49a64564afb04dc961", "author": "Josh Berry", "description": "Zeus Exploit Kit Detection", "yaragenerator": "https://github.com/Xen0ph0n/YaraGenerator", "sample_filetype": "js-html"}', '[
    {
        "condition_terms": [
            "14",
            "of",
            "them"
        ],
        "metadata": [
            {
                "author": "Josh Berry"
            },
            {
                "date": "2016-06-26"
            },
            {
                "description": "Zeus Exploit Kit Detection"
            },
            {
                "hash0": "c87ac7a25168df49a64564afb04dc961"
            },
            {
                "sample_filetype": "js-html"
            },
            {
                "yaragenerator": "https://github.com/Xen0ph0n/YaraGenerator"
            }
        ],
        "raw_condition": "condition:\n\t14 of them\n",
        "raw_meta": "meta:\n\tauthor = \"Josh Berry\"\n\tdate = \"2016-06-26\"\n\tdescription = \"Zeus Exploit Kit Detection\"\n\thash0 = \"c87ac7a25168df49a64564afb04dc961\"\n\tsample_filetype = \"js-html\"\n\tyaragenerator = \"https://github.com/Xen0ph0n/YaraGenerator\"\n",
        "raw_strings": "strings:\n\t$string0 = \"var jsmLastMenu \"\n\t$string1 = \"position:absolute; z-index:99'' \"\n\t$string2 = \" -1)jsmSetDisplayStyle(''popupmenu'' \"\n\t$string3 = \" ''<tr><td><a href\"\n\t$string4 = \"  jsmLastMenu \"\n\t$string5 = \"  var ids \"\n\t$string6 = \"this.target\"\n\t$string7 = \" jsmPrevMenu, ''none'');\"\n\t$string8 = \"  if(jsmPrevMenu \"\n\t$string9 = \")if(MenuData[i])\"\n\t$string10 = \" ''<div style\"\n\t$string11 = \"popupmenu\"\n\t$string12 = \"  jsmSetDisplayStyle(''popupmenu'' \"\n\t$string13 = \"function jsmHideLastMenu()\"\n\t$string14 = \" MenuData.length; i\"\n",
        "rule_name": "zeus_js",
        "start_line": 1,
        "stop_line": 28,
        "strings": [
            {
                "name": "$string0",
                "type": "text",
                "value": "var jsmLastMenu "
            },
            {
                "name": "$string1",
                "type": "text",
                "value": "position:absolute; z-index:99'' "
            },
            {
                "name": "$string2",
                "type": "text",
                "value": " -1)jsmSetDisplayStyle(''popupmenu'' "
            },
            {
                "name": "$string3",
                "type": "text",
                "value": " ''<tr><td><a href"
            },
            {
                "name": "$string4",
                "type": "text",
                "value": "  jsmLastMenu "
            },
            {
                "name": "$string5",
                "type": "text",
                "value": "  var ids "
            },
            {
                "name": "$string6",
                "type": "text",
                "value": "this.target"
            },
            {
                "name": "$string7",
                "type": "text",
                "value": " jsmPrevMenu, ''none'');"
            },
            {
                "name": "$string8",
                "type": "text",
                "value": "  if(jsmPrevMenu "
            },
            {
                "name": "$string9",
                "type": "text",
                "value": ")if(MenuData[i])"
            },
            {
                "name": "$string10",
                "type": "text",
                "value": " ''<div style"
            },
            {
                "name": "$string11",
                "type": "text",
                "value": "popupmenu"
            },
            {
                "name": "$string12",
                "type": "text",
                "value": "  jsmSetDisplayStyle(''popupmenu'' "
            },
            {
                "name": "$string13",
                "type": "text",
                "value": "function jsmHideLastMenu()"
            },
            {
                "name": "$string14",
                "type": "text",
                "value": " MenuData.length; i"
            }
        ],
        "tags": [
            "EK"
        ]
    }
]
');


INSERT INTO host (account, hostname)
SELECT '540155',
       'system' || seq || '.com'
FROM GENERATE_SERIES(1, :SEED_HOST_COUNT) seq;

INSERT INTO scan (created_at, host_id)
SELECT ((now()::date - :SEED_DAYS) + (random() * :SEED_DAYS)::int) + (random() * INTERVAL '1 day'),
       (SELECT array_agg(id) FROM host)[random() * (SELECT count(*) - 1 FROM host) + 1]
FROM GENERATE_SERIES(1, :SEED_HOST_COUNT * :SEED_DAYS) seq
ON CONFLICT DO NOTHING;

INSERT INTO rule_scan (scan_id, rule_id)
SELECT (SELECT array_agg(id) FROM scan)[random() * (SELECT count(*) - 1 FROM scan) + 1],
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

