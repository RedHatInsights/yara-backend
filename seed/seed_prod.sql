--PGPASSWORD=postgres pg_dump -U postgres -h localhost -p 5434 -d yara -t rule --inserts > seed/seed_prod.sql

INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (1, 'IRIS_Mirai', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "md5_hash": "D768F57F122F5BA070FC88BE677BFE5B", "description": "Detects Mirai Bots", "date_created": "13 May 2019", "yara_version": "3.7"}', '2021-01-07 19:41:12.493806', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (2, 'IRIS_Mirai_X86', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "ticket": "IRIS-8552", "md5_hash": "57f90080f26c033b3bb39279fbe466efd8f62287f1d3f6ec2165e093d00d820b", "description": "Detects X86 Mirai Bots", "date_created": "Oct 26 2020", "yara_version": "3.7"}', '2021-01-07 19:41:12.498341', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (3, 'IRIS_Mirai_ARM7', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "ticket": "IRIS-8552", "md5_hash": "57f90080f26c033b3bb39279fbe466efd8f62287f1d3f6ec2165e093d00d820b", "description": "Detects ARM7 Mirai Bots", "date_created": "Oct 26 2020", "yara_version": "3.7"}', '2021-01-07 19:41:12.503033', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (4, 'IRIS_ZeroShell', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "ticket": "IRIS-8009", "description": "Detects ZeroShell samples.", "sha256_hash": "ea0bd1002078bb304b20d8ce5c475b622c0b13656bee37841a65d19c59223259", "date_created": "3 Aug 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:12.608434', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (5, 'IRIS_ZeroShell_ELF_ARM', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "ticket": "IRIS-8009", "description": "Detects ZeroShell ELF ARM samples.", "sha256_hash": "ea0bd1002078bb304b20d8ce5c475b622c0b13656bee37841a65d19c59223259", "date_created": "3 Aug 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:12.610686', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (6, 'IRIS_ZeroShell_ELF_32bit', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "ticket": "IRIS-8009", "description": "Detects ZeroShell 32bit ELF samples.", "sha256_hash": "ebfa0aa59700e61bcf064fd439fb18b030237f14f286c6587981af1e68a8e477", "date_created": "3 Aug 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:12.612383', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (7, 'IRIS_ZeroShell_ELF_64bit', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "ticket": "IRIS-8009", "description": "Detects ZeroShell 64bit ELF samples.", "date_created": "3 Aug 20", "yara_version": "4.0.2", "sha256_hash64": "6027d9ec503f69dbb58560a63e6acd62d7ab93f36bf8f676d282394a0e55be95"}', '2021-01-07 19:41:12.614524', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (8, 'XFTI_Punk', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force Threat Intelligence", "ticket": "IRIS-8624", "description": "Detects Punk post-exploitation tool.", "sha256_hash": "c2491f9b1f6eb9b1b31e84b0dd5505c5959947c47230af97dce18a49aab90e6b", "date_created": "30 Dec 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:12.71507', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (9, 'XFTI_FinSpy', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force Threat Intelligence", "ticket": "IRIS-8493", "description": "Detects FinSpy samples.", "sha256_hash": "bd1b8bc046dbf19f8c9bbf9398fdbc47c777e1d9e6d9ff1787ada05ed75c1b12", "date_created": "4 Nov 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:12.920117', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (10, 'IRIS_Linux__Generic_Backdoor', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "ticket": "IRIS-8469", "description": "Detects Linux Generic Backdoor samples.", "date_created": "6 Oct 20", "yara_version": "4.0.2", "sha256_hash64": "cbe81ca4f1d2b8af04eaebffd970db794909983e10f03673cdc2afb6c638696c"}', '2021-01-07 19:41:13.025383', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (11, 'XFTI_brootkit', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force Threat Intelligence", "ticket": "IRIS-8540", "description": "Detects brootkit rootkit.", "sha256_hash": "371ce879928eb3f35f77bcb8841e90c5e0257638b67989dc3d025823389b3f79", "date_created": "26 Oct 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:13.15056', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (12, 'IRIS_Kinsing', NULL, '{"hash": "b44dae9d1ce0ebec7a40e9aa49ac01e2c775fa9e354477a45b723c090b5a28f2", "usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "description": "Detects Kinsing Trojan", "date_created": "5 Aug 20", "yara_version": "4.02"}', '2021-01-07 19:41:13.26194', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (13, 'IRIS_Kinsing_downloader', NULL, '{"hash": "c73c876c7f3251d9b7428585eeabc0b050c2ff057db2058eaae233e696cf3eac", "usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "description": "Detects Kinsing Downloader", "date_created": "5 Aug 20", "yara_version": "4.02"}', '2021-01-07 19:41:13.264115', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (14, 'XFTI_IPStorm', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force Threat Intelligence", "ticket": "IRIS-8201", "description": "Detects IPStorm botnet samples.", "sha256_hash": "db9c95bdc4247ff6cdaf8a8e47b4add21a730461d8f6e2693136aecd346b3fb5", "date_created": "15 Oct 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:13.374222', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (15, 'XFTI_LinuxRansomware', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "md5_hash": "48f0da05ebce412728e5ce033d68f15d", "description": "Detects unnamed Linux Ransomware variant - possibly related to SFile or Escal", "date_created": "17 Nov 2020", "yara_version": "3.7"}', '2021-01-07 19:41:13.495822', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (16, 'IRIS_Doki', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "ticket": "IRIS-8201", "description": "Detects Doki malware.", "sha256_hash": "9907eaa1b487306c43b1352369f0409ba59a9aa0f5590fbd60e8825999db1f14", "date_created": "7 Oct 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:13.603049', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (17, 'XFTI_AnchorLinux', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force Threat Intelligence", "ticket": "IRIS-8201", "description": "Detects Anchor_Linux backdoor for Trickbot", "sha256_hash": "c721189a2b89cd279e9a033c93b8b5017dc165cba89eff5b8e1b5866195518bc", "date_created": "15 Oct 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:13.705757', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (18, 'IRIS_Trickbot_Loader', NULL, '{"author": "IBM X-Force IRIS", "sample_md5": "726145F66CCAC177E04D8C9587DB8A54", "description": "Detects unpacked Trickbot loader (32-bit)", "date_created": "31 January 2020", "yara_version": "3.11"}', '2021-01-07 19:41:13.84492', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (19, 'IRIS_Trickbot_core32', NULL, '{"author": "IBM X-Force IRIS", "description": "Detects unpacked Trickbot core (32bit) XOR function", "date_created": "07 October 2019", "yara_version": "3.7"}', '2021-01-07 19:41:13.847186', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (20, 'IRIS_Trickbot_core64', NULL, '{"md5": "08E94AC7B8A3428FFA5B5B5267313BF5", "author": "IBM X-Force IRIS", "description": "Detects unpacked Trickbot core (64bit) XOR function", "date_created": "13 February 2020", "yara_version": "3.11"}', '2021-01-07 19:41:13.849403', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (21, 'IRIS_Trickbot_Loader_64', NULL, '{"md5": "2C55E15C184446349678D099335B865D", "author": "IBM X-Force IRIS", "description": "Detects unpacked 64-bit Trickbot loader", "date_created": "13 February 2020", "yara_version": "3.11"}', '2021-01-07 19:41:13.850949', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (22, 'IRIS_Trickbot_module', NULL, '{"author": "IBM X-Force IRIS", "description": "Generic Trickbot module detection", "date_created": "23 September 2019", "yara_version": "3.7"}', '2021-01-07 19:41:13.853215', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (23, 'IRIS_Trickbot_importDLL', NULL, '{"author": "IBM X-Force IRIS", "md5_hash": "b6c58eff64e385312926ae27cbf14ed8", "description": "Detects Trickbot importDLL module", "date_created": "23 September 2019", "yara_version": "3.7"}', '2021-01-07 19:41:13.855904', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (24, 'IRIS_Trickbot_injectDLL', NULL, '{"author": "IBM X-Force IRIS", "md5_hash": "94cf72da8dc69ce79bf96c055cd2e455", "description": "Detects Trickbot injectDLL module", "date_created": "23 September 2019", "yara_version": "3.7"}', '2021-01-07 19:41:13.858507', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (25, 'IRIS_Trickbot_mailsearcher', NULL, '{"author": "IBM X-Force IRIS", "md5_hash": "8b76a667d2de4c96e8b38ea37e56dfc1", "description": "Detects Trickbot mailsearcher module", "date_created": "30 September 2019", "yara_version": "3.7"}', '2021-01-07 19:41:13.861064', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (26, 'IRIS_Trickbot_networkDLL', NULL, '{"author": "IBM X-Force IRIS", "md5_hash": "dfea960bc5c888fe39b7ff83008a1dde", "description": "Detects Trickbot networkDLL module", "date_created": "30 September 2019", "yara_version": "3.7"}', '2021-01-07 19:41:13.863927', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (27, 'IRIS_Trickbot_NewBCtestnDLL', NULL, '{"author": "IBM X-Force IRIS", "md5_hash": "bdc49363dd9b13f4e6cbe5bc2017a5a2", "description": "Detects Trickbot NewBCtestnDLL module", "date_created": "30 September 2019", "yara_version": "3.7"}', '2021-01-07 19:41:13.866967', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (28, 'IRIS_Trickbot_psfin', NULL, '{"author": "IBM X-Force IRIS", "md5_hash": "b2b50fe0b5cfcf6ada8289c9317fa984", "description": "Detects Trickbot psfin module", "date_created": "30 September 2019", "yara_version": "3.7"}', '2021-01-07 19:41:13.869649', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (29, 'IRIS_Trickbot_pwgrab', NULL, '{"author": "IBM X-Force IRIS", "md5_hash": "7faa8d17a9b7517e95725f8844c18292", "description": "Detects Trickbot pwgrab module", "date_created": "30 September 2019", "yara_version": "3.7"}', '2021-01-07 19:41:13.872094', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (30, 'IRIS_Trickbot_shareDll', NULL, '{"author": "IBM X-Force IRIS", "md5_hash": "9dc9a2a0cdbb25fc587ff32cba96a2c3", "description": "Detects Trickbot shareDll module", "date_created": "01 October 2019", "yara_version": "3.7"}', '2021-01-07 19:41:13.875131', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (31, 'IRIS_Trickbot_systeminfo', NULL, '{"author": "IBM X-Force IRIS", "md5_hash": "6ee8252d5eb1f4bb3dee0fc6e78500e5", "description": "Detects Trickbot systeminfo module", "date_created": "01 October 2019", "yara_version": "3.7"}', '2021-01-07 19:41:13.878531', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (32, 'IRIS_Trickbot_tabDll', NULL, '{"author": "IBM X-Force IRIS", "md5_hash": "51aa9c132ec6741a397bd7df3a3a3eb1", "description": "Detects Trickbot tabDll module", "date_created": "01 October 2019", "yara_version": "3.7"}', '2021-01-07 19:41:13.882516', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (33, 'IRIS_Trickbot_vncDll', NULL, '{"author": "IBM X-Force IRIS", "md5_hash": "5c54c8b829c8aee4ddd1eceebc5122cd", "description": "Detects Trickbot vncDll module", "date_created": "01 October 2019", "yara_version": "3.7"}', '2021-01-07 19:41:13.886293', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (34, 'IRIS_Trickbot_wormDll', NULL, '{"author": "IBM X-Force IRIS", "md5_hash": "93ec64dc4a53b9980070114244b12465", "description": "Detects Trickbot wormDll module", "date_created": "01 October 2019", "yara_version": "3.7"}', '2021-01-07 19:41:13.890182', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (35, 'IRIS_Trickbot_templDll', NULL, '{"author": "IBM X-Force IRIS", "md5_hash": "D8806D98712722A81E045540974C3334", "description": "Detects Trickbot templDll module format.", "date_created": "07 October 2019", "yara_version": "3.7"}', '2021-01-07 19:41:13.893439', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (36, 'IRIS_Trickbot_Anchor_DNS', NULL, '{"author": "IBM X-Force IRIS", "description": "Detects Trickbot Anchor DNS samples", "date_created": "13 December 2019", "yara_version": "3.7"}', '2021-01-07 19:41:13.896656', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (37, 'IRIS_Chalubo_Downloader', NULL, '{"hash1": "19ef212c4f3406b6aca1c2ce11619443e33ac64aa9688cba64671d3679b73221", "hash2": "5270efedbd96a80213e1480c085a18b336162e399b9af58f21403869f61b4115", "usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "ticket": "IRIS-6024", "description": "Detects the Chalubo Downloader", "date_created": "14 Feb 20", "yara_version": "3.7"}', '2021-01-07 19:41:14.028086', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (38, 'IRIS_Chalubo_bot', NULL, '{"hash1": "27a7d733f0013acdc2f67d5522e269f7f6449f38e0ca8f399aa3421cecc7109c", "usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "ticket": "IRIS-6024", "description": "Detects the Chalubo Bot", "date_created": "14 Feb 20", "yara_version": "3.7"}', '2021-01-07 19:41:14.030332', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (39, 'IRIS_Defray911_Loader', NULL, '{"hash": "68cb520d2084020638790187e34638ea", "usage": "Hunting and Identification", "author": "IBM X Force IRIS", "ticket": "IRIS-7274", "description": "Detects Defray911 Rainmeter Loader", "date_created": "22 June 20", "yara_version": "3.11"}', '2021-01-07 19:41:14.13874', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (40, 'IRIS_Defray911_Shellcode_Loader', NULL, '{"hash": "07415ADD8DE43208959ACDF15D88DF69", "usage": "Hunting and Identification", "author": "IBM X Force IRIS", "ticket": "IRIS-7274", "description": "Detects Defray911 Shellcode Loader", "date_created": "22 June 20", "yara_version": "3.11"}', '2021-01-07 19:41:14.141066', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (41, 'IRIS_Defray911_Ransomware', NULL, '{"hash": "26ddabd889bee996a65604ba39d892e5", "usage": "Hunting and Identification", "author": "IBM X Force IRIS", "ticket": "IRIS-7274", "description": "Detects Defray911 Ransomware", "date_created": "22 June 20", "yara_version": "3.11"}', '2021-01-07 19:41:14.142966', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (42, 'IRIS_Defray911_Ransom_Note', NULL, '{"hash": "F0AB69A0DF265AB27AAC084B2EC0A43E", "usage": "Hunting and Identification", "author": "IBM X Force IRIS", "ticket": "IRIS-7274", "description": "Detects Defray911 Ransom Note and variant", "date_created": "22 June 20", "yara_version": "3.11"}', '2021-01-07 19:41:14.144955', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (43, 'IRIS_Defray911_Linux_Ransomware', NULL, '{"hash": "210f47c8f47ded8525da927710abc6ad", "usage": "Hunting and Identification", "author": "IBM X Force IRIS", "ticket": "IRIS-7274", "description": "Detects the Linux variant of the Defray911 Ransomware", "date_created": "17 August 2020", "yara_version": "3.11"}', '2021-01-07 19:41:14.147022', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (44, 'IRIS_Defray_Decryptor_Win', NULL, '{"usage": "Memory Scanning", "author": "IBM X Force IRIS", "ticket": "IRIS-8626", "description": "Detects Defray Windows Decryptor in memory only (due to Themida packing)", "date_created": "03 November 2020", "yara_version": "3.11"}', '2021-01-07 19:41:14.148964', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (45, 'IRIS_Win_Dacls', NULL, '{"hash": "cef99063e85af8b065de0ffa9d26cb03", "usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "description": "Detects the Windows variant of the Dacls Trojan.", "date_created": "12 Aug 19", "yara_version": "3.10"}', '2021-01-07 19:41:14.25315', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (46, 'IRIS_Dacls', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "description": "Detects variants of the Dacls Trojan.", "date_created": "9 Mar 20", "yara_version": "3.10"}', '2021-01-07 19:41:14.255167', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (47, 'IRIS_Linux_Dacls', NULL, '{"hash": "80c0efb9e129f7f9b05a783df6959812", "usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "description": "Detects the Linux variant of the Dacls Trojan.", "date_created": "9 Mar 20", "yara_version": "3.10"}', '2021-01-07 19:41:14.258453', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (48, 'IRIS_MacOS_Dacls', NULL, '{"hash": "f05437d510287448325bac98a1378de1", "usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "description": "Detects the Mach-O variant of the Dacls Trojan.", "date_created": "15 Apr 20", "yara_version": "3.10"}', '2021-01-07 19:41:14.26106', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (49, 'IRIS_StealthWorker', NULL, '{"hash": "bf00575032b58b36b93b32b9a12c5b5d", "usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "ticket": "IRIS-7235", "description": "Detects the StealthWorker golang malware family by looking for unique strings", "date_created": "20 Jul 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:14.366728', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (50, 'IRIS_Echobot_Dropper', NULL, '{"hash": "", "usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "description": "Detects Echobot Dropper", "date_created": "03 Mar 2020", "yara_version": "3.9"}', '2021-01-07 19:41:14.472751', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (51, 'IRIS_Echobot', NULL, '{"hash": "6592eae817483acd41a2a6d748b4cc7d", "usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "description": "Detects Echobot ", "date_created": "03 Mar 2020", "yara_version": "3.9"}', '2021-01-07 19:41:14.475143', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (52, 'XFTI_GuardianInstaller', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force Threat Intelligence", "ticket": "IRIS-8540", "description": "Detects GuardianInstaller samples.", "sha256_hash": "59fa110c24920aacbf668baacadce7154265c2a3dca01d968f21b568bda2130b", "date_created": "16 Oct 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:14.575431', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (53, 'XFTI_UPX_GuardianInstaller', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force Threat Intelligence", "ticket": "IRIS-8540", "description": "Detects UPX-packed GuardianInstaller samples.", "sha256_hash": "e0d1a482b4df92def48cf714584fa417ce914b50ee28cc595bbf89bad76429d1", "date_created": "26 Oct 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:14.577755', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (54, 'XFTI_FritzFrog', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force Threat Intelligence", "ticket": "IRIS-8201", "description": "Detects FritzFrog P2P botnet samples.", "sha256_hash": "001eb377f0452060012124cb214f658754c7488ccb82e23ec56b2f45a636c859", "date_created": "15 Oct 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:14.676501', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (55, 'IRIS_Gafgypt_X64', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "ticket": "IRIS-7901", "description": "Detects Gafgypt 64bit ELF samples.", "sha256_hash": "0e776d75be2f260790ce87a6c141476ef3df3195cda7da30eb71f326265d22ab", "date_created": "5 Oct 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:14.78409', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (56, 'IRIS_Generic_Gafgypt', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "ticket": "IRIS-7901", "description": "Detects Generic Gafgypt samples.", "date_created": "8 Oct 20", "yara_version": "4.0.2", "sha256_hash64": "437eea41f257cfc115913ff8350a460ab28b64b1ed604ab1d6bb923c7e248ac9"}', '2021-01-07 19:41:14.786281', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (57, 'IRIS_Linux__Generic_Gafgypt_ARM', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "ticket": "IRIS-7901", "description": "Detects Generic Gafgypt ARM samples.", "sha256_hash": "d107c80446207dd650f1326536c9cf2e28ea9b922e0debf3306bc734a35f9cdd", "date_created": "8 Oct 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:14.788702', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (58, 'IRIS_Linux__Generic_Gafgypt_X86', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "ticket": "IRIS-7901", "description": "Detects Generic Gafgypt X86 samples.", "sha256_hash": "437eea41f257cfc115913ff8350a460ab28b64b1ed604ab1d6bb923c7e248ac9", "date_created": "8 Oct 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:14.791454', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (59, 'IRIS_Linux__Generic_Gafgypt_X64', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "ticket": "IRIS-7901", "description": "Detects Generic Gafgypt X64 samples.", "sha256_hash": "7828b1e7bb069ae66bc4a90bf4f2961d3a617feb117a6c5ef675efa735ba8119", "date_created": "8 Oct 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:14.793493', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (60, 'IRIS_Linux__Generic_Gafgypt_MIPS', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "ticket": "IRIS-7901", "description": "Detects Generic Gafgypt MIPS samples.", "sha256_hash": "bf5861c804c70edfb331d19222276be18cd71a0787e9c57e89f7199111d9454a", "date_created": "8 Oct 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:14.796166', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (61, 'IRIS_Linux__Generic_Gafgypt_PPC', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force IRIS", "ticket": "IRIS-7901", "description": "Detects Generic Gafgypt PPC samples.", "sha256_hash": "55087b9eb76619a56fa8f0a4ce7ce3e275ed26c012a58760239a1054a1485c5a", "date_created": "8 Oct 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:14.798841', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (62, 'XFTI_Lucifer', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force Threat Intelligence", "ticket": "IRIS-8679", "description": "Detects lucifer botnet samples.", "sha256_hash": "3ea56bcf897cb8909869e1bfc35f47e1c8a454dd891c5396942c1255aa09b0ce", "date_created": "30 Dec 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:14.909652', '');
INSERT INTO public.rule OVERRIDING SYSTEM VALUE VALUES (63, 'XFTI_WellMess', NULL, '{"usage": "Hunting and Identification", "author": "IBM X-Force Threat Intelligence", "ticket": "IRIS-8530", "description": "Detects APT29 WellMess Elf binaries", "sha256_hash": "0b8e6a11adaa3df120ec15846bb966d674724b6b92eae34d63b665e0698e0193", "date_created": "19 Oct 20", "yara_version": "4.0.2"}', '2021-01-07 19:41:15.010109', '');

