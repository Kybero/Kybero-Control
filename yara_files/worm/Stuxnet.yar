rule Worm_Stuxnet_A_con {
    meta:
        threat_name = "Worm/Stuxnet.A!con"
        author = "JAG-S (turla@chronicle.security)"
        hash = "c1961e54d60e34bbec397c9120564e8d08f2f243ae349d2fb20f736510716579"
        description = "Stuxshop standalone sample configuration"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stuxnet"
        malpedia_version = "20190418"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $cnc1 = "http://211.24.237.226/index.php?data=" ascii wide
        $cnc2 = "http://todaysfutbol.com/index.php?data=" ascii wide
        $cnc3 = "http://78.111.169.146/index.php?data=" ascii wide
        $cnc4 = "http://mypremierfutbol.com/index.php?data=" ascii wide
        $regkey1  =  "Software\\Microsoft\\Windows\\CurrentVersion\\MS-DOS Emulation" ascii wide
        $regkey2  =  "NTVDMParams" ascii wide
        $flowerOverlap1 = { 85 C0 75 3B 57 FF 75 1C FF 75 18 FF 75 14 50 FF 75 10 FF 75 FC FF 15 }
        $flowerOverlap2 = { 85 C0 75 4C 8B 45 1C 89 45 0C 8D 45 0C 50 8D 45 08 FF 75 18 50 6A 00 FF 75 10 FF 75 20 FF 15 }
        $flowerOverlap3  = { 55 8B EC 53 56 8B 75 20 85 F6 74 03 83 26 00 8D 45 20 5068 19 00 02 00 6A 00 FF 75 0C FF 75 08 }
        $flowerOverlap4  = { 55 8B EC 51 8D 4D FC 33 C0 51 50 6A 26 50 89 45 FC FF 15 }
        $flowerOverlap5  = { 85 DB 74 04 8B C3 EB 1A 8B 45 08 3B 45 14 74 07 B8 5D 06 00 00 EB 0B 85 F6 74 05 8B 45 0C 89 06 }
        $flowerOverlap6  = {   85 FF 74 12 83 7D F8 01 75 0C FF 75 0C FF 75 08 FF 15 }
    condition:
        all of  ($flowerOverlap*) or 2 of ($cnc*) or all of  ($regkey*)
}

rule Worm_Stuxnet_B_con {
    meta:
        threat_name = "Worm/Stuxnet.B!con"
        author = "Silas Cutler (havex@Chronicle.Security)"
        desc = "Identifies the OS Check function in STUXSHOP and CheshireCat"
        hash = "c1961e54d60e34bbec397c9120564e8d08f2f243ae349d2fb20f736510716579"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stuxnet"
        malpedia_version = "20190418"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $ = {10 F7 D8 1B C0 83 C0 ?? E9 ?? 01 00 00 39 85 7C FF FF FF 0F 85 ?? 01 00 00 83 BD 70 FF FF FF 04 8B 8D 74 FF FF FF 75 0B 85 C9 0F 85 ?? 01 00 00 6A 05 5E }
        $ = {01 00 00 3B FA 0F 84 ?? 01 00 00 80 7D 80 00 B1 62 74 1D 6A 0D 8D 45 80 68 ?? ?? ?? 10 50 FF 15 ?? ?? ?? 10 83 C4 0C B1 6F 85 C0 75 03 8A 4D 8D 8B C6 }
    condition:
        any of them
}

rule Worm_Stuxnet_C_con {
	meta:
        threat_name = "Worm/Stuxnet.C!con"
		description = "Stuxnet Sample - file malware.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "9c891edb5da763398969b6aaa86a5d46971bd28a455b20c2067cb512c9f9a0f8"
		id = "1f475dc3-ebb3-508f-b696-3d9ea270b13d"
	strings:
		 // 0x10001778 8b 45 08  mov     eax, dword ptr [ebp + 8]
		 // 0x1000177b 35 dd 79 19 ae    xor     eax, 0xae1979dd
		 // 0x10001780 33 c9     xor     ecx, ecx
		 // 0x10001782 8b 55 08  mov     edx, dword ptr [ebp + 8]
		 // 0x10001785 89 02     mov     dword ptr [edx], eax
		 // 0x10001787 89 ?? ??  mov     dword ptr [edx + 4], ecx
		 $op1 = { 8b 45 08 35 dd 79 19 ae 33 c9 8b 55 08 89 02 89 }
		 // 0x10002045 74 36     je      0x1000207d
		 // 0x10002047 8b 7f 08  mov     edi, dword ptr [edi + 8]
		 // 0x1000204a 83 ff 00  cmp     edi, 0
		 // 0x1000204d 74 2e     je      0x1000207d
		 // 0x1000204f 0f b7 1f  movzx   ebx, word ptr [edi]
		 // 0x10002052 8b 7f 04  mov     edi, dword ptr [edi + 4]
		 $op2 = { 74 36 8b 7f 08 83 ff 00 74 2e 0f b7 1f 8b 7f 04 }
		 // 0x100020cf 74 70     je      0x10002141
		 // 0x100020d1 81 78 05 8d 54 24 04      cmp     dword ptr [eax + 5], 0x424548d
		 // 0x100020d8 75 1b     jne     0x100020f5
		 // 0x100020da 81 78 08 04 cd ?? ??      cmp     dword ptr [eax + 8], 0xc22ecd04
		 $op3 = { 74 70 81 78 05 8d 54 24 04 75 1b 81 78 08 04 cd }
	condition:
		all of them
}

rule Worm_Stuxnet_D_con {
	meta:
        threat_name = "Worm/Stuxnet.D!con"
		description = "Stuxnet Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "63e6b8136058d7a06dfff4034b4ab17a261cdf398e63868a601f77ddd1b32802"
		id = "2865353c-44c5-5280-878b-daadcef017b8"
	strings:
		$s1 = "\\SystemRoot\\System32\\hal.dll" wide
		$s2 = "http://www.jmicron.co.tw0" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 70KB and all of them
}

rule Worm_Stuxnet_E_con {
	meta:
        threat_name = "Worm/Stuxnet.E!con"
		description = "Stuxnet Sample - file dll.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "9e392277f62206098cf794ddebafd2817483cfd57ec03c2e05e7c3c81e72f562"
		id = "92d812a6-2622-56e4-96c5-eb65ab7055b9"
	strings:
		$s1 = "SUCKM3 FROM EXPLORER.EXE MOTH4FUCKA #@!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and $s1
}

rule Worm_Stuxnet_F_con {
	meta:
        threat_name = "Worm/Stuxnet.F!con"
		description = "Stuxnet Sample - file Copy of Shortcut to.lnk"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "801e3b6d84862163a735502f93b9663be53ccbdd7f12b0707336fecba3a829a2"
		id = "582ab12b-808e-5d5c-ba36-3bb987c4c552"
	strings:
		$x1 = "\\\\.\\STORAGE#Volume#_??_USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler_2.0&Rev_PMAP#5B6B098B97BE&0#{53f56307-b6bf-11d0-94f2-00a0c" wide
	condition:
		uint16(0) == 0x004c and filesize < 10KB and $x1
}

rule Worm_Stuxnet_G_con {
	meta:
        threat_name = "Worm/Stuxnet.G!con"
		description = "Stuxnet Sample - file ~WTR4141.tmp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "6bcf88251c876ef00b2f32cf97456a3e306c2a263d487b0a50216c6e3cc07c6a"
		hash2 = "70f8789b03e38d07584f57581363afa848dd5c3a197f2483c6dfa4f3e7f78b9b"
		id = "1b0b301a-bf29-5080-a7d6-4d5f389bdf50"
	strings:
		$x1 = "SHELL32.DLL.ASLR." fullword wide

		$s1 = "~WTR4141.tmp" fullword wide
		$s2 = "~WTR4132.tmp" fullword wide
		$s3 = "totalcmd.exe" fullword wide
		$s4 = "wincmd.exe" fullword wide
		$s5 = "http://www.realtek.com0" fullword ascii
		$s6 = "{%08x-%08x-%08x-%08x}" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 150KB and ( $x1 or 3 of ($s*) ) ) or ( 5 of them )
}

rule Worm_Stuxnet_H_con {
	meta:
        threat_name = "Worm/Stuxnet.H!con"
		description = "Stuxnet Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "0d8c2bcb575378f6a88d17b5f6ce70e794a264cdc8556c8e812f0b5f9c709198"
		hash2 = "1635ec04f069ccc8331d01fdf31132a4bc8f6fd3830ac94739df95ee093c555c"
		id = "fd3fa395-15f1-5a11-9740-03b897e4620b"
	strings:
		$x1 = "\\objfre_w2k_x86\\i386\\guava.pdb" ascii
		$x2 = "MRxCls.sys" fullword wide
		$x3 = "MRXNET.Sys" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 80KB and 1 of them ) or ( all of them )
}

rule Worm_Stuxnet_I_con {
	meta:
        threat_name = "Worm/Stuxnet.I!con"
		description = "Stuxnet Sample - file maindll.decrypted.unpacked.dll_"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "4c3d7b38339d7b8adf73eaf85f0eb9fab4420585c6ab6950ebd360428af11712"
		id = "7009a41c-0588-5392-ae1c-045e0a5ee56b"
	strings:
		$s1 = "%SystemRoot%\\system32\\Drivers\\mrxsmb.sys;%SystemRoot%\\system32\\Drivers\\*.sys" fullword wide
		$s2 = "<Actions Context=\"%s\"><Exec><Command>%s</Command><Arguments>%s,#%u</Arguments></Exec></Actions>" fullword wide
		$s3 = "%SystemRoot%\\inf\\oem7A.PNF" fullword wide
		$s4 = "%SystemRoot%\\inf\\mdmcpq3.PNF" fullword wide
		$s5 = "%SystemRoot%\\inf\\oem6C.PNF" fullword wide
		$s6 = "@abf varbinary(4096) EXEC @hr = sp_OACreate 'ADODB.Stream', @aods OUT IF @hr <> 0 GOTO endq EXEC @hr = sp_OASetProperty @" wide
		$s7 = "STORAGE#Volume#1&19f7e59c&0&" fullword wide
		$s8 = "view MCPVREADVARPERCON as select VARIABLEID,VARIABLETYPEID,FORMATFITTING,SCALEID,VARIABLENAME,ADDRESSPARAMETER,PROTOKOLL,MAXLIMI" ascii
	condition:
		 6 of them
}

rule Worm_Stuxnet_J_con {
	meta:
        threat_name = "Worm/Stuxnet.J!con"
		description = "Stuxnet Sample - file s7hkimdb.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-07-09"
		hash1 = "4071ec265a44d1f0d42ff92b2fa0b30aafa7f6bb2160ed1d0d5372d70ac654bd"
		id = "e4cb277f-5eee-5405-9d48-d06657392323"
	strings:
		$x1 = "S7HKIMDX.DLL" fullword wide

		/* Opcodes by Binar.ly */

		// 0x10001778 8b 45 08  mov     eax, dword ptr [ebp + 8]
		// 0x1000177b 35 dd 79 19 ae    xor     eax, 0xae1979dd
		// 0x10001780 33 c9     xor     ecx, ecx
		// 0x10001782 8b 55 08  mov     edx, dword ptr [ebp + 8]
		// 0x10001785 89 02     mov     dword ptr [edx], eax
		// 0x10001787 89 ?? ??  mov     dword ptr [edx + 4], ecx
		$op1 = { 8b 45 08 35 dd 79 19 ae 33 c9 8b 55 08 89 02 89 }
		// 0x10002045 74 36     je      0x1000207d
		// 0x10002047 8b 7f 08  mov     edi, dword ptr [edi + 8]
		// 0x1000204a 83 ff 00  cmp     edi, 0
		// 0x1000204d 74 2e     je      0x1000207d
		// 0x1000204f 0f b7 1f  movzx   ebx, word ptr [edi]
		// 0x10002052 8b 7f 04  mov     edi, dword ptr [edi + 4]
		$op2 = { 74 36 8b 7f 08 83 ff 00 74 2e 0f b7 1f 8b 7f 04 }
		// 0x100020cf 74 70     je      0x10002141
		// 0x100020d1 81 78 05 8d 54 24 04      cmp     dword ptr [eax + 5], 0x424548d
		// 0x100020d8 75 1b     jne     0x100020f5
		// 0x100020da 81 78 08 04 cd ?? ??      cmp     dword ptr [eax + 8], 0xc22ecd04
		$op3 = { 74 70 81 78 05 8d 54 24 04 75 1b 81 78 08 04 cd }

	condition:
		( uint16(0) == 0x5a4d and filesize < 40KB and $x1 and all of ($op*) )
}
