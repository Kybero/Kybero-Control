rule Trojan_Upatre_A_con {

    meta:
	threat_name = "Trojan/Upatre.A!con"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2024-10-31"
        version = "1"
        description = "Detects win.upatre."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.upatre"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 7404 66ab ebf5 8b7594 }
            // n = 4, score = 200
            //   7404                 | je                  6
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   ebf5                 | jmp                 0xfffffff7
            //   8b7594               | mov                 esi, dword ptr [ebp - 0x6c]

        $sequence_1 = { 33c0 ac 8945a4 897da0 }
            // n = 4, score = 200
            //   33c0                 | xor                 eax, eax
            //   ac                   | lodsb               al, byte ptr [esi]
            //   8945a4               | mov                 dword ptr [ebp - 0x5c], eax
            //   897da0               | mov                 dword ptr [ebp - 0x60], edi

        $sequence_2 = { 3c01 740c b053 66ab b045 }
            // n = 5, score = 200
            //   3c01                 | cmp                 al, 1
            //   740c                 | je                  0xe
            //   b053                 | mov                 al, 0x53
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   b045                 | mov                 al, 0x45

        $sequence_3 = { 66ad 8945ac 33c0 8bc8 }
            // n = 4, score = 200
            //   66ad                 | lodsw               ax, word ptr [esi]
            //   8945ac               | mov                 dword ptr [ebp - 0x54], eax
            //   33c0                 | xor                 eax, eax
            //   8bc8                 | mov                 ecx, eax

        $sequence_4 = { b02f 66ab ff7590 33c0 b404 57 03f8 }
            // n = 7, score = 200
            //   b02f                 | mov                 al, 0x2f
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   ff7590               | push                dword ptr [ebp - 0x70]
            //   33c0                 | xor                 eax, eax
            //   b404                 | mov                 ah, 4
            //   57                   | push                edi
            //   03f8                 | add                 edi, eax

        $sequence_5 = { 50 6880000000 6a02 50 6a02 6800000040 ff75f0 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   6880000000           | push                0x80
            //   6a02                 | push                2
            //   50                   | push                eax
            //   6a02                 | push                2
            //   6800000040           | push                0x40000000
            //   ff75f0               | push                dword ptr [ebp - 0x10]

        $sequence_6 = { ff75f0 ff55f8 50 ebe7 56 ff55fc }
            // n = 6, score = 200
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   ff55f8               | call                dword ptr [ebp - 8]
            //   50                   | push                eax
            //   ebe7                 | jmp                 0xffffffe9
            //   56                   | push                esi
            //   ff55fc               | call                dword ptr [ebp - 4]

        $sequence_7 = { b02f 66ab 8b45a8 ff5504 33c9 8ac8 ff5508 }
            // n = 7, score = 200
            //   b02f                 | mov                 al, 0x2f
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   8b45a8               | mov                 eax, dword ptr [ebp - 0x58]
            //   ff5504               | call                dword ptr [ebp + 4]
            //   33c9                 | xor                 ecx, ecx
            //   8ac8                 | mov                 cl, al
            //   ff5508               | call                dword ptr [ebp + 8]

        $sequence_8 = { 8b4dfc 51 e8???????? 83c408 8945d8 }
            // n = 5, score = 100
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax

        $sequence_9 = { 0f84fa000000 8b55f8 52 8b45d8 }
            // n = 4, score = 100
            //   0f84fa000000         | je                  0x100
            //   8b55f8               | mov                 edx, dword ptr [ebp - 8]
            //   52                   | push                edx
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]

        $sequence_10 = { 8b4dc4 51 e8???????? 8b55d0 52 e8???????? e9???????? }
            // n = 7, score = 100
            //   8b4dc4               | mov                 ecx, dword ptr [ebp - 0x3c]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   8b55d0               | mov                 edx, dword ptr [ebp - 0x30]
            //   52                   | push                edx
            //   e8????????           |                     
            //   e9????????           |                     

        $sequence_11 = { 0dc21748db 60 23e7 1b800fa46451 }
            // n = 4, score = 100
            //   0dc21748db           | or                  eax, 0xdb4817c2
            //   60                   | pushal              
            //   23e7                 | and                 esp, edi
            //   1b800fa46451         | sbb                 eax, dword ptr [eax + 0x5164a40f]

        $sequence_12 = { 753b 6a01 8d4dcf 51 8b55fc }
            // n = 5, score = 100
            //   753b                 | jne                 0x3d
            //   6a01                 | push                1
            //   8d4dcf               | lea                 ecx, [ebp - 0x31]
            //   51                   | push                ecx
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_13 = { 51 e8???????? 83c40c eb2b 8b55f4 8b420c 50 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   eb2b                 | jmp                 0x2d
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   8b420c               | mov                 eax, dword ptr [edx + 0xc]
            //   50                   | push                eax

        $sequence_14 = { 05c8000000 3bc8 7c22 0fb74df8 }
            // n = 4, score = 100
            //   05c8000000           | add                 eax, 0xc8
            //   3bc8                 | cmp                 ecx, eax
            //   7c22                 | jl                  0x24
            //   0fb74df8             | movzx               ecx, word ptr [ebp - 8]

        $sequence_15 = { eb58 8b4df4 8b510c 52 e8???????? 83c404 0fb7c0 }
            // n = 7, score = 100
            //   eb58                 | jmp                 0x5a
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   8b510c               | mov                 edx, dword ptr [ecx + 0xc]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   0fb7c0               | movzx               eax, ax

    condition:
        7 of them and filesize < 294912
}

rule Trojan_Upatre_B_con {
	meta:
		threat_name = "Trojan/Upatre.B!con"
		author = "Florian Roth"
		description = "Detects Upatre malware - file hazgurut.exe"
		reference = "https://weankor.vxstream-sandbox.com/sample/6b857ef314938d37997c178ea50687a281d8ff9925f0c4e70940754643e2c0e3?environmentId=7"
		date = "2015-10-13"
		score = 70
		hash = "7ee0d20b15e24b7fe72154d9521e1959752b4e9c20d2992500df9ac096450a50"
		hash = "79ffc620ddb143525fa32bc6a83c636168501a4a589a38cdb0a74afac1ee8b92"
		hash = "62d8a6880c594fe9529158b94a9336179fa7a3d3bf1aa9d0baaf07d03b281bd3"
		hash = "c64282aca980d558821bec8b3dfeae562d9620139dc43d02ee4d1745cd989f2a"
		hash = "a35f9870f9d4b993eb094460b05ee1f657199412807abe6264121dd7cc12aa70"
		hash = "f8cb2730ebc8fac1c58da1346ad1208585fe730c4f03d976eb1e13a1f5d81ef9"
		hash = "b65ad7e2d299d6955d95b7ae9b62233c34bc5f6aa9f87dc482914f8ad2cba5d2"
		hash = "6b857ef314938d37997c178ea50687a281d8ff9925f0c4e70940754643e2c0e3"
		hash = "33a288cef0ae7192b34bd2ef3f523dfb7c6cbc2735ba07edf988400df1713041"
		hash = "2a8e50afbc376cb2a9700d2d83c1be0c21ef942309676ecac897ba4646aba273"
		hash = "3d0f2c7e07b7d64b1bad049b804ff1aae8c1fc945a42ad555eca3e1698c7f7d3"
		hash = "951360b32a78173a1f81da0ded8b4400e230125d05970d41621830efc5337274"
		hash = "bd90faebfd7663ef89b120fe69809532cada3eb94bb94094e8bc615f70670295"
		hash = "8c5823f67f9625e4be39a67958f0f614ece49c18596eacc5620524bc9b6bad3d"
		source = "https://github.com/mattulm/sfiles_yara/blob/master/malware/upatre_oct15.yar"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.upatre"
        malpedia_version = "20170517"
        malpedia_license = "CC BY-NC-SA 4.0"
        malpedia_sharing = "TLP:WHITE"
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
		$a1 in (0..4000) and all of ($s*)
}
