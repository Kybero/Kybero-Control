import "pe"

rule Trojan_Generic_A {
    meta:
        description = "Detects trojan executables posing as the EICAR test file"
        author = "Kybero Labs"

    strings:
        $s1 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
        $s2 = "This program cannot be run in DOS mode"

    condition:
        uint16(0) == 0x5a4d and all of them
}

rule Trojan_Generic_B {
    meta:
        author = "Elastic Security"
        id = "a681f24a-7054-4525-bcf8-3ee64a1d8413"
        fingerprint = "6323ed5b60e728297de19c878cd96b429bfd6d82157b4cf3475f3a3123921ae0"
        creation_date = "2021-06-10"
        last_modified = "2021-08-23"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a796f316b1ed7fa809d9ad5e9b25bd780db76001345ea83f5035a33618f927fa"
        severity = 25
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "_kasssperskdy" wide fullword
        $b = "[Time:]%d-%d-%d %d:%d:%d" wide fullword
        $c = "{SDTB8HQ9-96HV-S78H-Z3GI-J7UCTY784HHC}" wide fullword
    condition:
        2 of them
}

rule Trojan_Generic_C {
    meta:
        author = "Elastic Security"
        id = "ae824b13-eaae-49e6-a965-ff10379f3c41"
        fingerprint = "8658996385aac060ebe9eab45bbea8b05b9008926bb3085e5589784473bc3086"
        creation_date = "2022-02-03"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 31 31 34 2E 31 31 34 2E 31 31 34 2E 31 31 34 }
        $a2 = { 69 6E 66 6F 40 63 69 61 2E 6F 72 67 30 }
        $a3 = { 55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 33 3B 20 57 4F 57 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 35 30 2E 30 2E 32 36 36 31 2E 39 34 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 }
        $a4 = { 75 73 65 72 25 33 64 61 64 6D 69 6E 25 32 36 70 61 73 73 77 6F 72 64 25 33 64 64 65 66 61 75 6C 74 25 34 30 72 6F 6F 74 }
    condition:
        3 of them
}

rule Trojan_Generic_D {
    meta:
        author = "Elastic Security"
        id = "eb47e754-9b4d-45e7-b76c-027d03326c6c"
        fingerprint = "b71d13a34e5f791612ed414b8b0e993b1f476a8398a1b0be39046914ac5ac21d"
        creation_date = "2022-02-03"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 41 20 61 74 20 4C 20 25 64 }
        $a2 = { 74 63 70 69 70 5F 74 68 72 65 61 64 }
        $a3 = { 32 30 38 2E 36 37 2E 32 32 32 2E 32 32 32 }
        $a4 = { 55 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 33 3B 20 57 4F 57 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 35 37 2E 30 2E 32 39 38 37 2E 31 33 33 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 }
    condition:
        3 of them
}

rule Trojan_Generic_E {
    meta:
        author = "Elastic Security"
        id = "c7fd8d38-eaba-424d-b91a-098c439dab6b"
        fingerprint = "dc14cd519b3bbad7c2e655180a584db0a4e2ad4eea073a52c94b0a88152b37ba"
        creation_date = "2022-02-17"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a1702ec12c2bf4a52e11fbdab6156358084ad2c662c8b3691918ef7eabacde96"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "PCREDENTIAL" ascii fullword
        $a2 = "gHotkey" ascii fullword
        $a3 = "EFORMATEX" ascii fullword
        $a4 = "ZLibEx" ascii fullword
        $a5 = "9Root!" ascii fullword
    condition:
        all of them
}

rule Trojan_Generic_F {
    meta:
        author = "Elastic Security"
        id = "bbe6c282-e92d-4021-bdaf-189337e4abf0"
        fingerprint = "e004d77440a86c23f23086e1ada6d1453178b9c2292782c1c88a7b14151c10fe"
        creation_date = "2022-03-02"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a44c46d4b9cf1254aaabd1e689f84c4d2c3dd213597f827acabface03a1ae6d1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 00 D1 1C A5 03 08 08 00 8A 5C 01 08 08 00 8A 58 01 2E 54 FF }
    condition:
        all of them
}

rule Trojan_Generic_G {
    meta:
        author = "Elastic Security"
        id = "889b1248-a694-4c9b-8792-c04e582e814c"
        fingerprint = "a5e0c2bbd6a297c01f31eccabcbe356730f50f074587f679da6caeca99e54bc1"
        creation_date = "2022-03-11"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a48d57a139c7e3efa0c47f8699e2cf6159dc8cdd823b16ce36257eb8c9d14d53"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "BELARUS-VIRUS-MAKER" ascii fullword
        $a2 = "C:\\windows\\temp\\" ascii fullword
        $a3 = "~c~a~n~n~a~b~i~s~~i~s~~n~o~t~~a~~d~r~u~g~" ascii fullword
        $a4 = "untInfector" ascii fullword
    condition:
        all of them
}

rule Trojan_Generic_H {
    meta:
        author = "Elastic Security"
        id = "02a87a20-a5b4-44c6-addc-c70b327d7b2c"
        fingerprint = "fb25a522888efa729ee6d43a3eec7ade3d08dba394f3592d1c3382a5f7a813c8"
        creation_date = "2022-03-04"
        last_modified = "2022-04-12"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "13037b749aa4b1eda538fda26d6ac41c8f7b1d02d83f47b0d187dd645154e033"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 24 3C 8B C2 2B C1 83 F8 01 72 3A 8D 41 01 83 FA 08 89 44 24 38 8D 44 }
    condition:
        all of them
}

rule Trojan_Generic_I {
    meta:
        author = "Elastic Security"
        id = "4fbff084-5280-4ff8-9c21-c437207231a5"
        fingerprint = "728d7877e7a16fbb756b1c3b6c90ff3b718f0f750803b6a1549cb32c69be0dfc"
        creation_date = "2023-02-28"
        last_modified = "2023-04-23"
        description = "Shellcode found in REF2924, belonging to for now unknown trojan"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "7010a69ba77e65e70f4f3f4a10af804e6932c2218ff4abd5f81240026822b401"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $string_decryption = { 8A 44 30 ?? 8A CD 88 45 ?? 32 C5 C0 C1 ?? 88 04 3E 0F B6 C5 0F B6 D9 0F AF D8 0F B6 C1 0F B6 D1 88 6D ?? 0F AF D0 0F B6 C5 0F B6 CD 0F AF C8 8A 6D ?? 8A 45 ?? C0 CB ?? 02 D1 32 DA 02 EB 88 6D ?? 38 45 ?? 74 ?? 8B 45 ?? 46 81 FE ?? ?? ?? ?? 7C ?? }
        $thread_start = { E8 ?? ?? ?? ?? 6A ?? 8D 44 24 ?? BB ?? ?? ?? ?? 50 6A ?? 5A 8B CF 89 5C 24 ?? E8 ?? ?? ?? ?? 6A ?? 8D 44 24 ?? 89 5C 24 ?? 50 6A ?? 5A 8B CF E8 ?? ?? ?? ?? 6A ?? 8D 44 24 ?? 89 5C 24 ?? 50 6A ?? 5A 8B CF E8 ?? ?? ?? ?? 6A ?? 8D 44 24 ?? 89 5C 24 ?? 50 6A ?? 5A 8B CF E8 ?? ?? ?? ?? }
        $resolve = { 8B 7A ?? 8D 5D ?? 85 FF 74 ?? 0F B7 0F 8D 7F ?? 8D 41 ?? 83 F8 ?? 77 ?? 83 C1 ?? 0F B7 33 83 C3 ?? 8D 46 ?? 83 F8 ?? 77 ?? 83 C6 ?? 85 C9 }
    condition:
        2 of them
}

rule Trojan_Generic_J {
    meta:
        author = "Elastic Security"
        id = "73ed7375-c8ab-4d95-ae66-62b1b02a3d1e"
        fingerprint = "a026cc2db3bfebca4b4ea6e9dc41c2b18d0db730754ef3131d812d7ef9cd17d6"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "2b17328a3ef0e389419c9c86f81db4118cf79640799e5c6fdc97de0fc65ad556"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 48 8B 03 48 8B CE 49 8D 54 04 02 41 FF D6 48 89 03 48 83 C3 08 48 }
        $a2 = { 41 3C 42 8B BC 08 88 00 00 00 46 8B 54 0F 20 42 8B 5C 0F 24 4D }
    condition:
        all of them
}

rule Trojan_Generic_K {
    meta:
        author = "Elastic Security"
        id = "96cdf3c4-6f40-4eb3-8bfd-b3c41422388a"
        fingerprint = "1037576e2c819031d5dc8067650c6b869e4d352ab7553fb5676a358059b37943"
        creation_date = "2023-05-09"
        last_modified = "2023-06-13"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "9a4d68de36f1706a3083de7eb41f839d8c7a4b8b585cc767353df12866a48c81"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 74 24 28 48 8B 46 10 48 8B 4E 18 E8 9A CA F8 FF 84 C0 74 27 48 8B 54 }
        $a2 = { F2 74 28 48 89 54 24 18 48 89 D9 48 89 D3 E8 55 40 FF FF 84 C0 }
    condition:
        all of them
}

rule Trojan_Generic_L {
    meta:
        author = "Elastic Security"
        id = "f0c79978-2df9-4ae2-bc5d-b5366acff41b"
        fingerprint = "94b2a5784ae843b831f9ce34e986b2687ded5c754edf44ff20490b851e0261fc"
        creation_date = "2023-07-27"
        last_modified = "2023-09-20"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "8f800b35bfbc8474f64b76199b846fe56b24a3ffd8c7529b92ff98a450d3bd38"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "\\IronPython."
        $a2 = "\\helpers\\execassembly_x64"
    condition:
        all of them
}

rule Trojan_Generic_M {
    meta:
        author = "Elastic Security"
        id = "40899c85-bb49-412c-8081-3a1359957c52"
        fingerprint = "d02a17a3b9efc2fd991320a5db7ab2384f573002157cddcd12becf137e893bd8"
        creation_date = "2023-12-15"
        last_modified = "2024-01-12"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "88eb4f2e7085947bfbd03c69573fdca0de4a74bab844f09ecfcf88e358af20cc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "_sqlDataTypeSize"
        $a2 = "ChromeGetName"
        $a3 = "get_os_crypt"
    condition:
        all of them
}

rule Trojan_Generic_N {
    meta:
        author = "Elastic Security"
        id = "9997489c-4e22-4df1-90cb-dd098ca26505"
        fingerprint = "4c872be4e5eaf46c92e6f7d62ed0801992c36fee04ada1a1a3039890e2893d8c"
        creation_date = "2024-01-31"
        last_modified = "2024-02-08"
        threat_name = "Windows.Trojan.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $ldrload_dll = { 43 6A 45 9E }
        $loadlibraryw = { F1 2F 07 B7 }
        $ntallocatevirtualmemory = { EC B8 83 F7 }
        $ntcreatethreadex = { B0 CF 18 AF }
        $ntqueryinformationprocess = { C2 5D DC 8C }
        $ntprotectvirtualmemory = { 88 28 E9 50 }
        $ntreadvirtualmemory = { 03 81 28 A3 }
        $ntwritevirtualmemory = { 92 01 17 C3 }
        $rtladdvectoredexceptionhandler = { 89 6C F0 2D }
        $rtlallocateheap = { 5A 4C E9 3B }
        $rtlqueueworkitem = { 8E 02 92 AE }
        $virtualprotect = { 0D 50 57 E8 }
    condition:
        4 of them
}

rule Trojan_Generic_O {
    meta:
        author = "Elastic Security"
        id = "2993e5a5-26b2-4cfd-8130-4779abcfecb2"
        fingerprint = "709015984e3c9abaf141b76bf574921466493475182ca30a56dbc3671030b632"
        creation_date = "2024-03-18"
        last_modified = "2024-03-18"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "9f9b926cef69e879462d9fa914dda8c60a01f3d409b55afb68c3fb94bf1a339b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 0C 8B 45 F0 89 45 C8 8B 45 C8 8B 40 3C 8B 4D F0 8D 44 01 04 89 }
    condition:
        1 of them
}

rule Trojan_Generic_P {
    meta:
        author = "Elastic Security"
        id = "0e135d58-efd9-4d5e-95d8-ddd597f8e6a8"
        fingerprint = "e1a9e0c4e5531ae4dd2962285789c3bb8bb2621aa20437384fc3abcc349718c6"
        creation_date = "2024-03-19"
        last_modified = "2024-03-19"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "a91c1d3965f11509d1c1125210166b824a79650f29ea203983fffb5f8900858c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 55 8B EC 8B 45 14 56 57 8B 7D 08 33 F6 89 47 0C 39 75 10 76 15 8B }
    condition:
        1 of them
}

rule Trojan_Generic_Q {
   meta:
      threat_name = "Trojan/Generic.Q"
      description = "Detects an XORed URL in an executable"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/stvemillertime/status/1237035794973560834"
      date = "2020-03-09"
      modified = "2022-09-16"
      score = 50
      id = "f83991c8-f2d9-5583-845a-d105034783ab"
   strings:
      $s1 = "http://" xor
      $s2 = "https://" xor
      $f1 = "http://" ascii
      $f2 = "https://" ascii

      $fp01 = "3Com Corporation" ascii  /* old driver */
      $fp02 = "bootloader.jar" ascii  /* DeepGit */
      $fp03 = "AVAST Software" ascii wide
      $fp04 = "smartsvn" wide ascii fullword
      $fp05 = "Avira Operations GmbH" wide fullword
      $fp06 = "Perl Dev Kit" wide fullword
      $fp07 = "Digiread" wide fullword
      $fp08 = "Avid Editor" wide fullword
      $fp09 = "Digisign" wide fullword
      $fp10 = "Microsoft Corporation" wide fullword
      $fp11 = "Microsoft Code Signing" ascii wide
      $fp12 = "XtraProxy" wide fullword
      $fp13 = "A Sophos Company" wide
      $fp14 = "http://crl3.digicert.com/" ascii
      $fp15 = "http://crl.sectigo.com/SectigoRSACodeSigningCA.crl" ascii
      $fp16 = "HitmanPro.Alert" wide fullword
   condition:
      uint16(0) == 0x5a4d and
      filesize < 2000KB and (
         ( $s1 and #s1 > #f1 ) or
         ( $s2 and #s2 > #f2 )
      )
      and not 1 of ($fp*)
      and not pe.number_of_signatures > 0
}

rule Trojan_Generic_R {
    meta:
        threat_name = "Trojan/Generic.R"
        description = "Detects malware by known bad imphash or rich_pe_header_hash"
        reference = "https://yaraify.abuse.ch/statistics/"
        license = "Detection Rule License 1.1 https://github.com/SigmaHQ/Detection-Rule-License"
        author = "Arnim Rupp"
        date = "2023-03-20"
        modified = "2023-03-22"
        score = 75
        hash = "167dde6bd578cbfcc587d5853e7fc2904cda10e737ca74b31df52ba24db6e7bc"
        hash = "0a25a78c6b9df52e55455f5d52bcb3816460001cae3307b05e76ac70193b0636"
        hash = "d87a35decd0b81382e0c98f83c7f4bf25a2b25baac90c9dcff5b5a147e33bcc8"
        hash = "5783bf969c36f13f4365f4cae3ec4ee5d95694ff181aba74a33f4959f1f19e8b"
        hash = "4ca925b0feec851d787e7ee42d263f4c08b0f73f496049bdb5d967728ff91073"
        hash = "9c2d2fa9c32fdff1828854e8cc39160dae73a4f90fb89b82ef6d853b63035663"
        hash = "2c53d58f30b2ee1a2a7746e20f136c34d25d0214261783fc67e119329d457c2a"
        hash = "5e83747015b0589b4f04b0db981794adf53274076c1b4acf717e3ff45eca0249"
        hash = "ceaa0af90222ff3a899b9a360f6328cbda9ec0f5fbd18eb44bdc440470bb0247"
        hash = "82fb1ba998dfee806a513f125bb64c316989c36c805575914186a6b45da3b132"
        hash = "cb41d2520995abd9ba8ccd42e53d496a66da392007ea6aebd4cbc43f71ad461a"
        hash = "c7bd758506b72ee6db1cc2557baf745bf9e402127d8e49266cc91c90f3cf3ed5"
        hash = "e6e0d60f65a4ea6895ff97df340f6d90942bbfa402c01bf443ff5b4641ff849f"
        hash = "e8ddef9fa689e98ba2d48260aea3eb8fa41922ed718b7b9135df6426b3ddf126"
        hash = "ad57d77aba6f1bf82e0affe4c0ae95964be45fb3b7c2d6a0e08728e425ecd301"
        hash = "483df98eb489899bc89c6a0662ca8166c9b77af2f6bedebd17e61a69211843d9"
        hash = "a65ed85851d8751e6fe6a27ece7b3879b90866a10f272d8af46fb394b46b90a9"
        hash = "09081e04f3228d6ef2efc1108850958ed86026e4dfda199852046481f4711565"
        hash = "1b2c9054f44f7d08cffe7e2d9127dbd96206ab2c15b63ebf6120184950336ae1"
        hash = "257887d1c84eb15abb2c3c0d7eb9b753ca961d905f4979a10a094d0737d97138"
        hash = "1cbad8b58dbd1176e492e11f16954c3c254b5169dde52b5ad6d0d3c51930abf8"
        hash = "a9897fd2d5401071a8219b05a3e9b74b64ad67ab75044b3e41818e6305a8d7b9"
        hash = "aeac45fbc5d2a59c9669b9664400aeaf6699d76a57126d2f437833a3437a693e"
        hash = "7b4c4d4676fab6c009a40d370e6cb53ea4fd73b09c23426fbaccc66d652f2a00"
        hash = "b07f6873726276842686a6a6845b361068c3f5ce086811db05c1dc2250009cd0"
        hash = "d1b3afebcacf9dd87034f83d209b42b0d79e66e08c0a897942fbe5fbd6704a0e"
        hash = "074d52be060751cf213f6d0ead8e9ab1e63f055ae79b5fcbe4dd18469deea12b"
        hash = "84d1fdef484fa9f637ae3d6820c996f6c5cf455470e8717ad348a3d80d2fb8e0"
        hash = "437da123e80cfd10be5f08123cd63cfc0dc561e17b0bef861634d60c8a134eda"
        hash = "f76c36eb22777473b88c6a5fc150fd9d6b5fac5b2db093f0ccd101614c46c7e7"
        hash = "5498b7995669877a410e1c2b68575ca94e79014075ef5f89f0f1840c70ebf942"
        hash = "af4e633acfba903e7c92342b114c4af4e694c5cfaea3d9ea468a4d322b60aa85"
        hash = "d7d870f5afab8d4afa083ea7d7ce6407f88b0f08ca166df1a1d9bdc1a46a41b3"
        hash = "974209d88747fbba77069bb9afa9e8c09ee37ae233d94c82999d88dfcd297117"
        hash = "f2d99e7d3c59adf52afe0302b298c7d8ea023e9338c2870f74f11eaa0a332fc4"
        hash = "b32c93be9320146fc614fafd5e6f1bb8468be83628118a67eb01c878f941ee5d"
        hash = "bbd99acc750e6457e89acbc5da8b2a63b4ef01d4597d160e9cde5dc8bd04cf74"
        hash = "dbff5ca3d1e18902317ab9c50be4e172640a8141e09ec13dcca986f2ec1dc395"
        hash = "3ee1741a649f0b97bbeb05b6f9df97afda22c82e1e870177d8bdd34141ef163c"
        hash = "222096fc800c8ea2b0e530302306898b691858324dbe5b8357f90407e9665b85"
        hash = "b9995d1987c4e8b6fb30d255948322cfad9cc212c7f8f4c5db3ac80e23071533"
        hash = "a6a92ea0f27da1e678c15beb263647de43f68608afe82d6847450f16a11fe6c0"
        hash = "866e3ea86671a62b677214f07890ddf7e8153bec56455ad083c800e6ab51be37"
        id = "fb398c26-e9ac-55f9-b605-6b763021e96a"
    strings:
        $fp1 = "Win32 Cabinet Self-Extractor" wide
        $fp2 = "EXTRACTOPT" ascii fullword
    condition:
        uint16(0) == 0x5A4D and (
            // no size limit as some samples are 20MB+ (ceaa0af90222ff3a899b9a360f6328cbda9ec0f5fbd18eb44bdc440470bb0247) and the hash is calculated only on the header
            pe.imphash() == "9ee34731129f4801db97fd66adbfeaa0" or
            pe.imphash() == "f9e8597c55008e10a8cdc8a0764d5341" or
            pe.imphash() == "0a76016a514d8ed3124268734a31e2d2" or
            pe.imphash() == "d3cbd6e8f81da85f6bf0529e69de9251" or
            pe.imphash() == "d8b32e731e5438c6329455786e51ab4b" or
            pe.imphash() == "cdf5bbb8693f29ef22aef04d2a161dd7" or
            pe.imphash() == "890e522b31701e079a367b89393329e6" or
            pe.imphash() == "bf5a4aa99e5b160f8521cadd6bfe73b8" or
            pe.imphash() == "646167cce332c1c252cdcb1839e0cf48" or
            pe.imphash() == "9f4693fc0c511135129493f2161d1e86" or
            pe.imphash() == "b4c6fff030479aa3b12625be67bf4914" // or

            // these have lots of hits on abuse.ch but none on VT? (except for my one test upload) honeypot collected samples?
            //pe.imphash() == "2c2ad1dd2c57d1bd5795167a7236b045" or
            //pe.imphash() == "46f03ef2495b21d7ad3e8d36dc03315d" or
            //pe.imphash() == "6db997463de98ce64bf5b6b8b0f77a45" or
            //pe.imphash() == "c9246f292a6fdc22d70e6e581898a026" or
            //pe.imphash() == "c024c5b95884d2fe702af4f8984b369e" or
            //pe.imphash() == "4dcbc0931c6f88874a69f966c86889d9" or
            //pe.imphash() == "48521d8a9924bcb13fd7132e057b48e1" or

            // rich_pe_header_hash:b6321cd8142ea3954c1a27b162787f7d p:2+ has 238k hits on VT including many files without imphash (e.g. e193dadf0405a826b3455185bdd9293657f910e5976c59e960a0809b589ff9dc) due to being corrupted?
            // zero hits with p:0
            // disable bc it's killing performance
            //hash.md5(pe.rich_signature.clear_data) == "b6321cd8142ea3954c1a27b162787f7d"
        )
        and not 1 of ($fp*)
}

rule Trojan_Generic_S {
    meta:
        threat_name = "Trojan/Generic.S"
        author = "ditekSHen"
        description = "Detects executables referencing many IR and analysis tools"
    strings:
        $s1 = "procexp.exe" nocase ascii wide
        $s2 = "perfmon.exe" nocase ascii wide
        $s3 = "autoruns.exe" nocase ascii wide
        $s4 = "autorunsc.exe" nocase ascii wide
        $s5 = "ProcessHacker.exe" nocase ascii wide
        $s6 = "procmon.exe" nocase ascii wide
        $s7 = "sysmon.exe" nocase ascii wide
        $s8 = "procdump.exe" nocase ascii wide
        $s9 = "apispy.exe" nocase ascii wide
        $s10 = "dumpcap.exe" nocase ascii wide
        $s11 = "emul.exe" nocase ascii wide
        $s12 = "fortitracer.exe" nocase ascii wide
        $s13 = "hookanaapp.exe" nocase ascii wide
        $s14 = "hookexplorer.exe" nocase ascii wide
        $s15 = "idag.exe" nocase ascii wide
        $s16 = "idaq.exe" nocase ascii wide
        $s17 = "importrec.exe" nocase ascii wide
        $s18 = "imul.exe" nocase ascii wide
        $s19 = "joeboxcontrol.exe" nocase ascii wide
        $s20 = "joeboxserver.exe" nocase ascii wide
        $s21 = "multi_pot.exe" nocase ascii wide
        $s22 = "ollydbg.exe" nocase ascii wide
        $s23 = "peid.exe" nocase ascii wide
        $s24 = "petools.exe" nocase ascii wide
        $s25 = "proc_analyzer.exe" nocase ascii wide
        $s26 = "regmon.exe" nocase ascii wide
        $s27 = "scktool.exe" nocase ascii wide
        $s28 = "sniff_hit.exe" nocase ascii wide
        $s29 = "sysanalyzer.exe" nocase ascii wide
        $s30 = "CaptureProcessMonitor.sys" nocase ascii wide
        $s31 = "CaptureRegistryMonitor.sys" nocase ascii wide
        $s32 = "CaptureFileMonitor.sys" nocase ascii wide
        $s33 = "Control.exe" nocase ascii wide
        $s34 = "rshell.exe" nocase ascii wide
        $s35 = "smc.exe" nocase ascii wide
    condition:
         uint16(0) == 0x5a4d and 4 of them
}

rule Trojan_Generic_T {
    meta:
        threat_name = "Trojan/Generic.T"
        author = "ditekSHen"
        description = "Detects executables packed with VMProtect."
        snort2_sid = "930049-930051"
        snort3_sid = "930017"
    strings:
        $s1 = ".vmp0" fullword ascii
        $s2 = ".vmp1" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".vmp0" or
                pe.sections[i].name == ".vmp1"
            )
        )
}
