rule Backdoor_EagerBee_A_con {
    meta:
        threat_name = "Backdoor/EagerBee.A!con"
        author = "Elastic Security"
        creation_date = "2023-09-04"
        last_modified = "2023-09-20"
        reference_sample = "339e4fdbccb65b0b06a1421c719300a8da844789a2016d58e8ce4227cb5dc91b"
        license = "Elastic License v2"
        os = "windows"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.eagerbee"
        malpedia_rule_date = "20231009"
        malpedia_hash = ""
        malpedia_version = "20231009"
        malpedia_license = ""
        malpedia_sharing = "TLP:WHITE"

    strings:
        $dexor_config_file = { 48 FF C0 8D 51 FF 44 30 00 49 03 C4 49 2B D4 ?? ?? 48 8D 4F 01 48 }
        $parse_config = { 80 7C 14 20 3A ?? ?? ?? ?? ?? ?? 45 03 C4 49 03 D4 49 63 C0 48 3B C1 }
        $parse_proxy1 = { 44 88 7C 24 31 44 88 7C 24 32 48 F7 D1 C6 44 24 33 70 C6 44 24 34 3D 88 5C 24 35 48 83 F9 01 }
        $parse_proxy2 = { 33 C0 48 8D BC 24 F0 00 00 00 49 8B CE F2 AE 8B D3 48 F7 D1 48 83 E9 01 48 8B F9 }

    condition:
        2 of them
}
