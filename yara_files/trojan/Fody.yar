rule Trojan_Fody_A_con {
    meta:
        threat_name = "Trojan/Fody.A!con"
        author = "ditekSHen"
        description = "Detects executables manipulated with Fody"
    strings:
        $s1 = "ProcessedByFody" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and all of them
}
