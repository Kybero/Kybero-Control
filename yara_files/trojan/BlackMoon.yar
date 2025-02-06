rule Trojan_BlackMoon_A_con {
    meta:
        threat_name = "Trojan/BlackMoon.A!con"
        author = "ditekSHen"
        description = "Detects executables using BlackMoon RunTime"
    strings:
        $s1 = "blackmoon" fullword ascii
        $s2 = "BlackMoon RunTime Error:" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}
