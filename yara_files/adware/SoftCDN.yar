rule Adware_SoftCDN_A_con {
    meta:
        threat_name = "Adware/SoftCDN.A!con"
        description = "Detects SoftCDN"
        author = "Kybero Labs"

    strings:
        $s1 = "softcdn"
        $s2 = "Vitzo LLC0"

    condition:
        uint16(0) == 0x5a4d and all of them
}
