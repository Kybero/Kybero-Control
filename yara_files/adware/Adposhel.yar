rule Adware_Adposhel_A_con {
    meta:
        threat_name = "Adware/Adposhel.A!con"
        description = "Detects Adposhel certificate"
        author = "Kybero Labs"

    strings:
        $s1 = "PRIVATELY OWNED ENTERPRISE "SINETEKO"1"

    condition:
        uint16(0) == 0x5a4d and all of them
}
