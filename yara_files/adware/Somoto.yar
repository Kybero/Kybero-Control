rule Adware_Somoto_A_con {
    meta:
        threat_name = "Adware/Somoto.A!con"
        description = "Detects Somoto"
        author = "Kybero Labs"

    strings:
        $s1 = "VCBetterInstallerModule"
        $s2 = "Somoto Ltd.0"

    condition:
        uint16(0) == 0x5a4d and all of them
}
