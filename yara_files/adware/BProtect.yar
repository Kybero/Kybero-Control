rule Adware_BProtect_A_con {
    meta:
        threat_name = "Adware/BProtect.A!con"
        description = "Detects BProtect"
        author = "Kybero Labs"

    strings:
        $s1 = "BPROTECT_XML_NAME"
        $s2 = "bprotect.exe"

    condition:
        uint16(0) == 0x5a4d and all of them
}
