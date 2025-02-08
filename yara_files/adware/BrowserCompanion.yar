rule Adware_BrowserCompanion_A_con {
    meta:
        threat_name = "Adware/BrowserCompanion.A!con"
        description = "Detects BrowserCompanion certificate"
        author = "Kybero Labs"

    strings:
        $s1 = "Blabbers Communications Ltd1"

    condition:
        uint16(0) == 0x5a4d and all of them
}
