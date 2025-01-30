rule Adware_Hotbar_A_con {
    meta:
        threat_name = "Adware/Hotbar.A!con"
        description = "Detects Hotbar certificate"
        author = "Kybero Labs"

    strings:
        $s = {50 00 69 00 6e 00 62 00 61 00 6c 00 6c 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e}

    condition:
        uint16(0) == 0x5a4d and $s
}
