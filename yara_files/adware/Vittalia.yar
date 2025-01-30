rule Adware_Vittalia_A_con {
    meta:
        threat_name = "Adware/Vittalia.A!con"
        description = "Detects Vittalia certificate"
        author = "Kybero Labs"

    strings:
        $s = "Vittalia Internet S.L1"

    condition:
        uint16(0) == 0x5a4d and $s
}
