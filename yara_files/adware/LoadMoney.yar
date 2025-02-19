rule Adware_LoadMoney_A_con {
    meta:
        threat_name = "Adware/LoadMoney.A!con"
        description = "Detects LoadMoney certificate"
        author = "Kybero Labs"

    strings:
        $s1 = "LLC Mail.Ru1"

    condition:
        uint16(0) == 0x5a4d and all of them
}
