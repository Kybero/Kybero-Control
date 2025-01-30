rule Adware_Toggle_A_con {
    meta:
        threat_name = "Adware/Toggle.A!con"
        description = "Detects Toggle"
        author = "Kybero Labs"

    strings:
        $s1 = "http://download.toggle.com/installers/"

    condition:
        uint16(0) == 0x5a4d and all of them
}
