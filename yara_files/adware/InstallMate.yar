rule Adware_InstallMate_A_con {
    meta:
        threat_name = "Adware/InstallMate.A!con"
        description = "Detects InstallMate"
        author = "Kybero Labs"

    strings:
        $s1 = "ServerUrl=http://www.nlstorage.info"

    condition:
        uint16(0) == 0x5a4d and all of them
}
