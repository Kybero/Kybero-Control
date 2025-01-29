rule Adware_Gamevance_A_con {
    meta:
        description = "Detects Gamevance based on known EpicPlay domain"
        author = "Kybero Labs"

    strings:
        $s1 = "EpicPlayTPDClass"
        $s2 = "http://pages.epicplay.com/"
        $s3 = "EpicPlay Games Extension"

    condition:
        uint16(0) == 0x5a4d and all of them
}

rule Adware_Gamevance_B_con {
    meta:
        description = "Detects Gamevance based on known RivalGaming domain"
        author = "Kybero Labs"

    strings:
        $s1 = "http://pages.rivalgaming.com"
        $s2 = "RivalGaming"

    condition:
        uint16(0) == 0x5a4d and all of them
}
