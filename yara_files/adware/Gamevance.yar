rule Adware_Gamevance_A_con {
    meta:
        description = "Detects Gamevance based on known EpicPlay domain"
        author = "Kybero Labs"

    strings:
        $s1 = "EpicPlayTPDClass"
        $s2 = "http://pages.epicplay.com/"
        $s3 = "EpicPlay Games Extension"

    condition:
        all of them
}
