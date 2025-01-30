rule Adware_Trymedia_A_con {
    meta:
        threat_name = "Adware/Trymedia.A!con"
        description = "Detects Trymedia"
        author = "Kybero Labs"

    strings:
        $s1 = "http://fe.trymedia.com/"
        $s2 = {54 00 72 00 79 00 6d 00 65 00 64 00 69 00 61}
        $s3 = "Trymedia"

    condition:
        uint16(0) == 0x5a4d and 2 of them
}
