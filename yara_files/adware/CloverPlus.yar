rule Adware_CloverPlus_A_con {
    meta:
        threat_name = "Adware/CloverPlus.A!con"
        description = "Detects CloverPlus"
        author = "Kybero Labs"

    strings:
        $s1 = "AdMatching.exe"
        $s2 = "PROGRAMFILES\\AdMatching"
        $s3 = "http://api.admatching.co.kr/"

    condition:
        uint16(0) == 0x5a4d and all of them
}

rule Adware_CloverPlus_B_con {
    meta:
        threat_name = "Adware/CloverPlus.B!con"
        description = "Detects CloverPlus certificate"
        author = "Kybero Labs"

    strings:
        $s1 = "Korea Contents Network0"

    condition:
        uint16(0) == 0x5a4d and all of them
}
