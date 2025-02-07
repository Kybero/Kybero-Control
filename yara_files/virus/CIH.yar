rule Virus_CIH_A_con {
    meta:
        threat_name = "Virus/CIH.A!con"
        description = "Detects CIH"
        author = "Kybero Labs"

    strings:
        $s1 = "CIH v1."

    condition:
        uint16(0) == 0x5a4d and all of them
}
