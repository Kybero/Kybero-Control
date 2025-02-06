rule Ransom_Donut_A_con {
    meta:
        threat_name = "Ransom/Donut.A!con"
        description = "Detects Donut"
        author = "Kybero Labs"

    strings:
        $s1 = "donut_id"
        $s2 = "donutRenameFile"
        $s3 = "donut.Properties"
        $s4 = "donut_key"

    condition:
        uint16(0) == 0x5a4d and all of them
}

rule Ransom_Donut_B_con {
    meta:
        threat_name = "Ransom/Donut.B!con"
        description = "Detects Donut ransom note dropper"
        author = "Kybero Labs"

    strings:
        $s1 = {00 6f 00 6e 00 75 00 74 00 2e 00 65 00 78 00 65 00 00 0d 2e 00 64 00 6f 00 6e 00 75 00 74 00 00 17 64 00 65 00 63 00 72 00 79 00 70 00 74 00 2e 00 74 00 78 00 74}

    condition:
        uint16(0) == 0x5a4d and all of them
}
