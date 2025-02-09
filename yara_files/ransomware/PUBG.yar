rule Ransom_PUBG_A_con {
    meta:
        threat_name = "Ransom/PUBG.A!con"
        description = "Detects PUBG ransomware"
        author = "Kybero Labs"

    strings:
        $s1 = {59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 69 00 73 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 72 00 65 00 64 00 20 00 62 00 79 00 20 00 50 00 55 00 42 00 47 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 21}

    condition:
        uint16(0) == 0x5a4d and all of them
}
