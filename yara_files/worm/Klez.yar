rule Worm_Klez_A_con {
    meta:
        threat_name = "Worm/Klez.A!con"
        description = "Detects Klez dropped file"
        author = "Kybero Labs"

    strings:
        $s1 = "\krn132.exe"

    condition:
        uint16(0) == 0x5a4d and all of them
}
