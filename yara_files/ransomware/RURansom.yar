rule Ransom_RURansom_A_con {
    meta:
        threat_name = "Ransom/RURansom.A!con"
        description = "Detects RURansom"
        author = "Kybero Labs"

    strings:
        $s1 = "\\RURansom\\RURansom\\obj\\Debug\\RURansom.pdb"

    condition:
        uint16(0) == 0x5a4d and all of them
}
