rule Worm_Nimda_A_con {
    meta:
        threat_name = "Worm/Nimda.A!con"
        description = "Detects Nimda"
        author = "Kybero Labs"

    strings:
        $s1 = "Concept Virus(CV) "
        $s2 = "Copyright(C)2001  R.P.China"

    condition:
        uint16(0) == 0x5a4d and all of them
}
