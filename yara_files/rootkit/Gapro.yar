rule Rootkit_Gapro_A_con {
    meta:
        threat_name = "Rootkit/Gapro.A!con"
        description = "Detects Gapro certificate"
        author = "Kybero Labs"

    strings:
        $s1 = "Xtreaming Technology Inc.0"

    condition:
        uint16(0) == 0x5a4d and all of them
}
