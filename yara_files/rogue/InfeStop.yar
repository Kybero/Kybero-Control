rule Rogue_InfeStop_A_con {
    meta:
        threat_name = "Rogue/InfeStop.A!con"
        description = "Detects InfeStop certificate"
        author = "Kybero Labs"

    strings:
        $s1 = "PANDORA SOFTWARE0"

    condition:
        uint16(0) == 0x5a4d and 1 of them
}
