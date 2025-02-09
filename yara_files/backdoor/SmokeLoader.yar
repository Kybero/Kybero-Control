rule Backdoor_SmokeLoader_A_con {
    meta:
        threat_name = "Backdoor/SmokeLoader.A!con"
        description = "Detects SmokeLoader certificate"
        author = "Kybero Labs"

    strings:
        $s1 = {49 00 6e 00 73 00 70 00 65 00 63 00 74 00 6f 00 72 00 4f 00 66 00 66 00 69 00 63 00 65 00 47 00 61 00 64 00 67 00 65 00 74}

    condition:
        uint16(0) == 0x5a4d and all of them
}
