rule Trojan_MEMZ_A_con {
    meta:
        description = "Detects MEMZ"
        author = "Kybero Labs"

    strings:
        $s1 = "Your computer has been trashed by the MEMZ trojan."
        $s2 = "Nyan Cat"

    condition:
        uint16(0) == 0x5a4d and all of them
}
