rule Trojan_Zika_A_con {
    meta:
        description = "Detects Zika"
        author = "Kybero Labs"

    strings:
        $s1 = "doPayload"
        $s2 = "get_NavaShield_Laugh"
        $s3 = "get_NavaShield_Delete_C"
        $s4 = "http://rpi.net.au/~ajohnson/resourcehacker"

    condition:
        uint16(0) == 0x4d5a and all of them
}