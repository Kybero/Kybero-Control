rule Worm_Lentin_A_con {
    meta:
        threat_name = "Worm/Lentin.A!con"
        description = "Detects Lentin/Yaha"
        author = "Kybero Labs"

    strings:
        $s1 = "worm@worm.com"
        $s2 = "\\wormID.dll"

    condition:
        uint16(0) == 0x5a4d and all of them
}

rule Worm_Lentin_B_con {
    meta:
        threat_name = "Worm/Lentin.B!con"
        description = "Detects the signed variant of Lentin/Yaha"
        author = "Kybero Labs"

    strings:
        $s = "Author : Hirosh"

    condition:
        uint16(0) == 0x5a4d and $s
}
