rule Adware_Linkury_A_con {
    meta:
        threat_name = "Adware/Linkury.A!con"
        description = "Detects Linkury"
        author = "Kybero Labs"

    strings:
        $s1 = {5c 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 00}
        $s2 = "Copyright (c) 1992-2004 by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED."

    condition:
        uint16(0) == 0x5a4d and all of them
}
