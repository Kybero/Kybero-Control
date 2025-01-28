rule Adware_Generic_A {
    meta:
        description = "Detects files attempting to change browser homepages"
        author = "Kybero Labs"

    strings:
        $s1 = {43 68 61 6e 67 65 53 74 61 72 74 50 61 67 65 49 45 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 53 74 61 72 74 20 50 61 67 65}
        $s2 = {68 61 6e 67 65 53 74 61 72 74 50 61 67 65 46 69 72 65 66 6f 78 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 66 69 72 65 66 6f 78 2e 65 78 65 00 62 72 6f 77 73 65 72 2e 73 74 61 72 74 75 70 2e 68 6f 6d 65 70 61 67 65}

    condition:
        uint16(0) == 0x5a4d and 1 of ($s*)
}
