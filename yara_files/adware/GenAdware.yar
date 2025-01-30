rule Adware_Generic_A {
    meta:
        threat_name = "Adware/Generic.A"
        description = "Detects files attempting to change browser homepages"
        author = "Kybero Labs"

    strings:
        $s1 = {43 68 61 6e 67 65 53 74 61 72 74 50 61 67 65 49 45 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 53 74 61 72 74 20 50 61 67 65}
        $s2 = {43 68 61 6e 67 65 53 74 61 72 74 50 61 67 65 46 69 72 65 66 6f 78 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 66 69 72 65 66 6f 78 2e 65 78 65 00 62 72 6f 77 73 65 72 2e 73 74 61 72 74 75 70 2e 68 6f 6d 65 70 61 67 65}
        $s3 = {43 68 61 6e 67 65 53 74 61 72 74 50 61 67 65 43 68 72 6f 6d 65 00 fe 1c 1c 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 41 70 70 6c 69 63 61 74 69 6f 6e 5c 63 68 72 6f 6d 65 2e 65 78 65 00 20 73 74 61 72 74}

    condition:
        uint16(0) == 0x5a4d and 1 of ($s*)
}

rule Adware_Generic_B {
    meta:
        threat_name = "Adware/Generic.B"
        description = "Detects files attempting to change default browser search providers"
        author = "Kybero Labs"

    strings:
        $s1 = {43 68 61 6e 67 65 44 65 66 61 75 6c 74 53 65 61 72 63 68 49 45 20 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 53 65 61 72 63 68 53 63 6f 70 65 73 00 44 65 66 61 75 6c 74 53 63 6f 70 65 00 53 65 61 72 63 68 20 50 61 67 65}
        $s2 = {43 68 61 6e 67 65 44 65 66 61 75 6c 74 53 65 61 72 63 68 43 68 72 6f 6d 65 20 00 fe 1c 1c 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 57 65 62 20 44 61 74 61}

    condition:
        uint16(0) == 0x5a4d and 1 of ($s*)
}
