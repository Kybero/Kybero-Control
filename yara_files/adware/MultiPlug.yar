rule Adware_MultiPlug_A_con {
    meta:
        description = "Detects MultiPlug"
        author = "Kybero Labs"

    strings:
        $s1 = "!@Install@!UTF-8!"
        $s2 = "Title=\"Download\""
        $s3 = "Progress=\"no\""
        $s4 = "GUIMode=\"2\""
        $s5 = ";!@InstallEnd@!"

    condition:
        uint16(0) == 0x4d5a and all of them
}

rule Adware_MultiPlug_B_con {
    meta:
        description = "Detects MultiPlug"
        author = "Kybero Labs"

    strings:
        $s1 = "!@Install@!UTF-8!"
        $s2 = "Title=\"Self Extract\""
        $s3 = "Progress=\"no\""
        $s4 = "GUIMode=\"2\""
        $s5 = ";!@InstallEnd@!"

    condition:
        uint16(0) == 0x4d5a and all of them
}
