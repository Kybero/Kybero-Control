rule Adware_MultiPlug_A_con {
    meta:
        description = "Detects MultiPlug"
        author = "Kybero Labs"

    strings:
        $s1 = "!@Install@!UTF-8!
        $s2 = "Title=\"Download\""
        $s3 = "Progress=\"no\""
        $s4 = "RunProgram=\"51caf10e4098c.exe /s\""
        $s5 = "GUIMode=\"2\""
        $s6 = ";!@InstallEnd@!"

    condition:
        uint16(0) == 0x4d5a and all of them
}
