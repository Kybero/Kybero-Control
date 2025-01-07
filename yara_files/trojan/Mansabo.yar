rule Trojan_Mansabo_A_con {
    meta:
        description = "Detects Mansabo"
        author = "Kybero Labs"

    strings:
        $s1 = "CMDViewer"
        $s2 = "Bit Operations"
        $s3 = "\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB"

    condition:
        uint16(0) == 0x4d5a and all of them
}
