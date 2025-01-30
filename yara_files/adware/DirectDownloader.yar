rule Adware_DirectDownloader_A_con {
    meta:
        threat_name = "Adware/DirectDownloader.A!con"
        description = "Detects DirectDownloader"
        author = "Kybero Labs"

    strings:
        $s1 = "www.directdownloader.com"
        $s2 = "\\DirectDownloader\\directdownloader.exe"

    condition:
        uint16(0) == 0x5a4d and all of them
}
