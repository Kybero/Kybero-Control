rule Adware_1ClickDownload_A_con {
    meta:
        threat_name = "Adware/1ClickDownload.A!con"
        description = "Detects 1ClickDownload certificate"
        author = "Kybero Labs"

    strings:
        $s1 = "Terra Firma Internet Consulting LTD0"
        $s2 = "note=1clickdownloader_is_NOT_downloading_any_file_directly"

    condition:
        uint16(0) == 0x5a4d and 1 of them
}
