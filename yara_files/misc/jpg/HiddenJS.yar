rule JPG_HiddenJS_A_con {
    meta:
        description = "Detects JavaScript code hidden within JPG format images"
        author = "Kybero Labs"

    strings:
        $s = "<script src="

    condition:
        uint16(0) == 0xffd8 and $s
}
