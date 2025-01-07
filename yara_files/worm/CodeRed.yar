rule Worm_CodeRed_A_con {
    meta:
        description = "Detects CodeRed"
        author = "Kybero Labs"

    strings:
        $s1 = "GET /default.ida"
        $s2 = "CodeRedII"
        $s3 = "d:\\inetpub\\scripts\\root.exe"
        $s4 = "d:\\progra~1\\common~1\\system\\MSADC\\root.exe"

    condition:
        all of them
}
