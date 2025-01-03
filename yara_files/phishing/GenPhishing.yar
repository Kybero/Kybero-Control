rule Phishing_Generic_A {
    meta:
        description = "Detects PDF phishing"
        author = "Kybero Labs"

    strings:
        $s1 = "PDF-1"
        $s2 = "/Author (Franklin Daw)"
        $s3 = "/Creator (Softplicity)"

    condition:
        all of them
}

rule Phishing_Generic_B {
    meta:
        description = "Detects PDF phishing based on risky domain connection"
        author = "Kybero Labs"

    strings:
        $s1 = "PDF-1"
        $s2 = "https://cdn-cms.f-static.net"

    condition:
        all of them
}
