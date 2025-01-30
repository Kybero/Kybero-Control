rule PDFPhishing_Generic_A {
    meta:
        threat_name = "PDFPhishing/Generic.A"
        description = "Detects PDF phishing based on suspicious domain structure"
        author = "Kybero Labs"

    strings:
        $p = "PDF-1"

        $s1 = "/wp-content/plugins/super-forms/uploads/php/files/"
        $s2 = "/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s3 = "/ckfinder/userfiles/files/"

    condition:
        $p and 1 of ($s*)
}

rule PDFPhishing_Generic_B {
    meta:
        threat_name = "PDFPhishing/Generic.B"
        description = "Detects PDF phishing based on authors"
        author = "Kybero Labs"

    strings:
        $p = "PDF-1"

        $s1 = "/Author (Franklin Daw)"
        $s2 = "/Creator (Softplicity)"
        $s3 = "/Author (Kixafoji Yeyevifera)"
        $s4 = "/Subject (Mukkala mukabula tamil song mp3 free download.       By Laila Alvarez            i Sean Gallup/Getty Images News/Getty Images    Sharing music you')" 
        $s5 = "/Author (Tuvude Fukojuru)" 
        $s6 = "/Subject (South point movies. Movies Theaters United States Nevada Las Vegas Century South Point 16 2 people preferred this theate)" 
        $s7 = "/Title (Soft aesthetic bio template)" 
        $s8 = "/Author (Yorepufi Tutoyale)" 
        $s9 = "/Title (Play word whomp unblocked)" 
        $s10 = "/Author (Nevoketejo Hovajihe)" 
        $s11 = "/Title (Warframe how to get archwing)" 
        $s12 = "/Author (Rotigiri Ruveyake)" 

    condition:
        $p and 2 of ($s*)
}
