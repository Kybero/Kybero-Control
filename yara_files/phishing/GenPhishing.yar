rule PDFPhishing_Generic_A {
    meta:
        description = "Detects PDF phishing based on authors"
        author = "Kybero Labs"

    strings:
        $p = "PDF-1"

        $s1 = "/Author (Franklin Daw)"
        $s2 = "/Creator (Softplicity)"
        $s3 = "/Author (Kixafoji Yeyevifera)"
        $s4 = "/Subject (Mukkala mukabula tamil song mp3 free download.       By Laila Alvarez            i Sean Gallup/Getty Images News/Getty Images    Sharing music you')"

    condition:
        $p and 2 of ($s*)
}

rule PDFPhishing_Generic_B {
    meta:
        description = "Detects PDF phishing based on risky domain connections"
        author = "Kybero Labs"

    strings:
        $p = "PDF-1"

        $s1 = "https://cdn-cms.f-static.net"
        $s2 = "http://arohitourandtravels.com/userfiles/file/"
        $s3 = "https://autosaloncenter.com/uploads/file/"
        $s4 = "http://cnzhongkui.com/fckeditor/editor/filemanager/connectors/php/uploads/file/"
        $s5 = "http://www.hcibatiment.fr/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s6 = "https://sieompaysdebray.fr/lesiom/txt/imgadmin/file/"
        $s7 = "http://inewbus.com/wp-content/plugins/super-forms/uploads/php/files/"
        $s8 = "http://keralabiblesociety.com/fck_uploads/file/"
        $s9 = "http://eske.hu/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s10 = "http://sfera-vlad.ru/img/file/"
        $s11 = "https://riverasphotovideo.com/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s12 = "http://bixenony.com/userfiles/files/"
        $s13 = "https://comodee.com/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s14 = "http://www.leesii.com/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s15 = "http://birons.net/wp-content/plugins/super-forms/uploads/php/files/"
        $s16 = "http://selfmadefilms.nl/userfiles/files/"
        $s17 = "http://interwork.sk/userfiles/file/"
        $s18 = "http://mijneigenlift.nl/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s19 = "https://elpmarketing.ca/wp-content/plugins/super-forms/uploads/php/files/"
        $s20 = "http://indianmailbox.com/assets/images/userfiles/files/"
        $s21 = "https://101doctor.com/uploads/ckfiles/files/"
        $s22 = "http://boathousebrokerage.com/userfiles/file/"
        $s23 = "http://arlingtonhigh1961.com/clients/"

    condition:
        $p and 1 of ($s*)
}
