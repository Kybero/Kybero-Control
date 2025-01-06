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
        $s5 = "/Author (Tuvude Fukojuru)"
        $s6 = "/Subject (South point movies. Movies Theaters United States Nevada Las Vegas Century South Point 16 2 people preferred this theate)"

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
        $s24 = "http://mattstergamer.com/wp-content/plugins/super-forms/uploads/php/files/"
        $s25 = "http://www.viksexteriors.com/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s26 = "https://lawrenceyezersky.com/userfiles/file/"
        $s27 = "http://dalhousieretreat.com/cote_dor_import/admin/ckfinder/userfiles/files/"
        $s28 = "https://www.mybizwebsites.com/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s29 = "https://realwebguys.com/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s30 = "https://yildizwebpaket.com/calisma2/files/uploads/"
        $s31 = "https://mavismanagement.com/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s32 = "http://asianmosaicnyc.com/userfiles/file/"
        $s33 = "https://takipcisec.com/calisma2/files/uploads/"
        $s34 = "http://www.sunarnuricomuisvealisverismerkezi.com/wp-content/plugins/super-forms/uploads/php/files/"
        $s35 = "https://www.ideaklinikankara.com/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s36 = "https://lacausedeslivres.com/userfiles/file/"
        $s37 = "https://investmentskillsgroup.com/images/userfiles/file/"
        $s38 = "https://leo-translate.com.ua/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s39 = "https://villanakarin.com/userfiles/files/"
        $s40 = "http://ohmamakitchen.com/uploads/files/"
        $s41 = "http://autoscuolauniversale.it/userfiles/files/"
        $s42 = "http://purofirstli.net/userfiles/file/"
        $s43 = "http://elistaprezentow.pl/userfiles/file/"
        $s44 = "http://email-database.info/userfiles/file/"
        $s45 = "https://akvaguru.hu/user/file/"
        $s46 = "http://medicapoland.pl/uploaded/file/"
        $s47 = "https://www.sgestrecho.es/wp-content/plugins/formcraft/file-upload/server/content/files/"

        $s48 = "https://leo-translate.com.ua/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s49 = "https://villanakarin.com/userfiles/files/"
        $s50 = "http://ohmamakitchen.com/uploads/files/"

    condition:
        $p and 1 of ($s*)
}
