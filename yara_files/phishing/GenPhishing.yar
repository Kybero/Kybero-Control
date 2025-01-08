rule Susp_PDFPhishing_Generic {
    meta:
        description = "Detects PDF phishing based on suspicious domain structure"
        author = "Kybero Labs"

    strings:
        $s1 = "/wp-content/plugins/super-forms/uploads/php/files/"
        $s2 = "/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s3 = "/ckfinder/userfiles/files/"

    condition:
        uint32(0) == 0x25504446 and 1 of ($s*)
}

rule PDFPhishing_Generic_A {
    meta:
        description = "Detects PDF phishing based on authors"
        author = "Kybero Labs"

    strings:
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
        uint32(0) == 0x25504446 and 2 of ($s*)
}

rule PDFPhishing_Generic_B {
    meta:
        description = "Detects PDF phishing based on risky domain connections"
        author = "Kybero Labs"

    strings:
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
        $s48 = "https://traffset.ru/"
        $s49 = "https://medvor.ru/"
        $s50 = "http://turatabor.hu/media/"
        $s51 = "https://rfcorporation.net/wp-content/plugins/super-forms/uploads/php/files/"
        $s52 = "https://people11people.com/uploads/File/"
        $s53 = "http://shinserviceodi.ru/wp-content/plugins/super-forms/uploads/php/files/"
        $s54 = "https://teplitsyoptom.ru/wp-content/plugins/super-forms/uploads/php/files/"
        $s55 = "https://nmcs.ca/userfiles/files/"
        $s56 = "http://donaldnathanlaw.com/customer/"
        $s57 = "http://greaterdeliveranceministries1.com/clients/"
        $s58 = "https://evg-prague.fr/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s59 = "https://gresathouse.com/wp-content/plugins/super-forms/uploads/php/files/"
        $s60 = "http://www.assignproject.com/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s61 = "https://gpuhub.net/wp-content/plugins/super-forms/uploads/php/files/"
        $s62 = "https://www.asahinafunnels.com/wp-content/plugins/super-forms/uploads/php/files/"
        $s63 = "https://fietenhaardenenkachels.nl/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s64 = "http://ampletrekking.com/userfiles/file/"
        $s65 = "http://www.1000ena.com/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s66 = "http://amwordpress.org/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s67 = "https://urbanplace.me/wp-content/plugins/super-forms/uploads/php/files/"
        $s68 = "https://lashmakerpro.it/wp-content/plugins/super-forms/uploads/php/files/"
        $s69 = "http://discoveryenglish.org/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s70 = "https://michaels-limo.com/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s71 = "https://angkorphotographyguide.com/userfiles/file/"
        $s72 = "https://ladangmimpi.com/contents//files/"
        $s73 = "https://cremeconferences.com/wp-content/plugins/super-forms/uploads/php/files/"
        $s74 = "https://www.teppiche-waschen-hamburg.de/wp-content/plugins/formcraft/file-upload/server/content/files/"
        $s75 = "http://fullcolorspandoeken.nl/userfiles/file/"

    condition:
        uint32(0) == 0x25504446 and 1 of ($s*)
}
