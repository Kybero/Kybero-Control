rule Infostealer_Generic_A {
    meta:
        threat_name = "Infostealer/Generic.A"
        author = "ditekSHen"
        description = "Detects executables containing SQL queries to confidential data stores. Observed in infostealers"
    strings:
        $select = "select " ascii wide nocase
        $table1 = " from credit_cards" ascii wide nocase
        $table2 = " from logins" ascii wide nocase
        $table3 = " from cookies" ascii wide nocase
        $table4 = " from moz_cookies" ascii wide nocase
        $table5 = " from moz_formhistory" ascii wide nocase
        $table6 = " from moz_logins" ascii wide nocase
        $column1 = "name" ascii wide nocase
        $column2 = "password_value" ascii wide nocase
        $column3 = "encrypted_value" ascii wide nocase
        $column4 = "card_number_encrypted" ascii wide nocase
        $column5 = "isHttpOnly" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 2 of ($table*) and 2 of ($column*) and $select
}

rule Infostealer_Generic_B {
    meta:
        threat_name = "Infostealer/Generic.B"
        description = "Detects binaries (Windows and macOS) referencing many web browsers. Observed in information stealers."
        author = "ditekSHen"
    strings:
        $s1 = "Uran\\User Data" nocase ascii wide
        $s2 = "Amigo\\User Data" nocase ascii wide
        $s3 = "Torch\\User Data" nocase ascii wide
        $s4 = "Chromium\\User Data" nocase ascii wide
        $s5 = "Nichrome\\User Data" nocase ascii wide
        $s6 = "Google\\Chrome\\User Data" nocase ascii wide
        $s7 = "360Browser\\Browser\\User Data" nocase ascii wide
        $s8 = "Maxthon3\\User Data" nocase ascii wide
        $s9 = "Comodo\\User Data" nocase ascii wide
        $s10 = "CocCoc\\Browser\\User Data" nocase ascii wide
        $s11 = "Vivaldi\\User Data" nocase ascii wide
        $s12 = "Opera Software\\" nocase ascii wide
        $s13 = "Kometa\\User Data" nocase ascii wide
        $s14 = "Comodo\\Dragon\\User Data" nocase ascii wide
        $s15 = "Sputnik\\User Data" nocase ascii wide
        $s16 = "Google (x86)\\Chrome\\User Data" nocase ascii wide
        $s17 = "Orbitum\\User Data" nocase ascii wide
        $s18 = "Yandex\\YandexBrowser\\User Data" nocase ascii wide
        $s19 = "K-Melon\\User Data" nocase ascii wide
        $s20 = "Flock\\Browser" nocase ascii wide
        $s21 = "ChromePlus\\User Data" nocase ascii wide
        $s22 = "UCBrowser\\" nocase ascii wide
        $s23 = "Mozilla\\SeaMonkey" nocase ascii wide
        $s24 = "Apple\\Apple Application Support\\plutil.exe" nocase ascii wide
        $s25 = "Preferences\\keychain.plist" nocase ascii wide
        $s26 = "SRWare Iron" ascii wide
        $s27 = "CoolNovo" ascii wide
        $s28 = "BlackHawk\\Profiles" ascii wide
        $s29 = "CocCoc\\Browser" ascii wide
        $s30 = "Cyberfox\\Profiles" ascii wide
        $s31 = "Epic Privacy Browser\\" ascii wide
        $s32 = "K-Meleon\\" ascii wide
        $s33 = "Maxthon5\\Users" ascii wide
        $s34 = "Nichrome\\User Data" ascii wide
        $s35 = "Pale Moon\\Profiles" ascii wide
        $s36 = "Waterfox\\Profiles" ascii wide
        $s37 = "Amigo\\User Data" ascii wide
        $s38 = "CentBrowser\\User Data" ascii wide
        $s39 = "Chedot\\User Data" ascii wide
        $s40 = "RockMelt\\User Data" ascii wide
        $s41 = "Go!\\User Data" ascii wide
        $s42 = "7Star\\User Data" ascii wide
        $s43 = "QIP Surf\\User Data" ascii wide
        $s44 = "Elements Browser\\User Data" ascii wide
        $s45 = "TorBro\\Profile" ascii wide
        $s46 = "Suhba\\User Data" ascii wide
        $s47 = "Secure Browser\\User Data" ascii wide
        $s48 = "Mustang\\User Data" ascii wide
        $s49 = "Superbird\\User Data" ascii wide
        $s50 = "Xpom\\User Data" ascii wide
        $s51 = "Bromium\\User Data" ascii wide
        $s52 = "Brave\\" nocase ascii wide
        $s53 = "Google\\Chrome SxS\\User Data" ascii wide
        $s54 = "Microsoft\\Internet Explorer" ascii wide
        $s55 = "Packages\\Microsoft.MicrosoftEdge_" ascii wide
        $s56 = "IceDragon\\Profiles" ascii wide
        $s57 = "\\AdLibs\\" nocase ascii wide
        $s58 = "Moonchild Production\\Pale Moon" nocase ascii wide
        $s59 = "Firefox\\Profiles" nocase ascii wide
        $s60 = "AVG\\Browser\\User Data" nocase ascii wide
        $s61 = "Kinza\\User Data" nocase ascii wide
        $s62 = "URBrowser\\User Data" nocase ascii wide
        $s63 = "AVAST Software\\Browser\\User Data" nocase ascii wide
        $s64 = "SalamWeb\\User Data" nocase ascii wide
        $s65 = "Slimjet\\User Data" nocase ascii wide
        $s66 = "Iridium\\User Data" nocase ascii wide
        $s67 = "Blisk\\User Data" nocase ascii wide
        $s68 = "uCozMedia\\Uran\\User Data" nocase ascii wide
        $s69 = "setting\\modules\\ChromiumViewer" nocase ascii wide
        $s70 = "Citrio\\User Data" nocase ascii wide
        $s71 = "Coowon\\User Data" nocase ascii wide
        $s72 = "liebao\\User Data" nocase ascii wide
        $s73 = "Edge\\User Data" nocase ascii wide
        $s74 = "BlackHawk\\User Data" nocase ascii wide
        $s75 = "QQBrowser\\User Data" nocase ascii wide
        $s76 = "GhostBrowser\\User Data" nocase ascii wide
        $s77 = "Xvast\\User Data" nocase ascii wide
        $s78 = "360Chrome\\Chrome\\User Data" nocase ascii wide
        $s79 = "Brave-Browser\\User Data" nocase ascii wide
        $s80 = "Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer" nocase ascii wide
        $s81 = "Chromodo\\User Data" nocase ascii wide
        $s82 = "Mail.Ru\\Atom\\User Data" nocase ascii wide
        $s83 = "8pecxstudios\\Cyberfox" nocase ascii wide
        $s84 = "NETGATE Technologies\\BlackHaw" nocase ascii wide
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0xfacf) and 6 of them
}

rule Infostealer_Generic_C {
    meta:
        threat_name = "Infostealer/Generic.C"
        author = "ditekSHen"
        description = "Detects Prynt, WorldWind, DarkEye, Stealerium and ToxicEye / TelegramRAT infostealers"
    strings:
        $n1 = /Prynt|WorldWind|DarkEye(\s)?Stealer/ ascii wide
        $n2 = "Stealerium" ascii wide
        $x1 = "@FlatLineStealer" ascii wide
        $x2 = "@CashOutGangTalk" ascii wide
        $x3 = /\.Target\.(Passwords|Messengers|Browsers|VPN|Gaming)\./ ascii
        $x4 = /\.Modules\.(Keylogger|Implant|Passwords|Messengers|Browsers|VPN|Gaming|Clipper)\./ ascii
        $s1 = "Timeout /T 2 /Nobreak" fullword wide
        $s2 =  /---\s(AntiAnalysis|WebcamScreenshot|Keylogger|Clipper)/ wide
        $s3 = "Downloading file: \"{file}\"" wide
        $s4 = "/bot{0}/getUpdates?offset={1}" wide
        $s5 = "send command to bot!" wide
        $s6 = " *Keylogger " fullword wide
        $s7 = "*Stealer" wide
        $s8 = "Bot connected" wide
        $s9 = "### {0} ### ({1})" wide
    condition:
        uint16(0) == 0x5a4d and 4 of them
}
