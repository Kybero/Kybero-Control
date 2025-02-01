rule Ransom_Ako_A_con {
    meta:
        threat_name = "Ransom/Ako.A!con"
        description = "Detects Ako"
        author = "Kybero Labs"

    strings:
        $s1 = "true NETWORK"
        $s2 = "AppData,boot,PerfLogs,ProgramData,Google,Intel,Microsoft,Application Data,Tor Browser,Windows"
        $s3 = ".arm,.acr,.arz,.bck,.bak,.cnf,.dbs,.ddl,.frm,.ibd,.ism,.mrg,.mdf,.mds,.frm,.myd,.myi,.mysql,.opt,.phl,.sal,.sqr,.tmd,.ibz,.ibc,.pptx,.pptm,.ppt,.potx,.potm,.qbquery,.rul,.qbw,.qbmb,.qbb,.qbm,.qbo,.des,.qbr,.qwc,.qbx,.qba,.qby,.qbj,.tlg,.xlc,.zip,.rar,.ldf,.avhd,.vhd,.vsv,.vmrs,.vmcx,.vhdx,.iso"
        $s4 = "winword.exe,visio.exe,encsvc.exe,mysqld_opt.exe,ocssd.exe,thebat.exe,ocomm.exe,outlook.exe,onenote.exe,sqlwriter.exe,msaccess.exe,mysqld.exe,sqlagent.exe,sqlservr.exe,infopath.exe,sqlbrowser.exe,thunderbird.exe,msftesql.exe,wordpad.exe,synctime.exe,agntsvc.exe,dbsnmp.exe,mydesktopservice.exe,ocautoupds.exe,thebat64.exe,sqbcoreservice.exe,isqlplussvc.exe,oracle.exe,tbirdconfig.exe,mysqld_nt.exe"
        $s5 = "vmickvpexchange,vmicguestinterface,vmicshutdown,vmicheartbeat,MSSQLFDLauncher,MSSQLSERVER,SQLBrowser,SQLSERVERAGENT,SQLWriter,MSSQL,WRSVC,ekrn"
        $s6 = "Your network has been hacked and locked."
        $s7 = "All files on each host in the network have been encrypted with a strong algorithm."
        $s8 = "Backups were either encrypted or deleted or backup disks were formatted."
        $s9 = "Shadow copies also removed. Any 3rd party software may damage encrypted data but not recover."
        $s10 = "We have decryption software for your situation."
        $s11 = "No decryption software is available in the public."
        $s12 = "DO NOT RESET OR SHUTDOWN - files may be damaged."
        $s13 = "DO NOT RENAME OR MOVE the encrypted and readme files."
        $s14 = "DO NOT DELETE readme files."
        $s15 = "To get info (decrypt your files) follow this instructions:"
        $s16 = "1) [Recommended] via Tor Browser:"
        $s17 = "a) Download and install Tor Browser: https://www.torproject.org/download/"
        $s18 = "b) Open our website in TOR: http://kwvhrdibgmmpkhkidrby4mccwqpds5za6uo2thcw5gz75qncv7rbhyad.onion/{UID}"
        $s19 = "2) If you have any problems connecting or using TOR network:"
        $s20 = "a) Open our website: https://buydecrypt.hk/{UID}"
        $s21 = "b) Follow the instructions on the site"
        $s22 = "When you open our page, paste this key in form:"

    condition:
        all of them
}
