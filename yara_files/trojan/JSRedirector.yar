rule Trojan_JSRedirector_A_con {
    meta:
        description = "Detects JavaScript code creating functions to redirect links onto a malicious site"
        author = "Kybero Labs"

    strings:
        $s1 = "function mylink() {"
        $s2 = "seoref=\"+encodeURIComponent(document.referrer)+ \"&parameter=$keyword&se=$se&ur=1&HTTP_REFERER=\"+encodeURIComponent(document.URL)+\"&default_keyword="
        $s3 = "<a href=\"#\" onClick=\"mylink()\">"

    condition:
        all of them
}
