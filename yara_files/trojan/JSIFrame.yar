rule Suspicious_Trojan_JSIFrame {
    meta:
        description = "Detects invisible IFrame instances - possibly malicious"
        author = "Kybero Labs"

    strings:
        $s = "width=0 height=0></iframe>"

    condition:
        $s
}

rule Trojan_JSIFrame_A_con {
    meta:
        description = "Detects malicious IFrame instances hidden in JavaScript code"
        author = "Kybero Labs"

    strings:
        $s1 = "<script>i=0;try{prototype;}catch(z){h=\"harCode\";f=["
        $s2 = "][0].split('c');v=\"e\"+\"va\";}if(v)e=window[v+\"l\"];try{q=document.createElement(\"div\");q.appendChild(q+\"\");}catch(qwg){w=f;s=[];}r=String;z=((e)?h:\"\");for(;595!=i;i+=1){j=i;if(e)s=s+r[\"fromC\"+z](w[j]*1+42);}if(v&&e&&r)e(s);</script>"

    condition:
        all of them
}

rule Trojan_JSIFrame_B_con {
    meta:
        description = "Detects malicious IFrame instances hidden in JavaScript code"
        author = "Kybero Labs"

    strings:
        $s1 = "(function () {    var phxa = document.createElement('iframe');    phxa.src ="
        $s2 = "phxa.style.position = 'absolute';    phxa.style.border = '0';    phxa.style.height = '1px';    phxa.style.width = '1px';    phxa.style.left = '1px';    phxa.style.top = '1px';    if (!document.getElementById('phxa')) {        document.write('<div id=\\'phxa\\'></div>');        document.getElementById('phxa').appendChild(phxa);    }})();"

    condition:
        all of them
}

rule Trojan_JSIFrame_C_con {
    meta:
        description = "Detects malicious IFrame instances hidden in JavaScript code"
        author = "Kybero Labs"

    strings:
        $s = "[\"split\"](\"a!\".substr(1));for(i=6-2-1-2-1;i!=613;i++){j=i;if(st)ss=ss+st[f](-h*(1+1*n[j]));}if(zz)q=ss;if(t)e(\"\"+q);</script>"

    condition:
        $s
}

rule Trojan_JSIFrame_D_con {
    meta:
        description = "Detects malicious IFrame instances hidden in JavaScript code"
        author = "Kybero Labs"

    strings:
        $s = "<script>if(window.document)a=(\""

    condition:
        $s
}

rule Trojan_JSIFrame_E_con {
    meta:
        description = "Detects malicious IFrame instances hidden in JavaScript code"
        author = "Kybero Labs"

    strings:
        $s = "</html><script type=\"text/javascript\">eval(String.fromCharCode("

    condition:
        $s
}
