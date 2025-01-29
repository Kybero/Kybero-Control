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
