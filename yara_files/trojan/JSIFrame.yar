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
