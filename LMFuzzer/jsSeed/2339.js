var v0 = 1, v1 = 2, v2 = 3;
v0 = v1;
++v2;
if (v0 !== v1)
    $ERROR('#1: Automatic semicolon insertion not work with ++');
