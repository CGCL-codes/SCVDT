var v0 = false;
var v1 = true;
if (!v0)
    WScript.Echo('test 1');
if (!!!v0)
    WScript.Echo('test 2');
if (v1)
    WScript.Echo('test 3');
if (!!v1)
    WScript.Echo('test 4');
