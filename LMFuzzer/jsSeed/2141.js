v0 = 4294967296;
for (var v1 = 0; v1 < 600000; v1++)
    v0 = v0 & v1;
var v2 = v0;
var v3 = 0;
if (v2 != v3)
    throw 'ERROR: bad result: expected ' + v3 + ' but got ' + v2;
