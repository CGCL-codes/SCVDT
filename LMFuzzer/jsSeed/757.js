var v0 = /^on([A-Z])/;
var v1 = ['onClick'];
var v2;
for (var v3 = 0; v3 < v1.length; v3++) {
    v2 = v0.exec(v1[v3]);
}
WScript.Echo(v2.toString());
