var v0 = new Object();
v0.x = 5;
v0.y = 'why';
WScript.Echo(v0['x']);
var v1 = 'y';
WScript.Echo(v0[v1]);
v0['y'] = 'yes';
WScript.Echo(v0.y);
for (field in v0) {
    WScript.Echo(v0[field]);
}
