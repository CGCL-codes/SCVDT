var v0 = [];
v0[4294967294] = 8;
try {
    v0.splice(4294967295, 0, 1);
} catch (e) {
    WScript.Echo('PASS');
}
