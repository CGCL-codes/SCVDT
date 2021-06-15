function f0(num) {
    var v0 = '';
    do {
        v0 += '0';
    } while (v0.length < num);
    return v0;
}
WScript.Echo(f0(4));
