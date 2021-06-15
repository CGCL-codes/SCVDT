try {
    var v0 = Error('123');
    v0.somevalue = 'xyz';
    v0.stack = 'abacaba';
    WScript.Echo('description = ' + v0.description);
    WScript.Echo('stack = ' + v0.stack);
    for (var v1 in v0) {
        WScript.Echo(v1 + ' = ' + v0[v1]);
    }
    throw v0;
} catch (ex) {
    WScript.Echo('----------------------');
    WScript.Echo('description = ' + v0.description);
    WScript.Echo('stack = ' + v0.stack);
    for (var v1 in ex) {
        WScript.Echo(v1 + ' = ' + ex[v1]);
    }
}