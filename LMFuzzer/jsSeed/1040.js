try {
    eval('((x = this));');
} catch (ex) {
}
try {
    eval('(524288 += x);');
} catch (ex) {
}
WScript.Echo('DONE');
