v0 = 1;
function f0(s) {
    return eval('line0 = Error.lineNumber\ndebugger\n' + s);
}
function f1(s) {
    return Array(65 << 13).join(s);
}
v1 = f1(' + i');
v2 = v1;
f0(v2);
