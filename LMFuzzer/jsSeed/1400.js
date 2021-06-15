function f0() {
    eval('{ let b = 1; b++; /**bp:locals()**/ }');
    return 0;
}
f0();
WScript.Echo('PASSED');
