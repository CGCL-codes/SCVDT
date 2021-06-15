function f0() {
    'use strict';
    let v0 = 1;
    eval('let a = 1; a++;');
    WScript.Echo(v0);
}
WScript.Attach(f0);
