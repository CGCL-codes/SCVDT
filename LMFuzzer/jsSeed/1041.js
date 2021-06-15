function f0(str) {
    try {
        eval(str);
    } catch (e) {
        WScript.Echo(e);
    }
}
f0('var a = { 1} ');
f0('var a = { 0.01 } ');
f0('var a = { "s" } ');
