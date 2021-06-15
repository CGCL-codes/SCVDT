try {
    eval('function test() { function * arguments() { "use strict"; } }; test();');
} catch (e) {
    WScript.Echo(e);
}
