try {
    WScript.Echo('FAILED');
} catch (e) {
    if (e instanceof SyntaxError) {
        WScript.Echo('PASSED');
    } else {
        WScript.Echo('FAILED');
    }
}
