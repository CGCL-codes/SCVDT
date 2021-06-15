function f0(value) {
    WScript.Echo(value);
}
f0(String.fromCharCode(65, 66, 67));
f0(String.fromCharCode(65.23, 66, 67.98));
f0(String.fromCharCode('65', '66', '67'));
