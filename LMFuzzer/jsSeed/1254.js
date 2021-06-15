(function () {
    var v0 = new Object();
    v0.x = 4;
    Object.freeze(v0);
    v0.x = 3;
    WScript.Echo(v0.x);
}());
