var v0 = function () {
    var v0;
    for (var v1 = 0; v1 < 10000000; ++v1)
        v0 = String.fromCharCode(32);
    return v0;
}();
if (v0 != ' ')
    throw 'Error: bad result: ' + v0;
