var v0 = function () {
    var v0;
    for (var v1 = 0; v1 < 1000000; ++v1)
        v0 = String.fromCharCode(1000);
    return v0;
}();
if (v0 != 'Ϩ')
    throw 'Error: bad result: ' + v0;
