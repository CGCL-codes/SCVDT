var v0 = 'Hello';
function f0(thing) {
    var v1 = 0;
    return function () {
        return v0 + ' ' + thing + ' #' + v1++;
    };
}
