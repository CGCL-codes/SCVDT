var v0 = function () {
    var v1 = v0.caller;
    return v1;
};
var v2 = {};
v2.toString = v0;
try {
    Object.hasOwnProperty(v2);
} catch (e) {
}
