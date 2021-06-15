var v0 = function ff() {
    var v1 = 0;
    var v2 = function q() {
        return ++v1;
    };
    return v2;
};
function f0() {
    for (var v3 = 0; v3 < 10; ++v3) {
        v0();
    }
}
f0();
