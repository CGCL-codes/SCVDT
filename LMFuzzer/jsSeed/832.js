function f0() {
}
var v0 = f0.bind(33, 44);
f0.apply = function () {
    $ERROR('Function.prototype.bind called original\'s .apply method');
};
v0(55, 66);
