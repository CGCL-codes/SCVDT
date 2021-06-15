function f0() {
}
f0.prototype = {
    set constructor(_) {
        $ERROR('`Base.prototype.constructor` is unreachable.');
    }
};
class C extends f0 {
}
new C();
