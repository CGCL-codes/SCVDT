class BaseClass {
    method() {
        return 1;
    }
}
class SubClass extends BaseClass {
    method(...args) {
        return super.method(...args);
    }
}
var v0 = new SubClass();
v0.method();
