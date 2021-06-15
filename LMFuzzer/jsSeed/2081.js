class A extends Function {
    constructor(...args) {
        super(...args);
        this.a = 42;
        this.d = 4.2;
        this.o = 0;
    }
}
var v0 = new A('\'use strict\';');
v0.o = 0.1;
