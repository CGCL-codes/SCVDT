function* f0() {
    yield;
}
let v0 = f0();
v0.next();
v0.throw(42);
