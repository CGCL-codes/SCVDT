v0 = {
    has() {
        return true;
    }
};
v1 = new Proxy({}, v0);
function f0(object) {
    with (object) {
        return delete __v_3;
    }
}
f0(v1);
