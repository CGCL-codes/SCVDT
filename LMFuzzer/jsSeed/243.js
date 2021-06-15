function f0(msg) {
    msg.split('\n');
}
function f1() {
    return undefined;
}
f2();
function f2() {
    f1();
    f0('');
    for (let v0 = 0; false;);
    new f2();
}
