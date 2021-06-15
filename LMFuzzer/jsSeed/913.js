v0 = v0 = '';
function f0(v0) {
    this.x = v0;
}
function f1() {
    var v1 = {};
    for (var v2 = 0; v2 < 1500; v2++)
        new f0(v1);
    f0('');
}
f1();
