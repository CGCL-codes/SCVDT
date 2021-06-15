if (this.Worker) {
    Function.prototype.toString = 'foo';
    function f0() {
    }
    assertThrows(function () {
        var v0 = new Worker(f0.toString());
    });
}
