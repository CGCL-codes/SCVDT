if (this.Worker) {
    assertThrows(function () {
        Worker.prototype.constructor('55');
    });
}
