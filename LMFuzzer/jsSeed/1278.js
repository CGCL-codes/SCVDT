if (this.Worker) {
    var v0 = new Worker('onmessage = function(){}');
    var v1 = new ArrayBuffer();
    v0.postMessage(v1, [v1]);
}
