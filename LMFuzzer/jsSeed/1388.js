if (this.Worker) {
    var v0 = new Worker('onmessage = function() {}');
    v0.postMessage('');
}
