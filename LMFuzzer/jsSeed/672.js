if (this.Worker) {
    var v0 = new Worker('');
    v0.terminate();
    v0.getMessage();
}
