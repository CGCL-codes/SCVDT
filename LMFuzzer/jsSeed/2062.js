if (this.Worker && this.quit) {
    try {
        new Function(new Worker('55'));
    } catch (err) {
    }
    quit();
}
