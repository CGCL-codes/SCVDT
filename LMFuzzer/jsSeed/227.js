v0 = new Proxy(Number.bind(), {});
Object.defineProperty(v0, 'caller', {
    set: function () {
    }
});
