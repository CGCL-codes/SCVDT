let v0 = Promise.resolve();
Object.defineProperty(v0, 'then', {
    get: () => new Proxy(function () {
    }, v0)
});
new Promise(r => r(v0));
