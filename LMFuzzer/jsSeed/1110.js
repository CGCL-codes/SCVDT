var v0 = new Proxy({
    get: function () {
        throw 42;
    }
}, {});
Function.prototype.__proto__ = v0;
this.hasOwnProperty('Intl');
