(function () {
    Error.prototype.toString.call({
        get name() {
            return { __proto__: this };
        },
        get message() {
        }
    });
}());
