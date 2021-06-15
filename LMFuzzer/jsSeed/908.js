try {
    Error.prepareStackTrace = function (error, stackTrace) {
        stackTrace.some();
    };
    x;
} catch (e) {
}
