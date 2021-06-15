var v0 = {
    then: function (_, reject) {
        reject();
    }
};
Promise.all([v0]).then(function () {
    $DONE('The promise should not be fulfilled.');
}, function (x) {
    $DONE();
});
