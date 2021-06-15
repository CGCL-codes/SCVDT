Error.prepareStackTrace = function (exception, frames) {
    return frames[0].getEvalOrigin();
};
try {
    Realm.eval(0, 'throw new Error(\'boom\');');
} catch (e) {
    print(e.stack);
}
