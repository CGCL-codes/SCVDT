if (typeof Promise.race !== 'function') {
    $ERROR('Expected Promise.race to be a function, actually ' + typeof Promise.race);
}
