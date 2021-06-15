taintProperties([
    'weekday',
    'era',
    'year',
    'month',
    'day',
    'hour',
    'minute',
    'second',
    'inDST'
]);
var v0 = new Intl.DateTimeFormat();
var v1 = v0.format();
