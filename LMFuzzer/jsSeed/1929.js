function f0() {
    return /\41/.exec('!')[0] === '!' && /[\41]/.exec('!')[0] === '!';
}
if (!f0())
    throw new Error('Test failed');
