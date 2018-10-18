// https://www.npmjs.com/package/bcryptjs

var bcrypt = require('bcryptjs');
var salt = bcrypt.genSaltSync(10);
var hash = bcrypt.hashSync("P@$$w0rd", salt);
console.log("Salt:     " + salt);
console.log("Password: " + hash);
console.log(bcrypt.compareSync("P@$$w0rd", hash)); // true
console.log(bcrypt.compareSync("not_P@$$w0rd", hash)); // false
