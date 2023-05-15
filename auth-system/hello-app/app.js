var express = require('express');
var app = express();

// app.get('/', function (req, res) {
//   res.send('Hello World!');
// });

app.get('/world', function(_, res) {
  res.send('Hello, World!')
})

app.get('/admin', function(_, res) {
  res.send('Hello, Admin!')
})

app.get('/user', function(_, res) {
  res.send('Hello, User!')
})

app.listen(3000, function () {
  console.log('Listening to Port 3000');
});
