const app = require('./app.js');
require('dotenv').config();




/////////////

const port = process.env.PORT || 3000;
const ip = process.env.IP || "127.0.0.1";

app.listen(port, ip, () => {
  console.log(`The website is running on port ${port}`);
});
