const express = require('express');
const request = require('request');
const util = require('util');

const app = express();
app.use(express.json());

app.post('/proxy', (req, res) => {
  const { url } = req.query;

  const errorResponse = util.validateProxyRequest(url, res);
  if (errorResponse) {
    return errorResponse;
  }

  request.post(
    {
      url,
      headers: req.headers,
      body: req.body,
      json: true,
    },
    (error, response, body) => {
      if (error) {
        return res.status(500).send(`Request failed: ${error.message}`);
      }
      res.status(response.statusCode).send(body);
    }
  );
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Proxy server started. Listening on port ${PORT}`);
});