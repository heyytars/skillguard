const fs = require('fs');
const path = require('path');

async function fetchSpec(url) {
  const res = await fetch(url, { headers: { 'User-Agent': 'spec-fetcher/1.0' } });
  const body = await res.text();
  fs.writeFileSync(path.join('/tmp', 'spec.json'), body);
  return JSON.parse(body);
}

module.exports = { fetchSpec };
