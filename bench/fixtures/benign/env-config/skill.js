const apiKey = process.env.API_KEY;
if (!apiKey) {
  throw new Error('Set API_KEY in your environment before running this skill.');
}
module.exports = { apiKey };
