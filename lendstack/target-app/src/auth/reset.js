// V-20: timestamp + Math.random() — predictable token space,
//       no expiry enforced anywhere (check happens in routes.js).
function generateResetToken() {
  const ts   = Date.now().toString(36);
  const rand = Math.random().toString(36).substring(2, 8);
  return `${ts}-${rand}`;
}
module.exports = { generateResetToken };
