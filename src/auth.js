const { query } = require("./db");

async function getUserFromRequest(req) {
  const token = req.headers.authorization?.startsWith("Bearer ")
    ? req.headers.authorization.slice(7)
    : req.headers["x-aveson-session"];

  if (!token) return null;

  const result = await query(`
    SELECT u.id, u.email, u.role, u.display_name
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.id = $1 AND s.expires_at > NOW()
  `, [token]);

  return result.rows[0] || null;
}

function requireAuth(req, res, next) {
  getUserFromRequest(req).then(user => {
    if (!user) return res.status(401).json({ error: "Authentication required" });
    req.user = user;
    next();
  }).catch(next);
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  };
}

module.exports = { getUserFromRequest, requireAuth, requireRole };