import jwt from 'jsonwebtoken';

const secret = process.env.JWT_SECRET;
if (!secret || secret.length < 32) console.warn('JWT_SECRET should be at least 32 characters.');

export function setAuth(res, user) {
  const token = jwt.sign({ id: user.id, role: user.role, email: user.email }, secret || 'development-only-secret', { expiresIn: '7d' });
  res.cookie('auth', token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 86400000 });
}
export function clearAuth(res) { res.clearCookie('auth'); }
export function requireAuth(req,res,next) {
  try { req.user = jwt.verify(req.cookies.auth || '', secret || 'development-only-secret'); next(); }
  catch { res.status(401).json({error:'Authentication required'}); }
}
export function requireAdmin(req,res,next) {
  if (req.user?.role !== 'admin') return res.status(403).json({error:'Admin access required'});
  next();
}