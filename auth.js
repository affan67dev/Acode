import jwt from 'jsonwebtoken';

const secret = process.env.JWT_SECRET;
if (!secret || secret.length < 32) {
  throw new Error('JWT_SECRET is required and must be at least 32 characters.');
}

export function setAuth(res,user){
  const token=jwt.sign({id:user.id,role:user.role,email:user.email},secret,{expiresIn:'7d'});
  res.cookie('auth',token,{
    httpOnly:true,
    sameSite:'lax',
    secure:process.env.NODE_ENV==='production',
    maxAge:7*86400000,
    path:'/'
  });
}
export function clearAuth(res){res.clearCookie('auth',{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',path:'/'});}
export function requireAuth(req,res,next){
  try{
    const token=req.cookies?.auth;
    if(!token) throw new Error();
    req.user=jwt.verify(token,secret);
    next();
  }catch{res.status(401).json({error:'Authentication required'});}
}
export function requireAdmin(req,res,next){
  if(req.user?.role!=='admin') return res.status(403).json({error:'Admin access required'});
  next();
}