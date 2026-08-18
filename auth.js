const jwt=require("jsonwebtoken");
const bcrypt=require("bcryptjs");
const sign=payload=>jwt.sign(payload,process.env.JWT_SECRET,{expiresIn:"8h"});
function requireJwt(req,res,next){
 const h=req.headers.authorization||"",t=h.startsWith("Bearer ")?h.slice(7):null;
 if(!t)return res.status(401).json({error:"Authentication required"});
 try{req.user=jwt.verify(t,process.env.JWT_SECRET);next();}catch{return res.status(401).json({error:"Invalid or expired token"});}
}
const verifyPassword=(p,h)=>bcrypt.compare(p,h);
const hashPassword=p=>bcrypt.hash(p,12);
module.exports={sign,requireJwt,verifyPassword,hashPassword};
