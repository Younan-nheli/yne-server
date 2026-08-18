require("dotenv").config();
const express=require("express"),helmet=require("helmet"),crypto=require("crypto");
const db=require("./db"),{sign,requireJwt,verifyPassword,hashPassword}=require("./auth");
const app=express();app.use(helmet());app.use(express.json({limit:"256kb"}));
const newKey=()=>`YNE-${crypto.randomBytes(5).toString("hex").toUpperCase()}-${crypto.randomBytes(5).toString("hex").toUpperCase()}`;
function state(r){
 if(!r)return{valid:false,reason:"NOT_FOUND"};
 if(!r.active)return{valid:false,reason:"RESTAURANT_DISABLED"};
 if(r.status!=="active")return{valid:false,reason:"LICENSE_DISABLED"};
 if(r.expires_at&&new Date(r.expires_at)<=new Date())return{valid:false,reason:"EXPIRED"};
 return{valid:true,reason:"ACTIVE"};
}
app.get("/api/health",async(_,res)=>{try{await db.query("SELECT 1");res.json({ok:true,service:"YNE Server",database:"connected"});}catch{res.status(503).json({ok:false,service:"YNE Server",database:"disconnected"});}});
app.post("/api/master/login",async(req,res)=>{
 const{username,password}=req.body||{},u=process.env.MASTER_USERNAME,h=process.env.MASTER_PASSWORD_HASH;
 if(!username||!password)return res.status(400).json({error:"Username and password are required"});
 if(!u||!h)return res.status(503).json({error:"Master account is not configured"});
 if(username!==u||!(await verifyPassword(password,h)))return res.status(401).json({error:"Invalid master credentials"});
 res.json({token:sign({type:"master",username})});
});
app.post("/api/master/restaurants",requireJwt,async(req,res)=>{
 if(req.user.type!=="master")return res.status(403).json({error:"Master access required"});
 const{name,code,phone=null,address=null,expiresAt=null,adminUsername,adminPassword}=req.body||{};
 if(!name||!code||!adminUsername||!adminPassword)return res.status(400).json({error:"name, code, adminUsername and adminPassword are required"});
 const c=await db.pool.connect();
 try{
  await c.query("BEGIN");
  const r=(await c.query("INSERT INTO restaurants(name,code,phone,address) VALUES($1,$2,$3,$4) RETURNING *",[name,code,phone,address])).rows[0];
  await c.query("INSERT INTO restaurant_users(restaurant_id,username,password_hash,role) VALUES($1,$2,$3,'Admin')",[r.id,adminUsername,await hashPassword(adminPassword)]);
  const l=(await c.query("INSERT INTO licenses(restaurant_id,license_key,expires_at) VALUES($1,$2,$3) RETURNING *",[r.id,newKey(),expiresAt])).rows[0];
  await c.query("COMMIT");res.status(201).json({restaurant:r,license:l,adminUsername});
 }catch(e){await c.query("ROLLBACK");res.status(400).json({error:e.code==="23505"?"Restaurant code or username already exists":"Could not create restaurant"});}
 finally{c.release();}
});
app.get("/api/master/restaurants",requireJwt,async(req,res)=>{
 if(req.user.type!=="master")return res.status(403).json({error:"Master access required"});
 const r=await db.query("SELECT r.*,l.license_key,l.status AS license_status,l.starts_at,l.expires_at FROM restaurants r LEFT JOIN licenses l ON l.restaurant_id=r.id ORDER BY r.created_at DESC");
 res.json(r.rows);
});
app.patch("/api/master/restaurants/:id/status",requireJwt,async(req,res)=>{
 if(req.user.type!=="master")return res.status(403).json({error:"Master access required"});
 const r=await db.query("UPDATE restaurants SET active=$1,updated_at=NOW() WHERE id=$2 RETURNING *",[Boolean(req.body?.active),req.params.id]);
 if(!r.rowCount)return res.status(404).json({error:"Restaurant not found"});res.json(r.rows[0]);
});
app.patch("/api/master/licenses/:id",requireJwt,async(req,res)=>{
 if(req.user.type!=="master")return res.status(403).json({error:"Master access required"});
 const{status,expiresAt}=req.body||{};
 if(!["active","disabled"].includes(status))return res.status(400).json({error:"status must be active or disabled"});
 const r=await db.query("UPDATE licenses SET status=$1,expires_at=$2,updated_at=NOW() WHERE id=$3 RETURNING *",[status,expiresAt??null,req.params.id]);
 if(!r.rowCount)return res.status(404).json({error:"License not found"});res.json(r.rows[0]);
});
app.post("/api/pos/login",async(req,res)=>{
 const{restaurantCode,username,password}=req.body||{};
 if(!restaurantCode||!username||!password)return res.status(400).json({error:"restaurantCode, username and password are required"});
 const r=(await db.query("SELECT u.*,r.name AS restaurant_name,r.code AS restaurant_code,r.active AS restaurant_active,l.status AS license_status,l.expires_at FROM restaurant_users u JOIN restaurants r ON r.id=u.restaurant_id JOIN licenses l ON l.restaurant_id=r.id WHERE r.code=$1 AND u.username=$2",[restaurantCode,username])).rows[0];
 if(!r||!(await verifyPassword(password,r.password_hash)))return res.status(401).json({error:"Invalid restaurant credentials"});
 const s=state({active:r.restaurant_active,status:r.license_status,expires_at:r.expires_at});
 if(!r.active||!s.valid)return res.status(403).json({error:"Restaurant account or license is disabled",reason:s.reason});
 res.json({token:sign({type:"restaurant",restaurantId:r.restaurant_id,role:r.role,username:r.username}),restaurant:{id:r.restaurant_id,name:r.restaurant_name,code:r.restaurant_code},role:r.role,license:{status:"active",expiresAt:r.expires_at}});
});
app.post("/api/pos/license/verify",requireJwt,async(req,res)=>{
 if(req.user.type!=="restaurant")return res.status(403).json({error:"Restaurant access required"});
 const r=(await db.query("SELECT r.active,l.status,l.expires_at FROM restaurants r JOIN licenses l ON l.restaurant_id=r.id WHERE r.id=$1",[req.user.restaurantId])).rows[0];
 res.json(state(r));
});
app.listen(Number(process.env.PORT||3000),()=>console.log("YNE Server running"));
