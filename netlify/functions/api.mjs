import {getStore,connectLambda} from "@netlify/blobs";
import crypto from "node:crypto";
const db=()=>getStore("nova");
const SECRET=()=>process.env.JWT_SECRET||"";
const b64=x=>Buffer.from(x).toString("base64url");
const mac=s=>crypto.createHmac("sha256",SECRET()).update(s).digest("base64url");
const sign=e=>{const h=b64('{"alg":"HS256","typ":"JWT"}'),p=b64(JSON.stringify({e,exp:Date.now()+30*864e5}));return h+"."+p+"."+mac(h+"."+p)};
const verify=t=>{try{const [h,p,s]=t.split(".");const ok=mac(h+"."+p);if(s.length!==ok.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(ok)))return null;const d=JSON.parse(Buffer.from(p,"base64url"));return d.exp>Date.now()?d.e:null}catch{return null}};
const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{"Content-Type":"application/json"}});
const get=async(k,d)=>(await db().get(k,{type:"json"}))??d;
const put=(k,v)=>db().setJSON(k,v);
const isAdmin=e=>!!process.env.ADMIN_EMAIL&&e===process.env.ADMIN_EMAIL.trim().toLowerCase();
const hash=(pw,salt)=>crypto.scryptSync(pw,salt,64).toString("hex");
const live=l=>!l.revoked&&l.activatedBy&&(!l.expiresAt||l.expiresAt>Date.now());
const core=async(req)=>{
  const path=new URL(req.url).pathname.replace(/^\/(?:\.netlify\/functions\/api|api)\/?/,"");
  if(path==="ping")return J({ok:true,jwt:!!SECRET(),admin:!!process.env.ADMIN_EMAIL});
  if(!SECRET())return J({error:"Server is missing JWT_SECRET"},500);
  let b={};if(req.method==="POST")try{b=await req.json()}catch{}
  try{
    if(path==="signup"){
      const e=String(b.email||"").trim().toLowerCase();
      if(!/^\S+@\S+\.\S+$/.test(e)||String(b.password||"").length<8)return J({error:"Enter a valid email and a password of 8+ characters"},400);
      if(await get("u/"+e,null))return J({error:"An account with this email already exists"},409);
      const salt=crypto.randomBytes(16).toString("hex");
      await put("u/"+e,{email:e,name:String(b.name||"").slice(0,40),salt,hash:hash(String(b.password),salt),created:Date.now()});
      const ix=await get("users",[]);ix.push(e);await put("users",ix);
      return J({token:sign(e)});
    }
    if(path==="login"){
      const e=String(b.email||"").trim().toLowerCase(),u=await get("u/"+e,null);
      if(!u||hash(String(b.password||""),u.salt)!==u.hash)return J({error:"Wrong email or password"},401);
      return J({token:sign(e)});
    }
    const email=verify((req.headers.get("authorization")||"").slice(7));
    if(!email)return J({error:"Please sign in"},401);
    const admin=isAdmin(email);
    if(path==="me"){
      const u=await get("u/"+email,null);if(!u)return J({error:"No account"},401);
      const [eas,ls,st]=await Promise.all([get("eas",[]),get("licenses",[]),get("s/"+email,{})]);
      const mine=ls.filter(l=>l.activatedBy===email&&live(l)).map(l=>({eaId:l.eaId,expiresAt:l.expiresAt}));
      const ids=new Set(mine.map(l=>l.eaId));
      return J({user:{email,name:u.name,admin},eas:eas.filter(x=>admin||ids.has(x.id)),licenses:mine,settings:st});
    }
    if(path==="activate"){
      const key=String(b.key||"").trim().toUpperCase(),ls=await get("licenses",[]),l=ls.find(x=>x.key===key);
      if(!l||l.revoked)return J({error:"Invalid license key"},404);
      if(l.activatedBy&&l.activatedBy!==email)return J({error:"This key is already in use"},409);
      if(!l.activatedBy){l.activatedBy=email;l.activatedAt=Date.now();l.expiresAt=l.days?Date.now()+l.days*864e5:0;await put("licenses",ls)}
      return J({ok:true});
    }
    if(path==="settings"){
      if(JSON.stringify(b.settings||{}).length>40000)return J({error:"Too large"},413);
      await put("s/"+email,b.settings||{});return J({ok:true});
    }
    if(path==="ai"){
      if(!admin&&!(await get("licenses",[])).some(l=>l.activatedBy===email&&live(l)))return J({error:"A valid license is required"},403);
      const k="ai/"+email+"/"+new Date().toISOString().slice(0,10),n=await get(k,0);
      if(n>=60)return J({error:"Daily AI limit reached"},429);
      await put(k,n+1);
      const content=(b.images||[]).slice(0,1).map(u=>{const m=/^data:(.+?);base64,(.+)$/.exec(String(u));return m&&{type:"image",source:{type:"base64",media_type:m[1],data:m[2]}}}).filter(Boolean);
      content.push({type:"text",text:String(b.prompt||"").slice(0,8000)});
      const r=await fetch("https://api.anthropic.com/v1/messages",{method:"POST",headers:{"x-api-key":process.env.ANTHROPIC_API_KEY||"","anthropic-version":"2023-06-01","content-type":"application/json"},body:JSON.stringify({model:"claude-sonnet-5-5",max_tokens:1800,messages:[{role:"user",content}]})});
      const j=await r.json();if(!r.ok)return J({error:(j.error&&j.error.message)||"AI error"},502);
      return J({text:j.content.filter(c=>c.type==="text").map(c=>c.text).join("")});
    }
    if(path.startsWith("admin/")){
      if(!admin)return J({error:"Admins only"},403);
      if(path==="admin/data"){const [eas,licenses,users]=await Promise.all([get("eas",[]),get("licenses",[]),get("users",[])]);return J({eas,licenses,users})}
      if(path==="admin/ea"){
        const eas=await get("eas",[]),name=String(b.name||"").trim().slice(0,40);if(!name)return J({error:"EA name is required"},400);
        let x=eas.find(e=>e.id===b.id);if(!x){x={id:crypto.randomBytes(6).toString("hex")};eas.push(x)}
        Object.assign(x,{name,desc:String(b.desc||"").slice(0,200)});if(b.logo)x.logo=b.logo;if(b.bg)x.bg=b.bg;
        await put("eas",eas);return J({ok:true});
      }
      if(path==="admin/ea-delete"){await put("eas",(await get("eas",[])).filter(e=>e.id!==b.id));return J({ok:true})}
      if(path==="admin/licenses"){
        if(!b.eaId)return J({error:"Create an EA first"},400);
        const ls=await get("licenses",[]),out=[];
        for(let i=0;i<Math.min(+b.count||1,100);i++){const key=Array.from({length:4},()=>crypto.randomBytes(2).toString("hex").toUpperCase()).join("-");ls.push({key,eaId:b.eaId,days:+b.days||0,note:String(b.note||"").slice(0,60),createdAt:Date.now()});out.push(key)}
        await put("licenses",ls);return J({keys:out});
      }
      if(path==="admin/revoke"){const ls=await get("licenses",[]),l=ls.find(x=>x.key===b.key);if(l)l.revoked=true;await put("licenses",ls);return J({ok:true})}
    }
    return J({error:"Not found"},404);
  }catch(err){return J({error:"Server error: "+(err&&err.message||"unknown")},500)}
};
export default core;
export const config={path:"/api/*"};
export const handler=async(event)=>{
  try{connectLambda(event)}catch(e){}
  const m=event.httpMethod||"GET",nb=m==="GET"||m==="HEAD";
  const body=nb||!event.body?undefined:(event.isBase64Encoded?Buffer.from(event.body,"base64"):event.body);
  const res=await core(new Request("https://x"+(event.path||"/"),{method:m,headers:event.headers||{},body}));
  return {statusCode:res.status,headers:{"Content-Type":"application/json"},body:await res.text()};
};
