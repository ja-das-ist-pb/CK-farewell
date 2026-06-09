import os
import random
import json
import datetime
import smtplib
from email.mime.text import MIMEText
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_FILE = "messages.json"
OTP_STORE = {} 

ADMIN_EMAIL_LIST = ["paulpb0725@gmail.com", "chunhansung@gmail.com"]

SMTP_USER = "paulpb0725@gmail.com"    
SMTP_PASSWORD = "jpzauitvidrijrdz"

if not os.path.exists(DB_FILE):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump([], f)

class MessageInput(BaseModel):
    text: str

class EmailInput(BaseModel):
    email: str

class VerifyInput(BaseModel):
    email: str
    otp: str  # 登入時傳入6位數驗證碼，後續操作時傳入長期 Token

def read_db():
    with open(DB_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def write_db(data):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def send_otp_email(target_email: str, otp: str):
    if not SMTP_USER or not SMTP_PASSWORD:
        print(f"\n[本地測試提示] 未偵測到環境變數。管理員驗證碼為: 【 {otp} 】\n")
        return True 
    
    msg = MIMEText(f"您好：\n\n您的惜別留言牆管理員登入驗證碼為：【 {otp} 】\n請於 5 分鐘內輸入。若非本人操作請忽略此信。", "plain", "utf-8")
    msg["Subject"] = "【惜別 CK 留言牆】管理員登入驗證碼"
    msg["From"] = SMTP_USER
    msg["To"] = target_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, target_email, msg.as_string())
        return True
    except Exception as e:
        print(f"發信失敗: {e}")
        return False

# --- API 路由 ---

# 留言送出 (任何人)
@app.post("/api/messages/submit")
def submit_message(data: MessageInput):
    if not data.text.strip():
        raise HTTPException(status_code=400, detail="留言不能為空")
    db = read_db()
    new_id = max([m["id"] for m in db], default=0) + 1
    new_msg = {
        "id": new_id,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "content": data.text.strip(),
        "is_visible": True,
        "is_pinned": False
    }
    db.append(new_msg)
    write_db(db)
    return {"status": "success"}

# 公開牆讀取
@app.get("/api/messages/public")
def get_public_messages():
    db = read_db()
    public_list = [m for m in db if m["is_visible"]]
    public_list.reverse()
    return public_list

# 1. 管理員請求 6 位數驗證碼
@app.post("/api/admin/request-otp")
def request_otp(data: EmailInput):
    email = data.email.strip().lower()
    if email not in [e.lower() for e in ADMIN_EMAIL_LIST]:
        raise HTTPException(status_code=403, detail="您不是合法的管理員")
    
    otp = f"{random.randint(100000, 999999)}"
    OTP_STORE[email] = {
        "otp": otp,
        "expire": datetime.datetime.now() + datetime.timedelta(minutes=5)
    }
    
    success = send_otp_email(email, otp)
    if not success:
        raise HTTPException(status_code=500, detail="驗證碼發送失敗")
    return {"status": "success"}

# 2. 管理員第一次輸入 6 位數驗證碼登入
@app.post("/api/admin/verify")
def verify_admin_login(data: VerifyInput):
    email = data.email.strip().lower()
    if email not in OTP_STORE:
        raise HTTPException(status_code=400, detail="請先請求驗證碼")
    
    saved = OTP_STORE[email]
    if datetime.datetime.now() > saved["expire"]:
        del OTP_STORE[email]
        raise HTTPException(status_code=400, detail="驗證碼已過期")
        
    if data.otp != saved["otp"]:
        raise HTTPException(status_code=401, detail="驗證碼錯誤")
    
    # 驗證成功，發放「長期萬用通行證Token」給前端
    long_term_token = f"TOKEN_VALID_{email}"
    db = read_db()
    return {
        "token": long_term_token,
        "stats": {"total": len(db), "visible": sum(1 for m in db if m["is_visible"])},
        "messages": db
    }

# 3. 檢查長期權杖是否有效 (免重新登入用)
@app.post("/api/admin/check-token")
def check_token(data: VerifyInput):
    email = data.email.strip().lower()
    # 只要傳過來的 token 符合規則，就直接放行，不卡5分鐘限制！
    if data.otp == f"TOKEN_VALID_{email}":
        db = read_db()
        return {
            "stats": {"total": len(db), "visible": sum(1 for m in db if m["is_visible"])},
            "messages": db
        }
    raise HTTPException(status_code=401, detail="通行證過期，請重新登入")

# 4. 後台操作：隱藏/顯示留言 (使用長期 Token 驗證)
@app.post("/api/admin/toggle/{msg_id}")
def toggle_message(msg_id: int, data: VerifyInput):
    email = data.email.strip().lower()
    
    # 安全檢查
    if data.otp != f"TOKEN_VALID_{email}": 
        raise HTTPException(status_code=401, detail="未授權的操作，請重新登入")
        
    db = read_db()
    for m in db:
        if m["id"] == msg_id:
            m["is_visible"] = not m["is_visible"]
            write_db(db)
            return {
                "status": "success", 
                "messages": db, 
                "stats": {"total": len(db), "visible": sum(1 for x in db if x["is_visible"])}
            }
            
    raise HTTPException(status_code=404, detail="找不到該則留言")