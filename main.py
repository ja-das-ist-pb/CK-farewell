import os
import random
import json
import datetime
import smtplib
from email.mime.text import MIMEText
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

firebase_creds = json.loads(
    os.environ["FIREBASE_CREDENTIALS"]
)

cred = credentials.Certificate(firebase_creds)

firebase_admin.initialize_app(cred)

db_firestore = firestore.client()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


OTP_STORE = {} 

ADMIN_EMAIL_LIST = ["paulpb0725@gmail.com", "chunhansung@gmail.com"]

SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")


class MessageInput(BaseModel):
    text: str

class EmailInput(BaseModel):
    email: str

class VerifyInput(BaseModel):
    email: str
    otp: str  # 登入時傳入6位數驗證碼，後續操作時傳入長期 Token

def get_all_messages():
    docs = db_firestore.collection("messages").stream()

    messages = []

    for doc in docs:
        item = doc.to_dict()
        item["id"] = doc.id
        messages.append(item)

    return messages


def get_stats(messages):
    return {
        "total": len(messages),
        "visible": sum(
            1 for m in messages
            if m["is_visible"]
        )
    }

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
    new_msg = {
        "timestamp":
            datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        "content": data.text.strip(),
        "is_visible": True,
        "is_pinned": False
    }

    db_firestore.collection(
        "messages"
    ).add(new_msg)

    return {"status": "success"}

# 公開牆讀取
@app.get("/api/messages/public")
def get_public_messages():
    messages = get_all_messages()
    public_list = [
        m for m in messages
        if m["is_visible"]
    ]
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
    messages = get_all_messages()
    return {
        "token": long_term_token,
        "stats": get_stats(messages),
        "messages": messages
    }

# 3. 檢查長期權杖是否有效 (免重新登入用)
@app.post("/api/admin/check-token")
def check_token(data: VerifyInput):
    email = data.email.strip().lower()
    # 只要傳過來的 token 符合規則，就直接放行，不卡5分鐘限制！
    if data.otp == f"TOKEN_VALID_{email}":
        messages = get_all_messages()
        return {
            "stats": get_stats(messages),
            "messages": messages
        }
    raise HTTPException(status_code=401, detail="通行證過期，請重新登入")

# 4. 後台操作：隱藏/顯示留言 (使用長期 Token 驗證)
@app.post("/api/admin/toggle/{msg_id}")
def toggle_message(msg_id: str, data: VerifyInput):

    email = data.email.strip().lower()

    if data.otp != f"TOKEN_VALID_{email}":
        raise HTTPException(
            status_code=401,
            detail="未授權的操作，請重新登入"
        )

    doc_ref = (
        db_firestore
        .collection("messages")
        .document(msg_id)
    )

    doc = doc_ref.get()

    if not doc.exists:
        raise HTTPException(
            status_code=404,
            detail="找不到該則留言"
        )

    current = doc.to_dict()

    doc_ref.update({
        "is_visible":
            not current["is_visible"]
    })

    messages = get_all_messages()

    return {
        "status": "success",
        "messages": messages,
        "stats": get_stats(messages)
    }