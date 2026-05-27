import os
import io
import time
import base64
import socket
import requests

from datetime import datetime, timedelta

from fastapi import FastAPI, Request, Form, Response, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from passlib.context import CryptContext
from sqlalchemy.orm import Session

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

from dotenv import load_dotenv

from database import Base, engine, SessionLocal
import models
from models import User, Scan, Payment

from auth import create_token, verify_token
from scanner import scan_site

# =========================================================
# LOAD ENV VARIABLES
# =========================================================
load_dotenv()

MPESA_KEY = os.getenv("MPESA_CONSUMER_KEY", "").strip()
MPESA_SECRET = os.getenv("MPESA_CONSUMER_SECRET", "").strip()
MPESA_SHORTCODE = os.getenv("MPESA_SHORTCODE", "174379").strip()
MPESA_PASSKEY = os.getenv("MPESA_PASSKEY", "").strip()

# USE NGROK URL
# Example:
# https://abcd-1234.ngrok-free.app
BASE_URL = os.getenv("BASE_URL", "").strip()

# =========================================================
# FASTAPI APP
# =========================================================
app = FastAPI(title="Sentinel Enterprise")

app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

Base.metadata.create_all(bind=engine)

pwd = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

# =========================================================
# RATE LIMIT
# =========================================================
rate_limits = {}

def apply_rate_limit(ip_address: str):

    now = datetime.now()

    if ip_address not in rate_limits:
        rate_limits[ip_address] = []

    rate_limits[ip_address] = [
        t for t in rate_limits[ip_address]
        if now - t < timedelta(seconds=10)
    ]

    if len(rate_limits[ip_address]) >= 5:

        raise HTTPException(
            status_code=429,
            detail="Too many requests."
        )

    rate_limits[ip_address].append(now)

# =========================================================
# GET CURRENT USER
# =========================================================
def get_user(request: Request):

    token = request.cookies.get("token")

    if not token:
        return None

    data = verify_token(token)

    if not data:
        return None

    return data["email"]

# =========================================================
# NETWORK TEST
# =========================================================
@app.get("/test-network")
def test_network():

    try:

        ip = socket.gethostbyname(
            "sandbox.safaricom.co.ke"
        )

        return {
            "success": True,
            "resolved_ip": ip
        }

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }

# =========================================================
# GET MPESA ACCESS TOKEN
# =========================================================
def get_mpesa_token():

    url = (
        "https://sandbox.safaricom.co.ke/"
        "oauth/v1/generate?grant_type=client_credentials"
    )

    print("\n===================================")
    print("TOKEN URL:", url)
    print("===================================\n")

    auth = f"{MPESA_KEY}:{MPESA_SECRET}"

    encoded = base64.b64encode(
        auth.encode()
    ).decode()

    headers = {
        "Authorization": f"Basic {encoded}"
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=20
        )

        print("\n===================================")
        print("STATUS CODE:", response.status_code)
        print("RESPONSE:", response.text)
        print("===================================\n")

        if response.status_code == 200:

            data = response.json()

            access_token = data.get("access_token")

            print("ACCESS TOKEN GENERATED")

            return access_token, None

        return None, response.text

    except Exception as e:

        print("\n===================================")
        print("TOKEN ERROR:", str(e))
        print("===================================\n")

        return None, str(e)

# =========================================================
# CHECK PAYMENT STATUS
# =========================================================
def check_payment_status(checkout_id):

    token, err = get_mpesa_token()

    if not token:
        return False

    timestamp = datetime.now().strftime(
        "%Y%m%d%H%M%S"
    )

    password = base64.b64encode(
        f"{MPESA_SHORTCODE}{MPESA_PASSKEY}{timestamp}".encode()
    ).decode()

    url = (
        "https://sandbox.safaricom.co.ke/"
        "mpesa/stkpushquery/v1/query"
    )

    payload = {
        "BusinessShortCode": MPESA_SHORTCODE,
        "Password": password,
        "Timestamp": timestamp,
        "CheckoutRequestID": checkout_id
    }

    headers = {
        "Authorization": f"Bearer {token}"
    }

    try:

        response = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=20
        )

        data = response.json()

        print("\n========== QUERY RESPONSE ==========")
        print(data)
        print("====================================\n")

        return data.get("ResultCode") == "0"

    except Exception as e:

        print("QUERY ERROR:", e)

        return False

# =========================================================
# HOME
# =========================================================
@app.get("/")
def home(request: Request):

    user = get_user(request)

    db = SessionLocal()

    history = []

    if user:

        history = (
            db.query(Scan)
            .filter_by(email=user)
            .order_by(Scan.id.desc())
            .limit(5)
            .all()
        )

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "USER": user,
            "HISTORY": history
        }
    )

# =========================================================
# SIGNUP
# =========================================================
@app.post("/signup")
def signup(username: str = Form(...), email: str = Form(...), password: str = Form(...)):

    existing_user = db.query(User).filter(User.email == email).first()

    if existing_user:
        return RedirectResponse("/?err=userexists", status_code=303)

    # bcrypt limit fix
    password = password[:72]

    hashed_password = pwd.hash(password)

    new_user = User(
        username=username,
        email=email,
        password=hashed_password
    )

    db.add(new_user)
    db.commit()

    return RedirectResponse("/?msg=accountcreated", status_code=303)

# =========================================================
# LOGIN
# =========================================================
@app.post("/login")
def login(
    email: str = Form(...),
    password: str = Form(...)
):

    db = SessionLocal()

    user = (
        db.query(User)
        .filter_by(email=email)
        .first()
    )

    if not user:

        return RedirectResponse(
            "/?err=invalid",
            status_code=303
        )

    if not pwd.verify(
        password,
        user.password
    ):

        return RedirectResponse(
            "/?err=invalid",
            status_code=303
        )

    token = create_token({
        "email": email
    })

    response = RedirectResponse(
        "/",
        status_code=303
    )

    response.set_cookie(
        key="token",
        value=token,
        httponly=True,
        max_age=604800
    )

    return response

# =========================================================
# LOGOUT
# =========================================================
@app.get("/logout")
def logout():

    response = RedirectResponse(
        "/",
        status_code=303
    )

    response.delete_cookie("token")

    return response

# =========================================================
# WEBSITE SCANNER
# =========================================================
@app.get("/scan")
def scan(url: str, request: Request):

    apply_rate_limit(
        request.client.host
    )

    email = get_user(request)

    if not email:
        return {"error": "Login required"}

    db = SessionLocal()

    user = (
        db.query(User)
        .filter_by(email=email)
        .first()
    )

    if not user:
        return {"error": "User missing"}

    result = scan_site(url)

    user.scans_used += 1

    db.add(
        Scan(
            email=email,
            url=url,
            score=result["score"],
            details=result
        )
    )

    db.commit()

    return result

# =========================================================
# MPESA PAYMENT
# =========================================================
@app.post("/pay-mpesa")
async def pay_mpesa(
    phone: str = Form(...),
    url: str = Form(...),
    score: int = Form(...)
):

    phone = (
        phone.strip()
        .replace("+", "")
        .replace(" ", "")
    )

    if phone.startswith("07"):
        phone = "2547" + phone[2:]

    elif phone.startswith("01"):
        phone = "2541" + phone[2:]

    token, error = get_mpesa_token()

    if not token:

        return HTMLResponse(f"""
        <body style="background:black;color:white;text-align:center;padding:100px;font-family:sans-serif;">

            <h1 style="color:red;">
                Authentication Failed
            </h1>

            <pre>{error}</pre>

        </body>
        """)

    timestamp = datetime.now().strftime(
        "%Y%m%d%H%M%S"
    )

    password = base64.b64encode(
        f"{MPESA_SHORTCODE}{MPESA_PASSKEY}{timestamp}".encode()
    ).decode()

    stk_url = (
        "https://sandbox.safaricom.co.ke/"
        "mpesa/stkpush/v1/processrequest"
    )

    payload = {
        "BusinessShortCode": MPESA_SHORTCODE,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": 1,
        "PartyA": phone,
        "PartyB": MPESA_SHORTCODE,
        "PhoneNumber": phone,
        "CallBackURL": f"{BASE_URL}/callback",
        "AccountReference": "Sentinel",
        "TransactionDesc": "Security Scan"
    }

    headers = {
        "Authorization": f"Bearer {token}"
    }

    try:

        response = requests.post(
            stk_url,
            json=payload,
            headers=headers,
            timeout=20
        )

        data = response.json()

        print("\n========== STK PUSH RESPONSE ==========")
        print(data)
        print("=======================================\n")

        if data.get("ResponseCode") == "0":

            checkout_id = data.get(
                "CheckoutRequestID"
            )

            return HTMLResponse(f"""
            <body style="background:#050505;color:white;text-align:center;padding-top:120px;font-family:sans-serif;">

                <div style="border:1px solid #22d3ee;padding:40px;border-radius:30px;display:inline-block;background:#0c0c0c;">

                    <h1 style="color:#22d3ee;">
                        STK PUSH SENT
                    </h1>

                    <p>
                        M-Pesa prompt sent to:
                    </p>

                    <h2>{phone}</h2>

                    <p>
                        Complete payment on your phone.
                    </p>

                    <p>
                        Verifying transaction...
                    </p>

                    <form id="verifyForm" action="/verify" method="POST">

                        <input type="hidden" name="cid" value="{checkout_id}">
                        <input type="hidden" name="url" value="{url}">
                        <input type="hidden" name="score" value="{score}">

                    </form>

                </div>

                <script>

                    setTimeout(() => {{

                        document.getElementById(
                            "verifyForm"
                        ).submit();

                    }}, 35000);

                </script>

            </body>
            """)

        return HTMLResponse(f"""
        <body style="background:black;color:white;text-align:center;padding:100px;">

            <h1 style="color:red;">
                STK PUSH FAILED
            </h1>

            <pre>{data}</pre>

        </body>
        """)

    except Exception as e:

        return HTMLResponse(f"""
        <body style="background:black;color:white;text-align:center;padding:100px;">

            <h1 style="color:red;">
                CONNECTION ERROR
            </h1>

            <pre>{str(e)}</pre>

        </body>
        """)

# =========================================================
# VERIFY PAYMENT
# =========================================================
@app.post("/verify")
def verify(
    cid: str = Form(...),
    url: str = Form(...),
    score: int = Form(...)
):

    for attempt in range(5):

        print(
            f"Checking payment attempt {attempt + 1}"
        )

        paid = check_payment_status(cid)

        if paid:

            print("PAYMENT CONFIRMED")

            return RedirectResponse(
                f"/pdf?url={url}&score={score}",
                status_code=303
            )

        time.sleep(5)

    return HTMLResponse("""
    <body style="background:black;color:white;text-align:center;padding:100px;font-family:sans-serif;">

        <h1 style="color:red;">
            Payment Not Confirmed
        </h1>

        <p>
            We could not verify your payment.
        </p>

        <a href="/" style="color:#22d3ee;">
            Go Back
        </a>

    </body>
    """)

# =========================================================
# MPESA CALLBACK
# =========================================================
@app.post("/callback")
async def mpesa_callback(request: Request):

    data = await request.json()

    print("\n========== CALLBACK RECEIVED ==========")
    print(data)
    print("=======================================\n")

    stk_callback = (
        data.get("Body", {})
        .get("stkCallback", {})
    )

    result_code = stk_callback.get(
        "ResultCode"
    )

    checkout_id = stk_callback.get(
        "CheckoutRequestID"
    )

    db = SessionLocal()

    if result_code == 0:

        callback_metadata = (
            stk_callback
            .get("CallbackMetadata", {})
            .get("Item", [])
        )

        amount = None
        mpesa_receipt = None
        phone_number = None

        for item in callback_metadata:

            if item.get("Name") == "Amount":
                amount = item.get("Value")

            elif item.get("Name") == "MpesaReceiptNumber":
                mpesa_receipt = item.get("Value")

            elif item.get("Name") == "PhoneNumber":
                phone_number = item.get("Value")

        print(
            f"SUCCESS: {mpesa_receipt}"
        )

        payment_record = (
            db.query(Payment)
            .filter_by(checkout_id=checkout_id)
            .first()
        )

        if payment_record:

            payment_record.status = "completed"

            user_record = (
                db.query(User)
                .filter_by(email=payment_record.email)
                .first()
            )

            if user_record:
                user_record.plan = "pro"

            db.commit()

    else:

        print(
            f"FAILED: ResultCode {result_code}"
        )

        payment_record = (
            db.query(Payment)
            .filter_by(checkout_id=checkout_id)
            .first()
        )

        if payment_record:

            payment_record.status = "failed"

            db.commit()

    db.close()

    return {
        "ResultCode": 0,
        "ResultDesc": "Accepted"
    }

# =========================================================
# PDF REPORT
# =========================================================
@app.get("/pdf")
def pdf(
    url: str,
    score: int = 80
):

    buffer = io.BytesIO()

    p = canvas.Canvas(
        buffer,
        pagesize=A4
    )

    p.setFont(
        "Helvetica-Bold",
        20
    )

    p.drawString(
        80,
        800,
        "SENTINEL SECURITY REPORT"
    )

    p.setFont(
        "Helvetica-Bold",
        12
    )

    p.drawString(
        80,
        760,
        f"Target Website: {url}"
    )

    p.drawString(
        80,
        730,
        f"Security Score: {score}%"
    )

    p.line(
        80,
        710,
        520,
        710
    )

    p.setFont(
        "Helvetica",
        11
    )

    p.drawString(
        80,
        670,
        "Security Recommendations:"
    )

    p.drawString(
        100,
        640,
        "- Add Content Security Policy"
    )

    p.drawString(
        100,
        620,
        "- Add Strict-Transport-Security"
    )

    p.drawString(
        100,
        600,
        "- Validate user inputs"
    )

    p.drawString(
        100,
        580,
        "- Prevent SQL Injection"
    )

    p.drawString(
        100,
        560,
        "- Use secure authentication"
    )

    p.showPage()

    p.save()

    buffer.seek(0)

    return Response(
        buffer.getvalue(),
        media_type="application/pdf",
        headers={
            "Content-Disposition":
            "attachment; filename=Sentinel_Report.pdf"
        }
    )
