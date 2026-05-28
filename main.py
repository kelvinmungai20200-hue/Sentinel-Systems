import os
import io
import time
import base64
import socket
import requests

from datetime import datetime, timedelta

from fastapi import (
    FastAPI,
    Request,
    Form,
    Response,
    HTTPException
)

from fastapi.responses import (
    HTMLResponse,
    RedirectResponse
)

from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from passlib.context import CryptContext

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

from dotenv import load_dotenv

from database import Base, engine, SessionLocal
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
BASE_URL = os.getenv("BASE_URL", "").strip()

# =========================================================
# FASTAPI APP
# =========================================================
app = FastAPI(title="Sentinel Enterprise")

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)

templates = Jinja2Templates(directory="templates")

Base.metadata.create_all(bind=engine)

# =========================================================
# PASSWORD HASHING
# =========================================================
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

    return data.get("email")

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
# GET MPESA TOKEN
# =========================================================
def get_mpesa_token():

    url = (
        "https://sandbox.safaricom.co.ke/"
        "oauth/v1/generate?grant_type=client_credentials"
    )

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

        print("TOKEN STATUS:", response.status_code)
        print("TOKEN RESPONSE:", response.text)

        if response.status_code == 200:

            data = response.json()

            return data.get("access_token"), None

        return None, response.text

    except Exception as e:

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

        print("QUERY:", data)

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

    try:

        if user:

            history = (
                db.query(Scan)
                .filter_by(email=user)
                .order_by(Scan.id.desc())
                .limit(5)
                .all()
            )

    finally:
        db.close()

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
def signup(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):

    db = SessionLocal()

    try:

        existing_user = (
            db.query(User)
            .filter(User.email == email)
            .first()
        )

        if existing_user:

            return RedirectResponse(
                "/?err=userexists",
                status_code=303
            )

        # bcrypt safe limit
        safe_password = password[:72]

        hashed_password = pwd.hash(
            safe_password
        )

        new_user = User(
            username=username,
            email=email,
            password=hashed_password
        )

        db.add(new_user)
        db.commit()

        return RedirectResponse(
            "/?msg=accountcreated",
            status_code=303
        )

    finally:
        db.close()

# =========================================================
# LOGIN
# =========================================================
@app.post("/login")
def login(
    email: str = Form(...),
    password: str = Form(...)
):

    db = SessionLocal()

    try:

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

        safe_password = password[:72]

        if not pwd.verify(
            safe_password,
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

        # secure=False for localhost
        response.set_cookie(
            key="token",
            value=token,
            httponly=True,
            samesite="lax",
            secure=False,
            max_age=604800
        )

        return response

    finally:
        db.close()

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

    try:

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
                score=result.get("score", 0),
                details=result
            )
        )

        db.commit()

        return result

    finally:
        db.close()

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
        "Helvetica",
        12
    )

    p.drawString(
        80,
        760,
        f"Website: {url}"
    )

    p.drawString(
        80,
        730,
        f"Security Score: {score}%"
    )

    p.drawString(
        80,
        680,
        "Recommendations:"
    )

    p.drawString(
        100,
        650,
        "- Enable HTTPS"
    )

    p.drawString(
        100,
        630,
        "- Add Security Headers"
    )

    p.drawString(
        100,
        610,
        "- Prevent SQL Injection"
    )

    p.drawString(
        100,
        590,
        "- Validate Inputs"
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