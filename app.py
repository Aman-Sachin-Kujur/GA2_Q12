# /// script# dependencies = ["python-dotenv", "fastapi", "uvicorn", "itsdangerous", "httpx", "authlib"]# ///
import os
import json
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth

load_dotenv()
app = FastAPI()

# IMPORTANT: Replace with a unique secret key
app.add_middleware(SessionMiddleware, secret_key="your-long-random-session-secret")

oauth = OAuth()
oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# --- Endpoint 1: Login Handler and Home Page ---
@app.get("/")
async def application(request: Request):
    id_token = request.session.get("id_token")
    
    # 3. Authenticated User: Display welcome message
    if id_token:
        user_info = request.session.get("userinfo", {"email": "Staff"})
        return f"Welcome, {user_info['email']}. Token available at /id_token"
    
    # 2. Handle OAuth Callback: Exchanges 'code' for tokens
    if "code" in request.query_params:
        token = await oauth.google.authorize_access_token(request)
        
        # --- CRITICAL STEP: Store the raw id_token and userinfo ---
        request.session["id_token"] = token["id_token"]
        request.session["userinfo"] = token.get("userinfo")
        
        return RedirectResponse("/")
        
    # 1. Initiate Login: Redirects to Google
    return await oauth.google.authorize_redirect(request, request.url)


# --- Endpoint 2: Required Submission Endpoint ---
@app.get("/id_token")
async def get_id_token(request: Request):
    """Exposes the raw id_token stored in the session as JSON."""
    id_token = request.session.get("id_token")
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    
    if not id_token:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: No id_token found in session. Please log in first."
        )
    
    # Return the raw id_token string and the Client ID in the required JSON format
    return JSONResponse(
        content={
            "id_token": id_token,
            "client_id": client_id
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
