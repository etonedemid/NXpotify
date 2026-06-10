#!/usr/bin/env python3
import http.server, urllib.parse, webbrowser, requests, secrets, hashlib, base64

CLIENT_ID   = input("Paste your client_id: ").strip()
REDIRECT    = "http://127.0.0.1:8888/callback"
SCOPE       = "streaming user-read-private user-read-playback-state"

cv = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode()
cc = base64.urlsafe_b64encode(hashlib.sha256(cv.encode()).digest()).rstrip(b'=').decode()

url = (f"https://accounts.spotify.com/authorize?client_id={CLIENT_ID}"
       f"&response_type=code&redirect_uri={REDIRECT}&scope={SCOPE}"
       f"&code_challenge_method=S256&code_challenge={cc}")
webbrowser.open(url)

code = None
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global code
        code = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get('code',[None])[0]
        self.send_response(200); self.end_headers()
        self.wfile.write("OK — close this tab")
    def log_message(self, *a): pass

http.server.HTTPServer(('', 8888), H).handle_request()

r = requests.post("https://accounts.spotify.com/api/token", data={
    "grant_type":"authorization_code","code":code,
    "redirect_uri":REDIRECT,"client_id":CLIENT_ID,"code_verifier":cv
}).json()
print("\nrefresh_token:", r.get("refresh_token","ERROR: "+str(r)))
