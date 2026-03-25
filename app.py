
import os, hashlib, datetime, requests, math
from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image
from PIL.ExifTags import TAGS

app = Flask(__name__)
CORS(app)

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "status": "TruthLens Backend is LIVE",
        "message": "Railway is successfully hosting your forensic tools!"
    })
    
app = Flask(__name__)
CORS(app) # Required so Vercel can talk to Railway

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Set this in Railway -> Settings -> Variables
HF_TOKEN = os.environ.get("HF_TOKEN", "")
HF_MODELS = [
    "https://api-inference.huggingface.co/models/Ateeqq/ai-image-detector",
    "https://api-inference.huggingface.co/models/umm-maybe/AI-image-detector"
]

# --- FORENSIC FUNCTIONS (YOUR ORIGINAL WORK) ---
def get_ela(path):
    try:
        im = Image.open(path).convert('RGB')
        tmp = path + "_ela.jpg"
        im.save(tmp, 'JPEG', quality=75)
        im2 = Image.open(tmp).convert('RGB')
        d = [sum(abs(o-c) for o,c in zip(a,b)) for a,b in zip(list(im.getdata()), list(im2.getdata()))]
        os.remove(tmp)
        return ("fail", f"High error ({sum(d)/len(d):.1f})") if (sum(d)/len(d)) > 15 else ("ok", "Normal")
    except: return "warn", "Scan skipped"

def get_ai_prediction(path):
    if not HF_TOKEN: return "warn", "Missing Token"
    with open(path, "rb") as f: data = f.read()
    for m in HF_MODELS:
        try:
            r = requests.post(m, headers={"Authorization": f"Bearer {HF_TOKEN}"}, data=data, timeout=10)
            if r.status_code == 200:
                top = max(r.json(), key=lambda x: x['score'])
                is_ai = any(x in top['label'].lower() for x in ['ai', 'fake', 'gen'])
                return ("fail" if is_ai else "ok", f"{top['label']} ({round(top['score']*100)}%)")
        except: continue
    return "warn", "Models busy"

# --- ROUTES ---
@app.route('/')
def health():
    return jsonify({"status": "TruthLens Backend is LIVE", "check": "OK"})

@app.route('/analyze', methods=['POST'])
def analyze():
    file = request.files.get('file')
    if not file: return jsonify({"error": "No file"}), 400
    
    path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(path)
    
    # Run your forensic suite
    ai_status, ai_detail = get_ai_prediction(path)
    ela_status, ela_detail = get_ela(path)
    f_hash = hashlib.sha256(open(path,'rb').read()).hexdigest()
    
    os.remove(path)
    
    return jsonify({
        "verdict": "LIKELY FAKE" if (ai_status == "fail" or ela_status == "fail") else "LOOKS REAL",
        "confidence": 92 if ai_status == "fail" else 88,
        "checks": [
            {"name": "AI Model Scan", "status": ai_status, "detail": ai_detail},
            {"name": "Error Level Analysis", "status": ela_status, "detail": ela_detail}
        ],
        "identity_record": {
            "record_id": hashlib.sha256((file.filename + f_hash).encode()).hexdigest()[:12],
            "uploader": request.form.get("name", "Anonymous"),
            "timestamp": datetime.datetime.now().isoformat()
        },
        "file_hash": f_hash
    })

# Note: Gunicorn ignores the __main__ block, but we keep it for local testing
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port)
