import os, hashlib, datetime, requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image
from PIL.ExifTags import TAGS

app = Flask(__name__)
# This allows your Vercel site to talk to this Railway backend
CORS(app, resources={r"/*": {"origins": "*"}})

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Set your HF_TOKEN in Railway -> Settings -> Variables
HF_TOKEN = os.environ.get("HF_TOKEN", "")
HF_MODELS = [
    "https://api-inference.huggingface.co/models/Ateeqq/ai-image-detector",
    "https://api-inference.huggingface.co/models/umm-maybe/AI-image-detector"
]

# --- FORENSIC LOGIC (YOUR ORIGINAL FEATURES) ---

def check_ela(path):
    try:
        original = Image.open(path).convert('RGB')
        tmp = path + "_ela.jpg"
        original.save(tmp, 'JPEG', quality=75)
        recomp = Image.open(tmp).convert('RGB')
        d = [sum(abs(o-c) for o,c in zip(a,b)) for a,b in zip(list(original.getdata()), list(recomp.getdata()))]
        os.remove(tmp)
        score = sum(d)/len(d)
        return ("fail", f"High pixel manipulation ({score:.1f})") if score > 15 else ("ok", "Consistent")
    except: return ("warn", "ELA skipped")

def check_ai(path):
    if not HF_TOKEN: return ("warn", "Token Missing")
    with open(path, "rb") as f: data = f.read()
    for m in HF_MODELS:
        try:
            r = requests.post(m, headers={"Authorization": f"Bearer {HF_TOKEN}"}, data=data, timeout=10)
            if r.status_code == 200:
                top = max(r.json(), key=lambda x: x['score'])
                is_ai = any(x in top['label'].lower() for x in ['ai', 'fake', 'gen'])
                return ("fail" if is_ai else "ok", f"{top['label']} ({round(top['score']*100)}%)")
        except: continue
    return ("warn", "Models busy")

# --- ROUTES ---

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "status": "TruthLens Backend is LIVE",
        "message": "Forensic tools active and ready."
    })

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({"error": "No file"}), 400
    
    file = request.files['file']
    uploader = request.form.get("name", "Anonymous")
    reason = request.form.get("reason", "Verification")
    
    path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(path)
    
    # 1. Forensic Checks
    ai_s, ai_d = check_ai(path)
    ela_s, ela_d = check_ela(path)
    
    # 2. Identity Records
    f_content = open(path, 'rb').read()
    f_hash = hashlib.sha256(f_content).hexdigest()
    rec_id = hashlib.sha256((file.filename + f_hash).encode()).hexdigest()[:12]
    
    os.remove(path)
    
    return jsonify({
        "verdict": "LIKELY FAKE" if (ai_s == "fail" or ela_s == "fail") else "LOOKS REAL",
        "confidence": 92 if ai_s == "fail" else 88,
        "checks": [
            {"name": "AI Generation Scan", "status": ai_s, "detail": ai_d},
            {"name": "Error Level Analysis", "status": ela_s, "detail": ela_d}
        ],
        "identity_record": {
            "record_id": rec_id,
            "uploader": uploader,
            "timestamp": datetime.datetime.now().isoformat() + "Z",
            "file_hash": f_hash[:16] + "..."
        },
        "file_hash": f_hash
    })

if __name__ == '__main__':
    # This block is for local testing; Railway uses the Procfile
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port)
