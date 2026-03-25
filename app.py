import os
import hashlib
import datetime
import requests
import math
from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image
from PIL.ExifTags import TAGS

app = Flask(__name__)
# Allows Vercel to talk to Railway
CORS(app, resources={r"/*": {"origins": "*"}})

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Set this in Railway -> Settings -> Variables
HF_TOKEN = os.environ.get("HF_TOKEN", "")

HF_MODELS = [
    "https://api-inference.huggingface.co/models/Ateeqq/ai-image-detector",
    "https://api-inference.huggingface.co/models/umm-maybe/AI-image-detector",
    "https://api-inference.huggingface.co/models/microsoft/resnet-50",
]

# --- 1. IDENTITY & UTILITY FUNCTIONS ---
def hash_file(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def create_identity_record(uploader_name, filename, file_hash, reason):
    now = datetime.datetime.utcnow()
    timestamp = now.isoformat() + "Z"
    name_hash = hashlib.sha256(uploader_name.encode()).hexdigest()[:16]
    return {
        "timestamp": timestamp,
        "uploader": uploader_name,
        "name_hash": name_hash,
        "filename": filename,
        "file_hash": file_hash[:16] + "...",
        "reason": reason,
        "record_id": hashlib.sha256((timestamp + file_hash).encode()).hexdigest()[:12]
    }

# --- 2. FORENSIC CHECK FUNCTIONS ---
def check_file_type(ext):
    allowed = ["jpg", "jpeg", "png", "webp", "gif"]
    return {"name": "File type", "status": "ok" if ext in allowed else "warn", "detail": f".{ext.upper()}"}

def check_exif_metadata(filepath):
    try:
        img = Image.open(filepath)
        exif = img._getexif()
        return {"name": "EXIF metadata", "status": "ok" if exif else "fail", "detail": f"{len(exif)} fields" if exif else "No EXIF found"}
    except: return {"name": "EXIF metadata", "status": "warn", "detail": "Scan error"}

def check_ela(filepath):
    try:
        original = Image.open(filepath).convert("RGB")
        temp = filepath + "_tmp.jpg"
        original.save(temp, "JPEG", quality=75)
        recomp = Image.open(temp).convert("RGB")
        diffs = [sum(abs(o-c) for o,c in zip(a,b)) for a,b in zip(list(original.getdata()), list(recomp.getdata()))]
        avg = sum(diffs)/len(diffs)
        os.remove(temp)
        return {"name": "ELA Scan", "status": "fail" if avg > 15 else "ok", "detail": f"Score: {avg:.1f}"}
    except: return {"name": "ELA Scan", "status": "warn", "detail": "Skipped"}

def check_ai_model(filepath):
    if not HF_TOKEN: return {"name": "AI Model", "status": "warn", "detail": "No Token"}
    with open(filepath, "rb") as f: data = f.read()
    for url in HF_MODELS:
        try:
            res = requests.post(url, headers={"Authorization": f"Bearer {HF_TOKEN}"}, data=data, timeout=10)
            if res.status_code == 200:
                top = max(res.json(), key=lambda x: x['score'])
                is_ai = any(x in top['label'].lower() for x in ['ai', 'fake', 'gen'])
                return {"name": "AI Detector", "status": "fail" if is_ai and top['score'] > 0.6 else "ok", "detail": f"{top['label']} ({round(top['score']*100)}%)"}
        except: continue
    return {"name": "AI Detector", "status": "warn", "detail": "Models offline"}

# --- 3. THE VERDICT LOGIC (YOUR ORIGINAL SYSTEM) ---
def calculate_verdict(checks):
    ai_flag = any(c['name'] == "AI Detector" and c['status'] == "fail" for c in checks)
    exif_fail = any(c['name'] == "EXIF metadata" and c['status'] == "fail" for c in checks)
    ela_fail = any(c['name'] == "ELA Scan" and c['status'] == "fail" for c in checks)

    if ai_flag and (exif_fail or ela_fail): return {"label": "LIKELY FAKE", "confidence": 95}
    if ai_flag: return {"label": "SUSPICIOUS", "confidence": 85}
    if exif_fail and ela_fail: return {"label": "HIGHLY SUSPICIOUS", "confidence": 80}
    return {"label": "LOOKS REAL", "confidence": 88}

# --- 4. ROUTES ---
@app.route('/', methods=['GET'])
def home():
    return jsonify({"status": "TruthLens LIVE", "railway": "connected"})

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files: return jsonify({"error": "No file"}), 400
    file = request.files['file']
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    
    f_hash = hash_file(filepath)
    identity = create_identity_record(request.form.get("name", "Anonymous"), file.filename, f_hash, request.form.get("reason", "None"))
    
    ext = file.filename.rsplit(".", 1)[-1].lower()
    checks = [check_file_type(ext), check_exif_metadata(filepath), check_ela(filepath), check_ai_model(filepath)]
    
    res = calculate_verdict(checks)
    os.remove(filepath)
    
    return jsonify({
        "verdict": res["label"], "confidence": res["confidence"],
        "checks": checks, "identity_record": identity, "file_hash": f_hash
    })

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
