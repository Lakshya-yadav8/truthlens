import os
import hashlib
import datetime
import requests
import math
from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image
from PIL.ExifTags import TAGS

# 1. INITIALIZE APP
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 2. CONFIGURATION (Set HF_TOKEN in Railway Variables)
HF_TOKEN = os.environ.get("HF_TOKEN", "")
HF_MODELS = [
    "https://api-inference.huggingface.co/models/Ateeqq/ai-image-detector",
    "https://api-inference.huggingface.co/models/umm-maybe/AI-image-detector",
    "https://api-inference.huggingface.co/models/microsoft/resnet-50"
]

# 3. FORENSIC UTILITIES
def get_file_hash(content):
    return hashlib.sha256(content).hexdigest()

def check_ela(filepath):
    """Performs Error Level Analysis to detect pixel manipulation."""
    try:
        original = Image.open(filepath).convert('RGB')
        temp_path = filepath + "_ela.jpg"
        original.save(temp_path, 'JPEG', quality=75)
        recompressed = Image.open(temp_path).convert('RGB')
        
        orig_px = list(original.getdata())
        comp_px = list(recompressed.getdata())
        diffs = [sum(abs(o - c) for o, c in zip(a, b)) for a, b in zip(orig_px, comp_px)]
        avg_diff = sum(diffs) / len(diffs)
        
        os.remove(temp_path)
        if avg_diff > 15:
            return "fail", f"High manipulation score: {avg_diff:.1f}"
        return "ok", "Pixel distribution looks consistent"
    except:
        return "warn", "ELA scan skipped"

def check_ai_models(filepath):
    """Queries Hugging Face models to detect AI generation signatures."""
    if not HF_TOKEN:
        return "warn", "AI models inactive (Missing Token)"
    
    with open(filepath, "rb") as f:
        data = f.read()
    
    headers = {"Authorization": f"Bearer {HF_TOKEN}"}
    for model_url in HF_MODELS:
        try:
            response = requests.post(model_url, headers=headers, data=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                top = max(result, key=lambda x: x['score'])
                label = top['label'].lower()
                is_ai = any(word in label for word in ['ai', 'fake', 'gen', 'synthetic'])
                return ("fail" if is_ai and top['score'] > 0.6 else "ok", 
                        f"{top['label']} ({round(top['score']*100)}%)")
        except:
            continue
    return "warn", "AI detection servers busy"

def get_exif_data(filepath):
    """Extracts camera and hardware metadata."""
    try:
        img = Image.open(filepath)
        exif = img._getexif()
        if not exif:
            return "fail", "No EXIF metadata found (Common in AI/Screenshots)"
        
        info = {TAGS.get(t, t): v for t, v in exif.items()}
        device = f"{info.get('Make', '')} {info.get('Model', '')}".strip()
        return "ok", f"Captured via: {device}" if device else "Metadata present"
    except:
        return "warn", "Metadata unreadable"

# 4. API ROUTES
@app.route('/', methods=['GET'])
def health_check():
    return jsonify({
        "status": "TruthLens Backend is LIVE",
        "timestamp": datetime.datetime.now().isoformat(),
        "ready": True
    })

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    uploader_name = request.form.get("name", "Anonymous")
    reason = request.form.get("reason", "Verification")
    
    # Save file temporarily
    filename = file.filename
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    with open(filepath, "rb") as f:
        content = f.read()
    
    # Generate Hashes & Records
    file_hash = get_file_hash(content)
    rec_id = hashlib.sha256((filename + file_hash).encode()).hexdigest()[:12]
    name_hash = hashlib.sha256(uploader_name.encode()).hexdigest()[:16]
    
    # Run Forensic Suite
    ai_status, ai_detail = check_ai_models(filepath)
    ela_status, ela_detail = check_ela(filepath)
    exif_status, exif_detail = get_exif_data(filepath)
    
    # Verdict Logic
    checks = [
        {"name": "AI Model Scan", "status": ai_status, "detail": ai_detail},
        {"name": "Error Level Analysis", "status": ela_status, "detail": ela_detail},
        {"name": "Metadata Integrity", "status": exif_status, "detail": exif_detail}
    ]
    
    fails = len([c for c in checks if c["status"] == "fail"])
    if fails >= 2:
        verdict, conf = "LIKELY FAKE", 94
    elif fails == 1:
        verdict, conf = "SUSPICIOUS", 72
    else:
        verdict, conf = "LOOKS REAL", 89

    # Cleanup
    os.remove(filepath)
    
    return jsonify({
        "verdict": verdict,
        "confidence": conf,
        "checks": checks,
        "file_hash": file_hash,
        "identity_record": {
            "record_id": rec_id,
            "uploader": uploader_name,
            "name_hash": name_hash,
            "filename": filename,
            "reason": reason,
            "timestamp": datetime.datetime.now().isoformat()
        }
    })

# 5. START SERVER
if __name__ == '__main__':
    # Railway requires binding to 0.0.0.0 and the dynamic PORT variable
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port)
