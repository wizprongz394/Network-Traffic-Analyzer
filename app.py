from flask import Flask, render_template, request
import os
from analysis import analyze_pcap

app = Flask(__name__)

# Folder to store uploaded files
UPLOAD_FOLDER = 'upload'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/")
def home():
    return render_template("index.html")  # Home page with links to bottlenecks/attacks

@app.route("/bottlenecks", methods=["GET", "POST"])
def bottlenecks():
    if request.method == "POST":
        file = request.files.get("pcap_file")
        if file:
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], "http.pcap")
            file.save(file_path)

            # Analyze PCAP and extract results
            results = analyze_pcap(file_path)

        traffic = {str(k): int(v) for k, v in dict(sorted(results["traffic_per_sec"].items())[:10]).items()}
        smooth = {str(k): int(v) for k, v in results["traffic_smoothed"].dropna().items()}

        top_talkers = {str(k): int(v) for k, v in results["top_talkers"].items()}
        protocols = {str(k): int(v) for k, v in results["protocol_counts"].items()}
        hints = [str(h) for h in results["hints"]]

        print("Smooth for chart:", smooth)  # Debug log

        return render_template(
            "bottlenecks.html",
            traffic=traffic,
            top_talkers=top_talkers,
            protocols=protocols,
            smooth=smooth,
            hints=hints
        )

    # GET request: Show upload form
    return render_template("upload.html")

@app.route("/attacks")
def attacks():
    return render_template("attacks.html")

if __name__ == "__main__":
    print("✅ Flask app is starting...")
    app.run(debug=True)