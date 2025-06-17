from flask import Flask, render_template, request, jsonify, redirect, Blueprint, url_for
import os
import threading

# ========== Import Modules ==========
from attack_scripts.dos_attack import start_attack, stop_attack, get_logs as dos_logs
from attack_scripts import mitm
from attack_scripts.sql_injection_analysis import load_pcap, find_sqli_attempts
from analysis import analyze_pcap

# ========== Flask App Setup ==========
app = Flask(__name__)
UPLOAD_FOLDER = 'upload'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ========== DoS State ==========
attack_info = {
    "running": False,
    "thread": None,
    "ip": None,
    "port": None,
    "threads": None
}

# ========== ROUTES ========== 

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/bottlenecks", methods=["GET", "POST"])
def bottlenecks():
    if request.method == "POST":
        file = request.files.get("pcap_file")
        if file:
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
            file.save(file_path)

            results = analyze_pcap(file_path)

            return render_template(
                "bottlenecks.html",
                traffic={str(k): int(v) for k, v in dict(sorted(results["traffic_per_sec"].items())[:10]).items()},
                smooth={str(k): int(v) for k, v in results["traffic_smoothed"].dropna().items()},
                top_talkers={str(k): int(v) for k, v in results["top_talkers"].items()},
                protocols={str(k): int(v) for k, v in results["protocol_counts"].items()},
                hints=[str(h) for h in results["hints"]]
            )
    return render_template("upload.html")


@app.route("/attacks")
def attacks():
    return render_template("attack_options.html")


@app.route("/attacks/floods", methods=["GET", "POST"])
def floods():
    global attack_info

    if request.method == "POST":
        action = request.form.get("action")

        if action == "start" and not attack_info["running"]:
            ip = request.form.get("ip")
            port = int(request.form.get("port"))
            thread_count = int(request.form.get("threads"))

            def run_attack():
                start_attack(ip, port, thread_count)

            t = threading.Thread(target=run_attack, daemon=True)
            t.start()

            attack_info.update({
                "running": True,
                "thread": t,
                "ip": ip,
                "port": port,
                "threads": thread_count
            })

        elif action == "stop" and attack_info["running"]:
            stop_attack()
            attack_info.update({
                "running": False,
                "thread": None
            })

    return render_template("floods.html", info=attack_info)


@app.route("/attacks/floods/logs")
def floods_logs():
    return jsonify(dos_logs())

# ========== MITM Blueprint ==========
mitm_bp = Blueprint("mitm", __name__, template_folder="templates")

mitm_state = {
    "running": False,
    "config": {}
}

@mitm_bp.route("/attacks/mitm", methods=["GET", "POST"])
def mitm_panel():
    global mitm_state

    if request.method == "POST":
        action = request.form.get("action")
        if action == "start":
            config = {
                "target_ip": request.form.get("target_ip"),
                "target_mac": request.form.get("target_mac"),
                "gateway_ip": request.form.get("gateway_ip"),
                "gateway_mac": request.form.get("gateway_mac")
            }
            mitm.start_attack(**config)
            mitm_state.update({"running": True, "config": config})

        elif action == "stop":
            mitm.stop_attack()
            mitm_state.update({"running": False})

        return redirect(url_for("mitm.mitm_panel"))

    return render_template("mitm_panel.html", status=mitm_state["running"])


@mitm_bp.route("/attacks/mitm/logs")
def mitm_logs():
    return jsonify(mitm.get_logs())


app.register_blueprint(mitm_bp)

# ========== SQL Injection Analysis ==========

@app.route("/analysis/sqlinjection", methods=["GET", "POST"])
def sqli_analysis():
    findings = []

    if request.method == "POST":
        file = request.files.get("pcap_file")
        if file:
            path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
            file.save(path)

            packets = load_pcap(path)
            findings = find_sqli_attempts(packets)

    return render_template("sqli_analysis.html", findings=findings)
# ========== Launch App ==========

if __name__ == "__main__":
    print("✅ Flask app is starting on http://127.0.0.1:5000")
    app.run(debug=True)
