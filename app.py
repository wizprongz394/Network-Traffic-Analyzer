from flask import Flask, render_template, request, jsonify, redirect
import os
import threading
from attack_scripts.dos_attack import start_attack, stop_attack, get_logs
from analysis import analyze_pcap

app = Flask(__name__)
UPLOAD_FOLDER = 'upload'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

attack_info = {
    "running": False,
    "thread": None,
    "ip": None,
    "port": None,
    "threads": None
}


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/bottlenecks", methods=["GET", "POST"])
def bottlenecks():
    if request.method == "POST":
        file = request.files.get("pcap_file")
        if file:
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], "http.pcap")
            file.save(file_path)
            results = analyze_pcap(file_path)

            traffic = {str(k): int(v) for k, v in dict(sorted(results["traffic_per_sec"].items())[:10]).items()}
            smooth = {str(k): int(v) for k, v in results["traffic_smoothed"].dropna().items()}
            top_talkers = {str(k): int(v) for k, v in results["top_talkers"].items()}
            protocols = {str(k): int(v) for k, v in results["protocol_counts"].items()}
            hints = [str(h) for h in results["hints"]]

            return render_template("bottlenecks.html",
                                   traffic=traffic,
                                   smooth=smooth,
                                   top_talkers=top_talkers,
                                   protocols=protocols,
                                   hints=hints)

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
    return jsonify(get_logs())


if __name__ == "__main__":
    print("✅ Flask app is starting on http://127.0.0.1:5000")
    app.run(debug=True)
