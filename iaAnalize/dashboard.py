from flask import Flask, request, render_template_string
from datetime import datetime

app = Flask(__name__)
alerts = []

TEMPLATE = """
<!doctype html>
<html>
<head>
    <title>IA Alert Dashboard</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        h1 { color: #c0392b; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            table-layout: fixed;
        }
        thead {
            background: #f4f4f4;
            display: table;
            width: 100%;
            table-layout: fixed;
        }
        tbody {
            display: block;
            max-height: 400px;  /* fixed height for scroll */
            overflow-y: auto;
            width: 100%;
            table-layout: fixed;
        }
        tr {
            display: table;
            width: 100%;
            table-layout: fixed;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            word-wrap: break-word;
            overflow-wrap: break-word;
            white-space: nowrap;
            text-overflow: ellipsis;
        }
        th {
            font-weight: bold;
        }
    </style>
</head>
<body>
    <h1>🚨 Anomaly Alerts Dashboard</h1>
    <p>Last refreshed at {{ now }}</p>
    <table>
        <thead>
            <tr>
                <th>Time</th>
                <th>Failed Logins</th>
                <th>Nmap Scans</th>
                <th>Unique IPs</th>
                <th>Message</th>
            </tr>
        </thead>
        <tbody id="alert-body">
            {% for alert in alerts %}
            <tr>
                <td>{{ alert['timestamp'] }}</td>
                <td>{{ alert['failed_logins'] }}</td>
                <td>{{ alert['nmap_scans'] }}</td>
                <td>{{ alert['unique_ips'] }}</td>
                <td title="{{ alert['alert'] }}">{{ alert['alert'] }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <script>
        // Scroll tbody to bottom so latest alerts show
        const tbody = document.getElementById('alert-body');
        tbody.scrollTop = tbody.scrollHeight;
    </script>
</body>
</html>
"""

@app.route("/")
def dashboard():
    return render_template_string(TEMPLATE, alerts=alerts[-50:], now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route("/alerts", methods=["POST"])
def receive_alert():
    data = request.get_json()
    if data:
        alerts.append(data)
        print(f"[RECEIVED] {data}")
        return {"status": "ok"}, 200
    return {"error": "Invalid payload"}, 400

if __name__ == "__main__":
    app.run(port=8080)
