"""
Dashboard Module
------------------
Flask-based web interface that displays real-time alerts and lets the
network administrator start/stop monitoring sessions.

Routes:
    GET  /            -> renders the dashboard page
    GET  /alerts       -> returns alert log + summary counts as JSON
    POST /start        -> starts the monitoring session
    POST /stop         -> stops the monitoring session
    GET  /status       -> returns whether monitoring is currently active
"""

from flask import Flask, jsonify, render_template


class Dashboard:
    """
    Wraps a Flask application exposing the monitoring dashboard.

    Attributes:
        host (str): Host address to bind the Flask server to.
        port (int): Port to serve the dashboard on.
        alert_engine (AlertEngine): Reference used to read alert data.
        on_start_callback (callable): Called when admin clicks "Start Monitoring".
        on_stop_callback (callable): Called when admin clicks "Stop Monitoring".
        is_monitoring (bool): Tracks current session state for the UI.
    """

    def __init__(self, alert_engine, host: str = "0.0.0.0", port: int = 5000):
        self.host = host
        self.port = port
        self.alert_engine = alert_engine
        self.is_monitoring = False
        self.on_start_callback = None
        self.on_stop_callback = None

        self.app = Flask(
            __name__,
            template_folder="../templates",
            static_folder="../static"
        )
        self._register_routes()

    def set_start_callback(self, callback):
        """Registers the function to call when a session should start."""
        self.on_start_callback = callback

    def set_stop_callback(self, callback):
        """Registers the function to call when a session should stop."""
        self.on_stop_callback = callback

    def _register_routes(self):
        app = self.app

        @app.route("/")
        def index():
            return render_template("index.html")

        @app.route("/alerts")
        def alerts():
            log = self.alert_engine.get_alert_log(limit=50)
            return jsonify({
                "alerts": log,
                "total": self.alert_engine.get_alert_count(),
                "http_count": self.alert_engine.get_count_by_protocol("HTTP"),
                "ftp_count": self.alert_engine.get_count_by_protocol("FTP"),
                "telnet_count": self.alert_engine.get_count_by_protocol("Telnet"),
                "is_monitoring": self.is_monitoring,
            })

        @app.route("/status")
        def status():
            return jsonify({"is_monitoring": self.is_monitoring})

        @app.route("/start", methods=["POST"])
        def start():
            if not self.is_monitoring:
                self.is_monitoring = True
                if self.on_start_callback:
                    self.on_start_callback()
            return jsonify({"is_monitoring": self.is_monitoring})

        @app.route("/stop", methods=["POST"])
        def stop():
            if self.is_monitoring:
                self.is_monitoring = False
                if self.on_stop_callback:
                    self.on_stop_callback()
            return jsonify({"is_monitoring": self.is_monitoring})

    def start_dashboard(self):
        """Starts the Flask development server. This call blocks, so it
        should be run on its own thread when used alongside packet capture."""
        self.app.run(host=self.host, port=self.port, debug=False, use_reloader=False)
