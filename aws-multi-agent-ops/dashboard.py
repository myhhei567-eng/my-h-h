"""
Flask Web Dashboard
提供可视化巡检报告界面
"""
import json
from flask import Flask, render_template, jsonify
from core.orchestrator import Orchestrator


_report_cache = None


def create_app(config, resources=None):
    app = Flask(__name__, template_folder="templates")
    orchestrator = Orchestrator(config, resources)

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/api/scan", methods=["POST"])
    def run_scan():
        global _report_cache
        report = orchestrator.run()
        _report_cache = report.to_dict()
        return jsonify(_report_cache)

    @app.route("/api/report")
    def get_report():
        if _report_cache:
            return jsonify(_report_cache)
        return jsonify({"error": "尚未执行巡检，请先点击开始巡检"}), 404

    return app
