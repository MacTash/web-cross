#!/usr/bin/env python3
"""
Web-Cross Live Server
Flask-based web interface for the vulnerability scanner.
"""

import time
import threading
from flask import Flask, render_template_string, request, jsonify
from flask_cors import CORS

from modules import (
    SQLiScanner, XSSScanner, CSRFScanner,
    HTMLAttackScanner, InputFieldScanner, HeaderScanner
)
from modules.llm_analyzer import LLMAnalyzer, get_analyzer
from reporting import RiskCalculator, ReportGenerator

app = Flask(__name__)
CORS(app)

# Store scan results
scan_results = {}
scan_status = {}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web-Cross Scanner</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 100%);
            min-height: 100vh; color: #e0e0e0;
        }
        .container { max-width: 900px; margin: 0 auto; padding: 40px 20px; }
        
        header { text-align: center; margin-bottom: 40px; }
        h1 { 
            font-size: 3em; color: #00d4ff; margin-bottom: 10px;
            text-shadow: 0 0 20px rgba(0, 212, 255, 0.3);
        }
        .subtitle { color: #888; font-size: 1.1em; }
        
        .scan-form {
            background: rgba(255, 255, 255, 0.05);
            padding: 30px; border-radius: 16px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            margin-bottom: 30px;
        }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #aaa; }
        input[type="url"] {
            width: 100%; padding: 15px 20px; font-size: 1.1em;
            background: rgba(0, 0, 0, 0.3); border: 1px solid #333;
            border-radius: 8px; color: #fff;
        }
        input[type="url"]:focus {
            outline: none; border-color: #00d4ff;
            box-shadow: 0 0 10px rgba(0, 212, 255, 0.2);
        }
        
        .btn {
            padding: 15px 40px; font-size: 1.1em; font-weight: bold;
            background: linear-gradient(135deg, #00d4ff 0%, #0099cc 100%);
            border: none; border-radius: 8px; color: #fff;
            cursor: pointer; transition: all 0.3s;
        }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(0, 212, 255, 0.4); }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        
        .status {
            text-align: center; padding: 20px;
            background: rgba(0, 0, 0, 0.2); border-radius: 8px;
            margin-bottom: 30px; display: none;
        }
        .status.active { display: block; }
        .spinner {
            display: inline-block; width: 20px; height: 20px;
            border: 2px solid #333; border-top-color: #00d4ff;
            border-radius: 50%; animation: spin 1s linear infinite;
            margin-right: 10px; vertical-align: middle;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        
        .results { display: none; }
        .results.active { display: block; }
        
        .summary-card {
            background: rgba(0, 0, 0, 0.3); padding: 25px;
            border-radius: 12px; margin-bottom: 20px;
            border-left: 4px solid #00d4ff;
        }
        .risk-score {
            font-size: 3em; font-weight: bold; display: inline-block;
            padding: 10px 20px; border-radius: 8px;
        }
        .risk-critical { color: #ff4757; }
        .risk-high { color: #ff7f50; }
        .risk-medium { color: #ffd93d; }
        .risk-low { color: #4ade80; }
        
        .findings { margin-top: 30px; }
        .finding {
            background: rgba(0, 0, 0, 0.2); padding: 20px;
            border-radius: 8px; margin-bottom: 15px;
            border-left: 3px solid #666;
        }
        .finding-critical { border-left-color: #ff4757; }
        .finding-high { border-left-color: #ff7f50; }
        .finding-medium { border-left-color: #ffd93d; }
        .finding-low { border-left-color: #4ade80; }
        
        .finding-type { font-weight: bold; color: #fff; margin-bottom: 8px; }
        .finding-details { color: #aaa; font-size: 0.95em; }
        .finding-evidence { 
            background: rgba(0, 0, 0, 0.3); padding: 10px;
            margin-top: 10px; border-radius: 4px;
            font-family: monospace; font-size: 0.9em;
        }
        
        .download-btn {
            margin-top: 20px; padding: 12px 30px;
            background: #333; border: 1px solid #555;
            border-radius: 8px; color: #fff; cursor: pointer;
        }
        .download-btn:hover { background: #444; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Web-Cross</h1>
            <p class="subtitle">Professional Web Vulnerability Scanner</p>
        </header>
        
        <div class="scan-form">
            <div class="form-group">
                <label for="url">Target URL</label>
                <input type="url" id="url" placeholder="https://example.com" required>
            </div>
            <div class="form-group" style="margin-bottom: 15px;">
                <label style="display: inline; cursor: pointer;">
                    <input type="checkbox" id="useAI" style="margin-right: 8px;">
                    🧠 Enable AI Analysis (Ollama + llama3.2:3b)
                </label>
            </div>
            <button class="btn" id="scanBtn" onclick="startScan()">
                Start Scan
            </button>
        </div>
        
        <div class="status" id="status">
            <span class="spinner"></span>
            <span id="statusText">Initializing scan...</span>
        </div>
        
        <div class="results" id="results">
            <div class="summary-card">
                <h2 style="margin-bottom: 15px;">Scan Summary</h2>
                <div id="summary"></div>
            </div>
            
            <div class="findings" id="findings"></div>
            
            <button class="download-btn" onclick="downloadReport()">
                📥 Download Full Report
            </button>
        </div>
    </div>
    
    <script>
        let currentScanId = null;
        
        async function startScan() {
            const url = document.getElementById('url').value;
            if (!url) {
                alert('Please enter a URL');
                return;
            }
            
            document.getElementById('scanBtn').disabled = true;
            document.getElementById('status').classList.add('active');
            document.getElementById('results').classList.remove('active');
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, use_ai: document.getElementById('useAI').checked })
                });
                
                const data = await response.json();
                currentScanId = data.scan_id;
                
                pollStatus();
            } catch (error) {
                alert('Error starting scan: ' + error);
                document.getElementById('scanBtn').disabled = false;
                document.getElementById('status').classList.remove('active');
            }
        }
        
        async function pollStatus() {
            try {
                const response = await fetch(`/api/status/${currentScanId}`);
                const data = await response.json();
                
                document.getElementById('statusText').textContent = data.status;
                
                if (data.complete) {
                    showResults(data);
                } else {
                    setTimeout(pollStatus, 1000);
                }
            } catch (error) {
                console.error('Poll error:', error);
                setTimeout(pollStatus, 2000);
            }
        }
        
        function showResults(data) {
            document.getElementById('status').classList.remove('active');
            document.getElementById('results').classList.add('active');
            document.getElementById('scanBtn').disabled = false;
            
            const risk = data.risk;
            const riskClass = risk.score >= 9 ? 'critical' : 
                             risk.score >= 7 ? 'high' :
                             risk.score >= 4 ? 'medium' : 'low';
            
            document.getElementById('summary').innerHTML = `
                <div class="risk-score risk-${riskClass}">${risk.score}</div>
                <span style="margin-left: 15px; font-size: 1.3em;">${risk.severity}</span>
                <div style="margin-top: 15px;">
                    <span style="color: #ff4757;">Critical: ${risk.critical_count}</span> |
                    <span style="color: #ff7f50;">High: ${risk.high_count}</span> |
                    <span style="color: #ffd93d;">Medium: ${risk.medium_count}</span> |
                    <span style="color: #4ade80;">Low: ${risk.low_count}</span>
                </div>
            `;
            
            const findingsHtml = data.findings.map(f => {
                const fClass = f.risk_score >= 9 ? 'critical' :
                              f.risk_score >= 7 ? 'high' :
                              f.risk_score >= 4 ? 'medium' : 'low';
                return `
                    <div class="finding finding-${fClass}">
                        <div class="finding-type">${f.type}</div>
                        <div class="finding-details">
                            <div>Risk: ${f.risk_score} (${f.severity_label})</div>
                            ${f.url ? `<div>URL: ${f.url}</div>` : ''}
                            ${f.parameter ? `<div>Parameter: ${f.parameter}</div>` : ''}
                            <div class="finding-evidence">${f.evidence || 'N/A'}</div>
                        </div>
                    </div>
                `;
            }).join('');
            
            document.getElementById('findings').innerHTML = findingsHtml || '<p>No vulnerabilities found!</p>';
        }
        
        async function downloadReport() {
            if (!currentScanId) return;
            window.open(`/api/report/${currentScanId}`, '_blank');
        }
    </script>
</body>
</html>
"""


class AsyncScanner:
    """Run scan in background thread"""
    
    def __init__(self, scan_id: str, url: str, use_ai: bool = False):
        self.scan_id = scan_id
        self.url = url
        self.use_ai = use_ai
        self.findings = []
        
    def run(self):
        try:
            scan_status[self.scan_id] = "Checking security headers..."
            header_scanner = HeaderScanner()
            self.findings.extend(header_scanner.scan_url(self.url))
            
            scan_status[self.scan_id] = "Testing for SQL injection..."
            sqli_scanner = SQLiScanner()
            self.findings.extend(sqli_scanner.scan_url(self.url))
            
            scan_status[self.scan_id] = "Testing for XSS..."
            xss_scanner = XSSScanner()
            self.findings.extend(xss_scanner.scan_url(self.url))
            
            scan_status[self.scan_id] = "Testing for CSRF..."
            csrf_scanner = CSRFScanner()
            self.findings.extend(csrf_scanner.scan_url(self.url))
            
            scan_status[self.scan_id] = "Testing for HTML attacks..."
            html_scanner = HTMLAttackScanner()
            self.findings.extend(html_scanner.scan_url(self.url))
            
            scan_status[self.scan_id] = "Testing input fields..."
            input_scanner = InputFieldScanner()
            self.findings.extend(input_scanner.scan_url(self.url))
            
            # AI Analysis (if enabled)
            if self.use_ai:
                scan_status[self.scan_id] = "Running AI analysis..."
                try:
                    llm = get_analyzer()
                    if llm.is_available():
                        import requests
                        resp = requests.get(self.url, timeout=10, verify=False)
                        if resp:
                            result = llm.analyze_response(
                                resp.text,
                                url=self.url,
                                context={"headers": dict(resp.headers)}
                            )
                            for vuln in result.vulnerabilities:
                                self.findings.append({
                                    "type": f"AI_{vuln.get('type', 'UNKNOWN')}",
                                    "evidence": vuln.get('evidence', ''),
                                    "url": self.url,
                                    "risk_score": 7 if vuln.get('severity') == 'High' else 5,
                                })
                except Exception as e:
                    pass  # AI failure shouldn't stop the scan
            
            # Calculate risk
            risk = RiskCalculator.calculate_overall_score(self.findings)
            
            scan_results[self.scan_id] = {
                'url': self.url,
                'findings': self.findings,
                'risk': risk,
                'complete': True
            }
            scan_status[self.scan_id] = "Scan complete!"
            
        except Exception as e:
            scan_status[self.scan_id] = f"Error: {str(e)}"
            scan_results[self.scan_id] = {
                'url': self.url,
                'findings': [],
                'risk': {'score': 0, 'severity': 'ERROR'},
                'complete': True,
                'error': str(e)
            }


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    url = data.get('url')
    use_ai = data.get('use_ai', False)
    
    if not url:
        return jsonify({'error': 'URL required'}), 400
    
    scan_id = f"scan_{int(time.time() * 1000)}"
    scan_status[scan_id] = "Initializing..."
    
    scanner = AsyncScanner(scan_id, url, use_ai)
    thread = threading.Thread(target=scanner.run)
    thread.start()
    
    return jsonify({'scan_id': scan_id})


@app.route('/api/status/<scan_id>')
def get_status(scan_id):
    if scan_id in scan_results:
        result = scan_results[scan_id]
        return jsonify({
            'status': scan_status.get(scan_id, 'Unknown'),
            'complete': result.get('complete', False),
            'findings': result.get('findings', []),
            'risk': result.get('risk', {})
        })
    
    return jsonify({
        'status': scan_status.get(scan_id, 'Unknown'),
        'complete': False
    })


@app.route('/api/report/<scan_id>')
def download_report(scan_id):
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    result = scan_results[scan_id]
    reporter = ReportGenerator(result['url'], result['findings'])
    html = reporter.generate_html()
    
    return html, 200, {'Content-Type': 'text/html'}


if __name__ == '__main__':
    print("Starting Web-Cross Live Server...")
    print("Open http://localhost:5000 in your browser")
    app.run(host='0.0.0.0', port=5000, debug=False)
