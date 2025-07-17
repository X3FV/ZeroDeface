from flask import Flask, render_template_string, request, redirect, url_for
from deface_scanner import DefacementScanner
import threading
import sys
import time
from io import StringIO

app = Flask(__name__)

scanner = None
output_log = []
output_lock = threading.Lock()

class Args:
    crawl = False
    admin = False
    upload = False
    deface = False
    all = False
    simulate = True
    verbose = True
    quiet = False
    threads = 5
    max_pages = 100
    brute = False
    report = None
    mirror = False
    interactive = False

args = Args()

TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZeroDeface Web Panel</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Orbitron:wght@500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0f172a;
            --text-color: #e2e8f0;
            --primary: #3b82f6;
            --primary-hover: #2563eb;
            --danger: #ef4444;
            --success: #10b981;
            --warning: #f59e0b;
            --card-bg: #1e293b;
            --border-color: #334155;
            --console-bg: #0a0a0a;
            --console-text: #00ff00;
        }

        .light-mode {
            --bg-color: #f8fafc;
            --text-color: #1e293b;
            --primary: #2563eb;
            --primary-hover: #1d4ed8;
            --card-bg: #ffffff;
            --border-color: #e2e8f0;
            --console-bg: #f1f5f9;
            --console-text: #1e40af;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            transition: background-color 0.3s, color 0.3s;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: 'JetBrains Mono', monospace;
            min-height: 100vh;
            padding: 2rem;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-color);
        }

        h1 {
            font-family: 'Orbitron', sans-serif;
            color: var(--primary);
            font-size: 2.5rem;
            text-shadow: 0 0 10px rgba(59, 130, 246, 0.3);
            letter-spacing: 1px;
        }

        .theme-toggle {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-color);
            padding: 0.5rem 1rem;
            border-radius: 50px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .theme-toggle:hover {
            background: var(--primary);
            color: white;
        }

        .control-panel {
            background: var(--card-bg);
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            border: 1px solid var(--border-color);
        }

        .url-input {
            display: flex;
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        input[type="text"] {
            flex: 1;
            padding: 0.75rem 1rem;
            background: var(--bg-color);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: var(--text-color);
            font-family: 'JetBrains Mono', monospace;
            font-size: 1rem;
        }

        input[type="text"]:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.3);
        }

        .button-group {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 0.75rem;
        }

        button {
            padding: 0.75rem;
            border: none;
            border-radius: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }

        button:hover {
            transform: translateY(-2px);
        }

        button:active {
            transform: translateY(0);
        }

        .btn-primary {
            background: var(--primary);
            color: white;
        }

        .btn-primary:hover {
            background: var(--primary-hover);
        }

        .btn-danger {
            background: var(--danger);
            color: white;
        }

        .btn-success {
            background: var(--success);
            color: white;
        }

        .btn-warning {
            background: var(--warning);
            color: white;
        }

        .console {
            background: var(--console-bg);
            border-radius: 10px;
            padding: 1.5rem;
            height: 500px;
            overflow-y: auto;
            font-family: 'JetBrains Mono', monospace;
            color: var(--console-text);
            border: 1px solid var(--border-color);
            box-shadow: inset 0 0 10px rgba(0, 0, 0, 0.5);
            line-height: 1.5;
            white-space: pre-wrap;
            word-break: break-word;
        }

        .console::-webkit-scrollbar {
            width: 8px;
        }

        .console::-webkit-scrollbar-track {
            background: var(--bg-color);
        }

        .console::-webkit-scrollbar-thumb {
            background: var(--primary);
            border-radius: 4px;
        }

        .status-bar {
            display: flex;
            justify-content: space-between;
            margin-top: 1rem;
            font-size: 0.9rem;
            color: var(--text-color);
            opacity: 0.8;
        }

        @keyframes pulse {
            0% { opacity: 0.6; }
            50% { opacity: 1; }
            100% { opacity: 0.6; }
        }

        .scanning {
            animation: pulse 1.5s infinite;
            color: var(--warning);
        }

        .log-error {
            color: #ef4444;
        }

        .log-success {
            color: #10b981;
        }

        .log-warning {
            color: #f59e0b;
        }

        .log-info {
            color: #3b82f6;
        }

        @media (max-width: 768px) {
            .button-group {
                grid-template-columns: 1fr;
            }
            
            .url-input {
                flex-direction: column;
            }
            
            h1 {
                font-size: 1.8rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>ZeroDeface</h1>
            <button class="theme-toggle" onclick="toggleTheme()">
                <span id="theme-icon">🌙</span> 
                <span id="theme-text">Dark Mode</span>
            </button>
        </header>

        <div class="control-panel">
            <form method="POST">
                <div class="url-input">
                    <input type="text" name="url" value="{{ url }}" placeholder="https://example.com" required>
                </div>
                <div class="button-group">
                    <button class="btn-primary" name="action" value="scan">
                        <span>🔍</span> Full Scan
                    </button>
                    <button class="btn-primary" name="action" value="admin">
                        <span>🛡️</span> Admin Panels
                    </button>
                    <button class="btn-primary" name="action" value="upload">
                        <span>📤</span> Upload Vulns
                    </button>
                    <button class="btn-warning" name="action" value="mirror">
                        <span>🪞</span> Mirror Attack
                    </button>
                    <button class="btn-danger" name="action" value="clear">
                        <span>🧹</span> Clear Log
                    </button>
                </div>
            </form>
        </div>

        <div class="console" id="console">{{ log }}</div>
        
        <div class="status-bar">
            <div id="status">Ready</div>
            <div id="timestamp">{{ timestamp }}</div>
        </div>
    </div>

    <script>
        // Theme toggle
        function toggleTheme() {
            document.body.classList.toggle('light-mode');
            const icon = document.getElementById('theme-icon');
            const text = document.getElementById('theme-text');
            
            if (document.body.classList.contains('light-mode')) {
                icon.textContent = '☀️';
                text.textContent = 'Light Mode';
            } else {
                icon.textContent = '🌙';
                text.textContent = 'Dark Mode';
            }
            
            localStorage.setItem('theme', document.body.classList.contains('light-mode') ? 'light' : 'dark');
        }
        
        // Check for saved theme preference
        if (localStorage.getItem('theme') === 'light') {
            document.body.classList.add('light-mode');
            document.getElementById('theme-icon').textContent = '☀️';
            document.getElementById('theme-text').textContent = 'Light Mode';
        }
        
        // Auto-scroll console
        const consoleElement = document.getElementById('console');
        consoleElement.scrollTop = consoleElement.scrollHeight;
        
        // Update timestamp
        function updateTimestamp() {
            const now = new Date();
            document.getElementById('timestamp').textContent = now.toLocaleString();
        }
        
        updateTimestamp();
        setInterval(updateTimestamp, 1000);
        
        // Update status when scanning
        function updateStatus(message, isScanning = false) {
            const statusElement = document.getElementById('status');
            statusElement.textContent = message;
            statusElement.className = isScanning ? 'scanning' : '';
        }

        // Auto-refresh console every 2 seconds
        function refreshConsole() {
            fetch(window.location.href)
                .then(response => response.text())
                .then(html => {
                    const parser = new DOMParser();
                    const doc = parser.parseFromString(html, 'text/html');
                    const newConsole = doc.getElementById('console').textContent;
                    if (newConsole !== consoleElement.textContent) {
                        consoleElement.textContent = newConsole;
                        consoleElement.scrollTop = consoleElement.scrollHeight;
                    }
                });
        }
        
        setInterval(refreshConsole, 2000);
    </script>
</body>
</html>
'''

def log(msg):
    """Thread-safe logging that only goes to web interface"""
    if not msg or not msg.strip():
        return
        
    with output_lock:
        output_log.append(msg.strip())
        if len(output_log) > 200:
            output_log.pop(0)

class WebOutput(StringIO):
    """Custom output stream that only logs to web interface"""
    def write(self, msg):
        if msg and msg.strip():
            log(msg)
            
    def flush(self):
        pass

# Create dedicated streams for scanner output
scanner_stdout = WebOutput()
scanner_stderr = WebOutput()

def run_task(target_func):
    """Run a task with redirected output"""
    def wrapper():
        # Save original streams
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        
        # Redirect for this thread
        sys.stdout = scanner_stdout
        sys.stderr = scanner_stderr
        
        try:
            target_func()
        finally:
            # Restore original streams
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            
    t = threading.Thread(target=wrapper)
    t.daemon = True
    t.start()

@app.route('/', methods=['GET', 'POST'])
def index():
    global scanner, args
    url = request.form.get('url') or ''

    if request.method == 'POST':
        action = request.form['action']

        if action == 'clear':
            with output_lock:
                output_log.clear()
            return redirect(url_for('index'))

        if not url:
            log("[-] No URL provided.")
        else:
            # Update args based on action
            args.all = (action == 'scan')
            args.admin = (action == 'admin')
            args.upload = (action == 'upload')
            args.mirror = (action == 'mirror')
            
            # Set the args in the deface_scanner module
            sys.modules['deface_scanner'].args = args
            
            scanner = DefacementScanner(url)
            log(f"[+] Target set to: {url}")

            if action == 'scan':
                run_task(lambda: scanner.scan_entire_site())
            elif action == 'admin':
                run_task(lambda: scanner.scan_admin_panels())
            elif action == 'upload':
                run_task(lambda: scanner.scan_upload_vulnerabilities())
            elif action == 'mirror':
                run_task(lambda: scanner.mirror_attack())

    # Get current log content safely
    with output_lock:
        current_log = '\n'.join(output_log[-100:])
    
    return render_template_string(TEMPLATE, 
                               log=current_log, 
                               url=url,
                               timestamp=time.strftime('%Y-%m-%d %H:%M:%S'))

if __name__ == '__main__':
    # Keep original stdout/stderr for Flask messages
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
