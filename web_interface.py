from flask import Flask, render_template_string, request, redirect, url_for
from deface_scanner import DefacementScanner
import threading
import sys

app = Flask(__name__)

scanner = None
output_log = []

# Initialize args with default values
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
<html>
<head>
    <title>ZeroDeface Web Panel</title>
    <style>
        body { background: #111; color: #eee; font-family: monospace; padding: 20px; }
        h1 { color: #f00; }
        button { padding: 10px; background: #222; color: #fff; border: 1px solid #555; margin: 5px; cursor:pointer; }
        form { margin-bottom: 15px; }
        pre { background: #000; padding: 10px; border: 1px solid #333; height: 400px; overflow-y: scroll; }
        input[type=text] { padding: 8px; background: #000; color: #fff; border: 1px solid #555; width: 300px; }
    </style>
</head>
<body>
    <h1>ZeroDeface Web Interface</h1>
    <form method="POST">
        <input type="text" name="url" value="{{ url }}" placeholder="Target URL" required>
        <button name="action" value="scan">Full Scan</button>
        <button name="action" value="admin">Scan Admin Panels</button>
        <button name="action" value="upload">Scan Upload Vulns</button>
        <button name="action" value="mirror">Mirror Attack</button>
        <button name="action" value="clear">Clear Log</button>
    </form>
    <pre>{{ log }}</pre>
</body>
</html>
'''

def log(msg):
    output_log.append(msg)
    print(msg)

def run_task(target_func):
    t = threading.Thread(target=target_func)
    t.daemon = True
    t.start()

@app.route('/', methods=['GET', 'POST'])
def index():
    global scanner, output_log, args
    url = request.form.get('url') or ''

    if request.method == 'POST':
        action = request.form['action']

        if action == 'clear':
            output_log = []
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

    return render_template_string(TEMPLATE, log='\n'.join(output_log[-100:]), url=url)

if __name__ == '__main__':
    app.run(debug=False)