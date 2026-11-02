# Installation and reset
Download the repository ZIP and extract it, or clone the repository. Install Node.js 24. Open a terminal in the directory containing server.js and run:

    node server.js

Visit http://127.0.0.1:8080 and choose Start a fresh seat. The server listens only on loopback. Keep the terminal open. If port 8080 is occupied, stop the other service or set the PORT environment variable to a free port and use that port in the browser.

Stop with Ctrl+C. Restart to invalidate every existing flag. No cleanup of persistent data is needed. Internet access is unnecessary once Node.js and the files are installed.
