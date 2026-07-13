/* Honeypot Lab — docs site interactivity (vanilla JS, no build step) */
(function(){
  "use strict";

  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---------------------------------------------------------
     Data: the 17 traps (kept in sync with config.ini / README)
  --------------------------------------------------------- */
  var HONEYPOTS = [
    { icon:"🐚", name:"SSH / Telnet",        proto:"SSH, Telnet",              ports:"2222",              captures:"Attacker commands, brute-force attempts, malware downloads. Runs on the real Cowrie engine." },
    { icon:"🏭", name:"ICS / SCADA",         proto:"Modbus, S7, BACnet",       ports:"502, 102, 47808",   captures:"Industrial control system probes — the kind aimed at power grids and factory floors." },
    { icon:"🔑", name:"Credential Capture",  proto:"FTP, SMTP, POP3, HTTP, MySQL", ports:"21, 25, 110, 8080, 3306", captures:"Every username and password an attacker tries, verbatim." },
    { icon:"🌐", name:"Web Traps",           proto:"HTTP / HTTPS",             ports:"80, 8081, 8082",    captures:"WordPress scans, admin login attempts, REST API probing." },
    { icon:"🗄️", name:"Database Traps",      proto:"Elasticsearch, MongoDB",   ports:"9200, 27017",       captures:"NoSQL exploitation attempts and unauthenticated query probes." },
    { icon:"🦠", name:"Malware Capture",     proto:"HTTP, TFTP",               ports:"8888, 69",          captures:"Uploaded malware samples, webshell drops, exploit kit payloads — hashed on capture." },
    { icon:"🖥️", name:"RDP Trap",            proto:"RDP",                      ports:"3389",              captures:"RDP brute-force attempts and client fingerprint/info extraction." },
    { icon:"📁", name:"SMB Trap",            proto:"SMB / CIFS",               ports:"445",               captures:"EternalBlue and WannaCry-style exploitation, SMB share enumeration." },
    { icon:"🌐", name:"DNS Trap",            proto:"DNS",                      ports:"53",                captures:"DNS tunneling attempts and amplification-style query floods." },
    { icon:"📞", name:"SIP Trap",            proto:"SIP / VoIP",               ports:"5060",              captures:"SIP scanning, registration attempts, and call INVITE floods." },
    { icon:"🔴", name:"Redis Trap",          proto:"Redis",                    ports:"6379",              captures:"Unauthenticated Redis probes and key enumeration attempts." },
    { icon:"🖥️", name:"VNC Trap",            proto:"VNC / RFB",                ports:"5900",              captures:"VNC scanning and remote-desktop takeover attempts." },
    { icon:"📟", name:"Telnet Trap",         proto:"Telnet",                   ports:"23",                captures:"IoT and Mirai-style botnet scanning — the classic default-credential sweep." },
    { icon:"📦", name:"Memcached Trap",      proto:"Memcached",                ports:"11211",             captures:"Requests used for memcached DDoS amplification attacks." },
    { icon:"📡", name:"MQTT Trap",           proto:"MQTT",                     ports:"1883",              captures:"IoT protocol attacks against pub/sub message brokers." },
    { icon:"🌐", name:"SNMP Trap",           proto:"SNMP",                     ports:"161",                captures:"Network device scanning and community-string brute forcing." },
    { icon:"🕐", name:"NTP Trap",            proto:"NTP",                      ports:"123",               captures:"Requests used for NTP DDoS amplification attacks." }
  ];

  /* ---------------------------------------------------------
     Build the hive grid
  --------------------------------------------------------- */
  var hiveGrid = document.getElementById("hive-grid");
  var hiveDetail = document.getElementById("hiveDetail");

  function renderDetail(hp, idx){
    hiveDetail.innerHTML =
      '<span class="hd-icon">' + hp.icon + '</span>' +
      '<h3 class="hd-title">' + hp.name + '</h3>' +
      '<div class="hd-badges">' +
        '<span class="hd-badge">#' + String(idx+1).padStart(2,'0') + '</span>' +
        '<span class="hd-badge">' + hp.proto + '</span>' +
      '</div>' +
      '<div class="hd-row"><b>Port(s)</b><span>' + hp.ports + '</span></div>' +
      '<div class="hd-row"><b>Captures</b><span>' + hp.captures + '</span></div>';
  }

  HONEYPOTS.forEach(function(hp, idx){
    var cell = document.createElement("button");
    cell.className = "hex-cell";
    cell.setAttribute("role", "listitem");
    cell.setAttribute("aria-label", hp.name + ", port " + hp.ports);
    cell.innerHTML =
      '<span class="hex-num">' + String(idx+1).padStart(2,'0') + '</span>' +
      '<span class="hex-icon">' + hp.icon + '</span>' +
      '<span class="hex-name">' + hp.name + '</span>';
    cell.addEventListener("click", function(){
      document.querySelectorAll(".hex-cell.active").forEach(function(c){ c.classList.remove("active"); });
      cell.classList.add("active");
      renderDetail(hp, idx);
    });
    hiveGrid.appendChild(cell);
  });

  /* ---------------------------------------------------------
     Hero terminal — typewriter of the real start_all.py banner
  --------------------------------------------------------- */
  var termBody = document.getElementById("termBody");
  var headerLines = [
    "=================================================================",
    "  \uD83C\uDF6F  HONEYPOT LAB v2.0 \u2014 All 17 Honeypots + Features",
    "  Developed by JOJIN JOHN",
    "================================================================="
  ];
  var checkLines = [
    "  \u2705 \uD83D\uDC1A  Cowrie (SSH/Telnet)",
    "  \u2705 \uD83C\uDFED  ICS/SCADA (Modbus/S7/BACnet)",
    "  \u2705 \uD83D\uDD11  Credential Capture (FTP/SMTP/POP3/HTTP/MySQL)",
    "  \u2705 \uD83C\uDF10  Web Traps (WordPress/Admin/API)",
    "  \u2705 \uD83D\uDDC4\uFE0F  DB Traps (Elasticsearch/MongoDB)",
    "  \u2705 \uD83E\uDDA0  Malware Capture (HTTP/TFTP)",
    "  \u2705 \uD83D\uDCC1  SMB Trap (EternalBlue/WannaCry)",
    "  \u2705 \uD83D\uDCDF  Telnet Trap (IoT/Mirai)",
    "  \u2705 \uD83D\uDD34  Redis Trap",
    "  \u2705 \uD83D\uDD50  NTP Trap (DDoS amp)",
    "  \u2026 and 7 more, 17/17 running"
  ];
  var footerLines = [
    "",
    "  \u2705 17/17 honeypots running",
    "  \uD83D\uDCCA Dashboard: http://localhost:5000"
  ];

  function typeLine(text, cls, speed, done){
    var span = document.createElement("div");
    if(cls) span.className = cls;
    termBody.appendChild(span);
    if(reduceMotion){ span.textContent = text; done(); return; }
    var i = 0;
    (function step(){
      span.textContent = text.slice(0, i);
      i++;
      if(i <= text.length){ setTimeout(step, speed); }
      else { done(); }
    })();
  }

  function revealLine(text, cls){
    var span = document.createElement("div");
    if(cls) span.className = cls;
    span.textContent = text;
    termBody.appendChild(span);
  }

  function runTerminal(){
    termBody.innerHTML = "";
    var cursor = document.createElement("span");
    cursor.className = "term-cursor";

    var queue = headerLines.slice();
    function typeNext(){
      if(queue.length === 0){
        // fast reveal the checklist + footer, then park the cursor
        checkLines.forEach(function(l){ revealLine(l, "tline-ok"); });
        footerLines.forEach(function(l, i){ revealLine(l, i===0 ? "" : "tline-honey"); });
        termBody.lastChild.appendChild(cursor);
        return;
      }
      var line = queue.shift();
      typeLine(line, "tline-dim", reduceMotion ? 0 : 12, typeNext);
    }
    typeNext();
  }
  runTerminal();

  /* ---------------------------------------------------------
     Quick start tabs
  --------------------------------------------------------- */
  var QS = {
    windows: {
      title: "powershell",
      steps: [
        ["Open PowerShell", "Administrator only needed if you map a port below 1024."],
        ["Clone the lab", "git clone https://github.com/jojin1709/Honeypot.git &amp;&amp; cd Honeypot"],
        ["Create the venv", "python -m venv venv &amp;&amp; venv\\Scripts\\activate"],
        ["Install &amp; launch", "pip install -r requirements.txt &amp;&amp; python start_all.py"],
        ["Open the dashboard", "python dashboard.py \u2192 http://127.0.0.1:5000"]
      ],
      term:
        "PS D:\\> git clone https://github.com/jojin1709/Honeypot.git\n" +
        "PS D:\\> cd Honeypot\n" +
        "PS D:\\Honeypot> python -m venv venv\n" +
        "PS D:\\Honeypot> venv\\Scripts\\activate\n" +
        "(venv) PS D:\\Honeypot> pip install -r requirements.txt\n" +
        "(venv) PS D:\\Honeypot> python start_all.py\n" +
        "\u2705 17/17 honeypots running\n" +
        "(venv) PS D:\\Honeypot> python dashboard.py\n" +
        " * Running on http://127.0.0.1:5000"
    },
    linux: {
      title: "bash",
      steps: [
        ["Open a terminal", "sudo only needed if you map a port below 1024."],
        ["Clone the lab", "git clone https://github.com/jojin1709/Honeypot.git &amp;&amp; cd Honeypot"],
        ["Create the venv", "python3 -m venv venv &amp;&amp; source venv/bin/activate"],
        ["Install &amp; launch", "pip install -r requirements.txt &amp;&amp; python3 start_all.py"],
        ["Open the dashboard", "python3 dashboard.py \u2192 http://127.0.0.1:5000"]
      ],
      term:
        "$ git clone https://github.com/jojin1709/Honeypot.git\n" +
        "$ cd Honeypot\n" +
        "$ python3 -m venv venv\n" +
        "$ source venv/bin/activate\n" +
        "(venv) $ pip install -r requirements.txt\n" +
        "(venv) $ sudo python3 start_all.py\n" +
        "\u2705 17/17 honeypots running\n" +
        "(venv) $ python3 dashboard.py\n" +
        " * Running on http://127.0.0.1:5000"
    }
  };

  var qsSteps = document.getElementById("qsSteps");
  var qsTermBody = document.getElementById("qsTermBody");
  var qsTermTitle = document.getElementById("qsTermTitle");

  function renderQS(osKey){
    var data = QS[osKey];
    qsSteps.innerHTML = data.steps.map(function(s){
      return '<li><strong>' + s[0] + '</strong><span>' + s[1] + '</span></li>';
    }).join("");
    qsTermBody.textContent = data.term;
    qsTermTitle.textContent = data.title;
  }
  renderQS("windows");

  document.querySelectorAll(".tab").forEach(function(tab){
    tab.addEventListener("click", function(){
      document.querySelectorAll(".tab").forEach(function(t){ t.classList.remove("active"); });
      tab.classList.add("active");
      renderQS(tab.dataset.os);
    });
  });

  /* ---------------------------------------------------------
     FAQ accordion
  --------------------------------------------------------- */
  var FAQ = [
    ["Port already in use?", "Run <code>netstat -ano | findstr :2222</code> (Windows) or <code>sudo netstat -tlnp | grep 2222</code> (Linux) to find the conflicting process, then change the port in <code>config.ini</code>."],
    ["Permission denied on ports below 1024?", "Run PowerShell as Administrator, or use <code>sudo python3 start_all.py</code> on Linux. Simplest fix: keep the default high ports (2222, 8080, etc.) instead of the real privileged ones."],
    ["Cowrie (SSH honeypot) won't start on Windows?", "This is handled automatically as of the current release \u2014 <code>start_all.py</code> invokes <code>twistd</code> directly instead of Cowrie's own CLI, works around the Windows-incompatible <code>--umask</code> flag, and syncs Cowrie's config to the path it expects. If you still see it fail, check <code>logs/ssh/cowrie_stdout.log</code> for details."],
    ["stop_all.py shows an error for some honeypots?", "That's usually just <code>os.kill()</code> reporting <code>WinError 87</code> on some Windows/Python builds \u2014 the script's fallback <code>taskkill</code> sweep still stops the process cleanly. Run <code>python status.py</code> afterward to confirm everything's actually down."],
    ["Module not found?", "Activate the venv first, then <code>pip install -r requirements.txt</code>. Only Cowrie, Twisted, Flask, and Paramiko are required \u2014 no <code>conpot</code> or <code>heralding</code> needed."],
    ["Nothing shows up in the dashboard?", "Generate some test traffic with <code>python tools/test_scanner.py</code>, and confirm the honeypots are actually running with <code>python status.py</code>."],
    ["Dashboard won't start?", "Port 5000 might already be in use \u2014 check with <code>netstat -ano | findstr :5000</code> and close whatever's holding it, or edit <code>dashboard.py</code> to bind a different port."]
  ];

  var accordion = document.getElementById("accordion");
  FAQ.forEach(function(item){
    var wrap = document.createElement("div");
    wrap.className = "acc-item";
    wrap.innerHTML =
      '<button class="acc-q"><span>' + item[0] + '</span><span class="plus">+</span></button>' +
      '<div class="acc-a"><div class="acc-a-inner">' + item[1] + '</div></div>';
    accordion.appendChild(wrap);

    var btn = wrap.querySelector(".acc-q");
    var panel = wrap.querySelector(".acc-a");
    btn.addEventListener("click", function(){
      var isOpen = wrap.classList.contains("open");
      accordion.querySelectorAll(".acc-item.open").forEach(function(o){
        o.classList.remove("open");
        o.querySelector(".acc-a").style.maxHeight = null;
      });
      if(!isOpen){
        wrap.classList.add("open");
        panel.style.maxHeight = panel.scrollHeight + "px";
      }
    });
  });

  /* ---------------------------------------------------------
     Mobile nav toggle
  --------------------------------------------------------- */
  var navToggle = document.getElementById("navToggle");
  if(navToggle){
    navToggle.addEventListener("click", function(){
      var links = document.querySelector(".nav-links");
      var expanded = navToggle.getAttribute("aria-expanded") === "true";
      navToggle.setAttribute("aria-expanded", String(!expanded));
      links.style.display = expanded ? "none" : "flex";
    });
  }
})();
