<?php
// /admin/index.php -- admin console dashboard.
//
// Runs through the same CGI bridge as every other PHP page (script is
// copied to a scratch file and handed to the interpreter). The HTTP Basic
// gate in front of /admin/ is enforced by the C++ router before this
// script is ever reached. The PHP below fills in the interpreter-side
// info panel; the forms talk to the JSON admin API on this box.

function h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Console | DVWS</title>
  <link rel="icon" href="/favicon.ico" sizes="any">
  <link rel="stylesheet" href="/static/style.css">
  <style>
    .admin { display: grid; grid-template-columns: 220px 1fr; gap: 24px; align-items: start; }
    .side { background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 12px 0; box-shadow: 0 2px 6px rgba(0,0,0,.06); }
    .side h4 { margin: 0; padding: 8px 18px; font-size: 11px; text-transform: uppercase; letter-spacing: .5px; color: #888; }
    .side a { display: block; padding: 7px 18px; font-size: 14px; color: #333; border-left: 3px solid transparent; }
    .side a:hover { background: #f8f8f8; text-decoration: none; }
    .side a.here { border-left-color: #c0392b; background: #fafafa; font-weight: 600; }
    .panel { margin-bottom: 16px; }
    form.inline { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-top: 10px; }
    input[type=text], select, textarea {
      font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 13px;
      border: 1px solid #ccc; border-radius: 4px; padding: 7px 10px; background: #fff; color: #333;
    }
    button { background: #2c3e50; color: #fff; border: 0; border-radius: 4px; padding: 8px 16px; font-size: 13px; cursor: pointer; }
    button:hover { background: #34495e; }
    .note { font-size: 12px; color: #888; margin-top: 6px; }
    @media (max-width: 720px) { .admin { grid-template-columns: 1fr; } }
  </style>
</head>
<body>

  <header class="site">
    <div class="container">
      <a class="brand" href="/"><img src="/static/logo.svg" alt="" width="28" height="28">Damn Vulnerable Web Server</a>
      <nav>
        <a href="/">Home</a>
        <a href="/projects.html">Projects</a>
        <a href="/status">Status</a>
        <a href="/logs">Logs</a>
      </nav>
    </div>
  </header>

  <main class="container" style="padding-top: 24px">
    <div class="admin">

      <nav class="side">
        <h4>Console</h4>
        <a class="here" href="/admin/">Overview</a>
        <a href="/admin/system_status">System status</a>
        <a href="/admin/upload_file">Upload file</a>
        <a href="/admin/add_rule">CGI rules</a>
        <a href="/admin/logger_config">Logger config</a>
        <h4>Utilities</h4>
        <a href="/logs">Log viewer</a>
        <a href="/whoami">Whoami</a>
        <a href="/status">Status API</a>
        <h4>Public site</h4>
        <a href="/">Front page</a>
      </nav>

      <div>
        <section class="hero" style="padding: 8px 0 16px">
          <h1>Admin Console</h1>
          <p class="lead">Authenticated operations area. Everything on this
            page talks to the JSON admin API on this box.</p>
          <p><span class="badge red">HTTP Basic</span><span class="badge">DVWS/1.0</span></p>
        </section>

        <section class="panel">
          <div class="card">
            <h3>Interpreter panel</h3>
            <dl class="info">
              <dt>php_version</dt><dd><?php echo h(PHP_VERSION); ?></dd>
              <dt>sapi</dt><dd><?php echo h(PHP_SAPI); ?></dd>
              <dt>uname</dt><dd><?php echo h(php_uname('s') . ' ' . php_uname('r')); ?></dd>
              <dt>memory_limit</dt><dd><?php echo h(ini_get('memory_limit')); ?></dd>
              <dt>server_time</dt><dd><?php echo h(date('Y-m-d H:i:s T')); ?></dd>
              <dt>core_status</dt><dd><a href="/status">/status</a> (served by the C++ core)</dd>
            </dl>
          </div>
        </section>

        <section class="panel">
          <div class="card">
            <h3>Post a system status notice</h3>
            <p>Publishes an operator notice. Calls
              <code>GET /admin/system_status?status=...</code></p>
            <form class="inline" method="get" action="/admin/system_status">
              <input type="text" name="status" placeholder="status message" size="40" required>
              <button type="submit">Publish</button>
            </form>
            <p class="note">Returns JSON. Watch the server console while it processes.</p>
          </div>
        </section>

        <section class="panel">
          <div class="card">
            <h3>Upload a file</h3>
            <p>Streams a request body to <code>POST /admin/upload_file</code>.</p>
            <form class="inline" method="post" action="/admin/upload_file">
              <textarea name="payload" rows="3" cols="52" placeholder="file contents go here"></textarea>
              <button type="submit">Upload</button>
            </form>
            <p class="note">Plain body upload -- the endpoint reads whatever Content-Length announces.</p>
          </div>
        </section>

        <section class="panel">
          <div class="card">
            <h3>CGI rules engine</h3>
            <p>Register a dispatch rule under <code>/cgi-bin/</code>.
              Calls <code>GET /admin/add_rule?type=...&amp;path=...&amp;target=...</code></p>
            <form class="inline" method="get" action="/admin/add_rule">
              <select name="type">
                <option value="alias">alias</option>
                <option value="exec">exec</option>
              </select>
              <input type="text" name="path" placeholder="/cgi-bin/rule-path" size="24" required>
              <input type="text" name="target" placeholder="target" size="18" required>
              <button type="submit">Add rule</button>
            </form>
          </div>
        </section>

        <section class="panel">
          <div class="card">
            <h3>Request logger</h3>
            <p>Set or reset the access-log format. Calls
              <code>GET /admin/logger_config?action=...</code></p>
            <form class="inline" method="get" action="/admin/logger_config">
              <select name="action">
                <option value="set">set</option>
                <option value="reset">reset</option>
              </select>
              <input type="text" name="format" placeholder="log format" size="28">
              <button type="submit">Apply</button>
            </form>
            <p class="note">Then read the result in the <a href="/logs">log viewer</a>.</p>
          </div>
        </section>

      </div>
    </div>
  </main>

  <footer class="site">
    <div class="container">
      <p class="fingerprint">internal area -- if you can read this you already have the password &middot; powered by <code>DVWS/1.0</code></p>
    </div>
  </footer>

</body>
</html>
