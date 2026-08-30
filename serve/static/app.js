/* DVWS/1.0 site script -- small progressive enhancements, no dependencies.
 * The site is fully readable with JS disabled; this only adds polish.
 */
(function () {
  'use strict';

  // Mark the nav entry matching the current path.
  var here = window.location.pathname;
  var links = document.querySelectorAll('header.site nav a, footer.site nav a');
  for (var i = 0; i < links.length; i++) {
    var href = links[i].getAttribute('href');
    if (href === here || (href !== '/' && here.indexOf(href) === 0)) {
      links[i].setAttribute('aria-current', 'page');
    }
  }

  // Keep the copyright year current.
  var year = document.querySelector('[data-year]');
  if (year) year.textContent = String(new Date().getFullYear());

  // Live status chip on the landing page, fed by the /status endpoint.
  var chip = document.getElementById('status-chip');
  if (chip && window.fetch) {
    window.fetch('/status').then(function (r) { return r.json(); }).then(function (s) {
      var mins = Math.floor(s.uptime_seconds / 60);
      var up = mins >= 60 ? Math.floor(mins / 60) + 'h ' + (mins % 60) + 'm' : mins + 'm';
      chip.textContent = s.version + ' -- up ' + up + ', ' +
        s.requests_handled + ' requests served';
      chip.classList.add('red');
    }).catch(function () { /* status endpoint unreachable; chip stays quiet */ });
  }
})();
