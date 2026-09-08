/*
 * KQL Library — landing search filter + query-detail copy button.
 *
 * Loaded via `site-js` on the KQL Library pages. Runs zero code on pages
 * where the expected DOM nodes don't exist, so it's safe to keep site-wide
 * if we ever pull it up into _config.yml.
 */
(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', function () {
    wireLandingSearch();
    wireCopyButtons();
  });

  // ---------------------------------------------------------------------
  // Landing page: search box filters between the category grid and a
  // flat list of matching queries. Empty search restores the category grid.
  // ---------------------------------------------------------------------
  function wireLandingSearch() {
    var input = document.getElementById('kql-lib-search');
    var categories = document.getElementById('kql-lib-categories');
    var results = document.getElementById('kql-lib-results');
    var empty = document.getElementById('kql-lib-empty');
    var hint = document.getElementById('kql-lib-hint');

    if (!input || !categories || !results) {
      return;
    }

    var items = Array.prototype.slice.call(
      results.querySelectorAll('.kql-lib-result')
    );

    function apply() {
      var q = input.value.trim().toLowerCase();
      if (!q) {
        categories.hidden = false;
        results.hidden = true;
        if (empty) empty.hidden = true;
        if (hint) hint.hidden = false;
        return;
      }

      categories.hidden = true;
      results.hidden = false;
      if (hint) hint.hidden = true;

      var terms = q.split(/\s+/).filter(Boolean);
      var visibleCount = 0;

      items.forEach(function (li) {
        var hay = (
          (li.getAttribute('data-title') || '') + ' ' +
          (li.getAttribute('data-desc') || '') + ' ' +
          (li.getAttribute('data-cat') || '')
        );
        var match = terms.every(function (t) { return hay.indexOf(t) !== -1; });
        li.hidden = !match;
        if (match) visibleCount++;
      });

      if (empty) empty.hidden = visibleCount !== 0;
    }

    input.addEventListener('input', apply);
    // Enter key on an empty search shouldn't submit anything.
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { input.value = ''; apply(); }
    });

    apply();
  }

  // ---------------------------------------------------------------------
  // Query detail page: copy the rendered KQL to the clipboard.
  // The button's data-copy-target points at the wrapper <div> around the
  // Rouge-rendered <pre><code> block.
  // ---------------------------------------------------------------------
  function wireCopyButtons() {
    var buttons = document.querySelectorAll('.kql-lib-copy-btn[data-copy-target]');
    if (!buttons.length) return;

    Array.prototype.forEach.call(buttons, function (btn) {
      btn.addEventListener('click', function () {
        var target = document.getElementById(btn.getAttribute('data-copy-target'));
        if (!target) return;
        var code = target.querySelector('pre code, pre');
        if (!code) return;
        var text = code.innerText;

        var done = function () {
          var original = btn.innerHTML;
          btn.classList.add('copied');
          btn.innerHTML = '<i class="fas fa-check" aria-hidden="true"></i>&nbsp;Copied';
          setTimeout(function () {
            btn.classList.remove('copied');
            btn.innerHTML = original;
          }, 1600);
        };

        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done, function () {
            legacyCopy(text, done);
          });
        } else {
          legacyCopy(text, done);
        }
      });
    });
  }

  function legacyCopy(text, cb) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'absolute';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) { /* ignore */ }
    document.body.removeChild(ta);
    cb();
  }
})();
