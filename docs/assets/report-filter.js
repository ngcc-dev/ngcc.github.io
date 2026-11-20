/* Client-side filter for the security index (reports/index.html).
 *
 * Everything is read from the rendered tables: the severity badge class
 * (sev-*), the scope cell and the status badge class (status-*). Without
 * JavaScript the page is unchanged. The filter state is kept in the query
 * string so filtered views can be linked, e.g.
 *     reports/index.html?scope=design&min=high&status=confirmed
 */
(function () {
  "use strict";

  var SCOPES = ["implementation", "design", "side-channel", "evaluation"];
  var RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  var MINS = [["all", "All (incl. Info)"], ["low", "Low and above"], ["medium", "Medium and above"],
              ["high", "High and above"], ["critical", "Critical only"]];
  var each = function (list, fn) { Array.prototype.forEach.call(list, fn); };

  function classValue(el, prefix) {
    var m = el && el.className.match(new RegExp("(?:^|\\s)" + prefix + "([a-z-]+)"));
    return m ? m[1] : "";
  }

  function init() {
    var tables = document.querySelectorAll("table.reports");
    var totals = document.querySelector("p.report-totals");
    if (!tables.length || !totals) return;

    // Group rows by candidate: a row with td.report-id starts a group; its
    // rowspan cells (identifier, candidate, family) are moved to whichever
    // row of the group is first visible.
    var groups = [], findings = [], sections = [];
    each(tables, function (table) {
      var section = { table: table, groups: [], empty: null };
      var group = null;
      each(table.tBodies[0].rows, function (tr) {
        if (tr.querySelector("td.report-id")) {
          group = { lead: [], rows: [] };
          each(tr.cells, function (td) { if (td.hasAttribute("rowspan")) group.lead.push(td); });
          groups.push(group);
          section.groups.push(group);
        }
        if (!group) return;
        var sev = classValue(tr.querySelector("td.severity .sev"), "sev-");
        var row = { tr: tr, sev: sev, finding: sev in RANK,
                    scope: (tr.querySelector("td.scope") || {}).textContent || "",
                    status: classValue(tr.querySelector(".issue-status"), "status-"),
                    group: group };
        row.scope = row.scope.trim();
        group.rows.push(row);
        if (row.finding) findings.push(row);
      });
      sections.push(section);
    });
    if (!findings.length) return;

    var present = SCOPES.filter(function (s) {
      return findings.some(function (r) { return r.scope === s; });
    });

    // The filter bar.
    var form = document.createElement("form");
    form.className = "report-filter";
    form.setAttribute("role", "search");
    form.setAttribute("aria-label", "Filter findings");
    form.addEventListener("submit", function (e) { e.preventDefault(); });

    var fieldset = document.createElement("fieldset");
    var legend = document.createElement("legend");
    legend.textContent = "Scope";
    fieldset.appendChild(legend);
    var scopeBoxes = {}, scopeCounts = {};
    present.forEach(function (s) {
      var label = document.createElement("label");
      var box = document.createElement("input");
      box.type = "checkbox"; box.name = "scope"; box.value = s;
      var count = document.createElement("span");
      count.className = "count";
      label.appendChild(box);
      label.appendChild(document.createTextNode(" " + s + " "));
      label.appendChild(count);
      fieldset.appendChild(label);
      scopeBoxes[s] = box; scopeCounts[s] = count;
    });
    form.appendChild(fieldset);

    var minLabel = document.createElement("label");
    minLabel.appendChild(document.createTextNode("Minimum severity "));
    var minSelect = document.createElement("select");
    minSelect.name = "min";
    MINS.forEach(function (m) {
      var opt = document.createElement("option");
      opt.value = m[0]; opt.textContent = m[1];
      minSelect.appendChild(opt);
    });
    minLabel.appendChild(minSelect);
    form.appendChild(minLabel);

    var confLabel = document.createElement("label");
    var confBox = document.createElement("input");
    confBox.type = "checkbox"; confBox.name = "confirmed";
    confLabel.appendChild(confBox);
    confLabel.appendChild(document.createTextNode(" Confirmed only"));
    form.appendChild(confLabel);

    var reset = document.createElement("button");
    reset.type = "button";
    reset.textContent = "Reset";
    form.appendChild(reset);

    var summary = document.createElement("output");
    summary.className = "filter-count";
    summary.setAttribute("aria-live", "polite");
    form.appendChild(summary);

    totals.parentNode.insertBefore(form, totals.nextSibling);

    var isActive = function (r) { return r.status !== "withdrawn"; };
    var activeTotal = findings.filter(isActive).length;
    var reportTotal = groups.filter(function (g) {
      return g.rows.some(function (r) { return r.finding && isActive(r); });
    }).length;
    var plural = function (n, word) { return n + " " + word + (n === 1 ? "" : "s"); };

    function readState() {
      var p = new URLSearchParams(window.location.search);
      // Keep each known scope once, in table order, however the query lists it.
      var listed = p.has("scope") ? p.get("scope").split(",") : present;
      var scopes = present.filter(function (s) { return listed.indexOf(s) >= 0; });
      var min = p.get("min");
      return { scopes: scopes,
               min: MINS.some(function (m) { return m[0] === min; }) ? min : "all",
               confirmed: p.get("status") === "confirmed" };
    }

    function formState() {
      return { scopes: present.filter(function (s) { return scopeBoxes[s].checked; }),
               min: minSelect.value, confirmed: confBox.checked };
    }

    function isDefault(st) {
      return st.scopes.length === present.length && st.min === "all" && !st.confirmed;
    }

    function writeState(st) {
      var p = new URLSearchParams(window.location.search);
      if (st.scopes.length === present.length) p.delete("scope"); else p.set("scope", st.scopes.join(","));
      if (st.min === "all") p.delete("min"); else p.set("min", st.min);
      if (st.confirmed) p.set("status", "confirmed"); else p.delete("status");
      var q = p.toString().replace(/%2C/gi, ",");
      try {
        window.history.replaceState(null, "", window.location.pathname + (q ? "?" + q : "") + window.location.hash);
      } catch (e) { /* some browsers refuse on file: URLs */ }
    }

    function passes(row, st, ignoreScope) {
      if (!row.finding) return isDefault(st);
      if (!ignoreScope && st.scopes.indexOf(row.scope) < 0) return false;
      if (st.min !== "all" && RANK[row.sev] < RANK[st.min]) return false;
      return !(st.confirmed && row.status !== "confirmed");
    }

    function apply(st) {
      var shown = 0, withdrawn = 0, reports = 0;
      groups.forEach(function (g) {
        var visible = g.rows.filter(function (r) { return passes(r, st); });
        g.rows.forEach(function (r) { r.tr.hidden = visible.indexOf(r) < 0; });
        if (visible.length && g.lead.length) {
          var first = visible[0].tr;
          for (var i = g.lead.length - 1; i >= 0; i--) first.insertBefore(g.lead[i], first.firstChild);
          g.lead.forEach(function (td) { td.rowSpan = visible.length; });
        }
        var hits = visible.filter(function (r) { return r.finding && isActive(r); }).length;
        withdrawn += visible.filter(function (r) { return r.finding && !isActive(r); }).length;
        shown += hits;
        if (hits) reports += 1;
      });
      sections.forEach(function (sec) {
        var any = sec.groups.some(function (g) {
          return g.rows.some(function (r) { return !r.tr.hidden; });
        });
        if (!any && !sec.empty) {
          sec.empty = document.createElement("tr");
          sec.empty.className = "filter-empty";
          var td = document.createElement("td");
          td.colSpan = sec.table.tHead ? sec.table.tHead.rows[0].cells.length : 7;
          td.textContent = "No findings match the filter.";
          sec.empty.appendChild(td);
          sec.table.tBodies[0].appendChild(sec.empty);
        }
        if (sec.empty) sec.empty.hidden = any;
      });
      present.forEach(function (s) {
        var n = findings.filter(function (r) { return r.scope === s && passes(r, st, true); }).length;
        scopeCounts[s].textContent = "(" + n + ")";
      });
      summary.textContent = "Showing " + shown + " of " + activeTotal + " active findings in " +
        reports + " of " + plural(reportTotal, "report") +
        (withdrawn ? " (and " + plural(withdrawn, "withdrawn record") + ")" : "") + ".";
    }

    function show(st) {
      present.forEach(function (s) { scopeBoxes[s].checked = st.scopes.indexOf(s) >= 0; });
      minSelect.value = st.min;
      confBox.checked = st.confirmed;
      apply(st);
    }

    form.addEventListener("change", function () {
      var st = formState();
      apply(st);
      writeState(st);
    });
    reset.addEventListener("click", function () {
      var st = { scopes: present.slice(), min: "all", confirmed: false };
      show(st);
      writeState(st);
    });
    show(readState());
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
