/* Client-side filter for the NIST On-Ramp security index (nist/on-ramp.html).
 *
 * Everything is read from the rendered table: the severity badge class
 * (sev-*), the layer cell (td.layer) and the finding's status badge class
 * (td.finding .issue-status -> status-*). Without JavaScript the page is
 * unchanged. The filter state is kept in the query string so filtered views
 * can be linked, e.g.
 *     nist/on-ramp.html?layer=design&min=medium&status=confirmed
 */
(function () {
  "use strict";

  var LAYERS = ["implementation", "design", "side-channel", "evaluation"];
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

    // Group rows by candidate: a row with td.candidate starts a group; its
    // rowspan cells (candidate, family, NIST files) are moved to whichever
    // row of the group is first visible.
    var groups = [], findings = [], sections = [];
    each(tables, function (table) {
      var section = { table: table, groups: [], empty: null };
      var group = null;
      each(table.tBodies[0].rows, function (tr) {
        if (tr.querySelector("td.candidate")) {
          group = { lead: [], rows: [] };
          each(tr.cells, function (td) { if (td.hasAttribute("rowspan")) group.lead.push(td); });
          groups.push(group);
          section.groups.push(group);
        }
        if (!group) return;
        var sev = classValue(tr.querySelector("td.severity .sev"), "sev-");
        var findingCell = tr.querySelector("td.finding");
        var row = { tr: tr, sev: sev, finding: sev in RANK,
                    layer: (tr.querySelector("td.layer") || {}).textContent || "",
                    status: classValue(findingCell && findingCell.querySelector(".issue-status"), "status-"),
                    group: group };
        row.layer = row.layer.trim();
        group.rows.push(row);
        if (row.finding) findings.push(row);
      });
      sections.push(section);
    });
    if (!findings.length) return;

    var present = LAYERS.filter(function (l) {
      return findings.some(function (r) { return r.layer === l; });
    });

    // The filter bar.
    var form = document.createElement("form");
    form.className = "report-filter";
    form.setAttribute("role", "search");
    form.setAttribute("aria-label", "Filter findings");
    form.addEventListener("submit", function (e) { e.preventDefault(); });

    var fieldset = document.createElement("fieldset");
    var legend = document.createElement("legend");
    legend.textContent = "Layer";
    fieldset.appendChild(legend);
    var layerBoxes = {}, layerCounts = {};
    present.forEach(function (l) {
      var label = document.createElement("label");
      var box = document.createElement("input");
      box.type = "checkbox"; box.name = "layer"; box.value = l;
      var count = document.createElement("span");
      count.className = "count";
      label.appendChild(box);
      label.appendChild(document.createTextNode(" " + l + " "));
      label.appendChild(count);
      fieldset.appendChild(label);
      layerBoxes[l] = box; layerCounts[l] = count;
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
    var candidateTotal = groups.filter(function (g) {
      return g.rows.some(function (r) { return r.finding && isActive(r); });
    }).length;
    var plural = function (n, word) { return n + " " + word + (n === 1 ? "" : "s"); };

    function readState() {
      var p = new URLSearchParams(window.location.search);
      // Keep each known layer once, in table order, however the query lists it.
      var listed = p.has("layer") ? p.get("layer").split(",") : present;
      var layers = present.filter(function (l) { return listed.indexOf(l) >= 0; });
      var min = p.get("min");
      return { layers: layers,
               min: MINS.some(function (m) { return m[0] === min; }) ? min : "all",
               confirmed: p.get("status") === "confirmed" };
    }

    function formState() {
      return { layers: present.filter(function (l) { return layerBoxes[l].checked; }),
               min: minSelect.value, confirmed: confBox.checked };
    }

    function isDefault(st) {
      return st.layers.length === present.length && st.min === "all" && !st.confirmed;
    }

    function writeState(st) {
      var p = new URLSearchParams(window.location.search);
      if (st.layers.length === present.length) p.delete("layer"); else p.set("layer", st.layers.join(","));
      if (st.min === "all") p.delete("min"); else p.set("min", st.min);
      if (st.confirmed) p.set("status", "confirmed"); else p.delete("status");
      var q = p.toString().replace(/%2C/gi, ",");
      try {
        window.history.replaceState(null, "", window.location.pathname + (q ? "?" + q : "") + window.location.hash);
      } catch (e) { /* some browsers refuse on file: URLs */ }
    }

    function passes(row, st, ignoreLayer) {
      if (!row.finding) return isDefault(st);
      if (!ignoreLayer && st.layers.indexOf(row.layer) < 0) return false;
      if (st.min !== "all" && RANK[row.sev] < RANK[st.min]) return false;
      return !(st.confirmed && row.status !== "confirmed");
    }

    function apply(st) {
      var shown = 0, withdrawn = 0, candidates = 0;
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
        if (hits) candidates += 1;
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
      present.forEach(function (l) {
        var n = findings.filter(function (r) { return r.layer === l && passes(r, st, true); }).length;
        layerCounts[l].textContent = "(" + n + ")";
      });
      summary.textContent = "Showing " + shown + " of " + activeTotal + " active findings across " +
        candidates + " of " + plural(candidateTotal, "candidate") +
        (withdrawn ? " (and " + plural(withdrawn, "withdrawn record") + ")" : "") + ".";
    }

    function show(st) {
      present.forEach(function (l) { layerBoxes[l].checked = st.layers.indexOf(l) >= 0; });
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
      var st = { layers: present.slice(), min: "all", confirmed: false };
      show(st);
      writeState(st);
    });
    show(readState());
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
