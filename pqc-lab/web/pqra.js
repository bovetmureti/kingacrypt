/* PQRA scoring in the browser. Mirrors kclab/pqra/scoring.py:
 * eq. (1) S_d = mean of non-N/A indicator scores, eq. (2) R = weighted mean of S_d,
 * eq. (3) band cut-points from instrument.json, plus Mosca's inequality.
 * UMD so tests can load it under Node and the page can load it with <script>. */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.PQRA = factory();
})(typeof self !== "undefined" ? self : this, function () {
  function band(R, instrument) {
    R = Math.round(R * 1e9) / 1e9; // match Python round(R, 9)
    if (!(R >= 0 && R <= 3)) throw new RangeError("R outside [0, 3]: " + R);
    for (const b of instrument.bands) {
      const upperOk = b.max_inclusive ? R <= b.max : R < b.max;
      if (b.min <= R && upperOk) return b.label;
    }
    throw new Error("bands do not cover [0, 3]");
  }

  function score(assessment, instrument) {
    const raw = assessment.scores || {};
    const dims = instrument.dimensions.map(function (d) {
      const vals = [];
      let na = 0;
      const missing = [];
      for (const ind of d.indicators) {
        if (!(ind.id in raw) || raw[ind.id] === undefined || raw[ind.id] === "") { missing.push(ind.id); continue; }
        const v = raw[ind.id];
        if (v === null) { na++; continue; }
        if (![0, 1, 2, 3].includes(v)) throw new RangeError(ind.id + ": score " + v + " not in {0,1,2,3}");
        vals.push(v);
      }
      const S = vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : null;
      return { id: d.id, name: d.name, S: S, m: vals.length, na: na, missing: missing };
    });
    const weights = assessment.weights || Object.fromEntries(dims.map((d) => [d.id, 1]));
    let R = null, label = null;
    if (dims.every((d) => d.S !== null)) {
      let num = 0, den = 0;
      for (const d of dims) { num += d.S * weights[d.id]; den += weights[d.id]; }
      R = num / den;
      label = band(R, instrument);
    }
    const complete = dims.every((d) => d.S !== null && d.missing.length === 0);
    let mosca = null;
    const m = assessment.mosca;
    if (m && [m.shelf_life_years, m.migration_years, m.crqc_horizon_years].every((x) => typeof x === "number")) {
      const xy = m.shelf_life_years + m.migration_years;
      mosca = { x_plus_y: xy, z_horizon: m.crqc_horizon_years, exposed: xy > m.crqc_horizon_years,
                margin_years: m.crqc_horizon_years - xy };
    }
    return { dimensions: dims, R: R, band: label, complete: complete, mosca: mosca };
  }

  return { band: band, score: score };
});
