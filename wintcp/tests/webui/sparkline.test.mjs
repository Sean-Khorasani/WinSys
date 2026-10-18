// wintcp/tests/webui/sparkline.test.mjs
// SPDX-License-Identifier: Apache-2.0
//
// Pure-logic tests for the Web UI's chart geometry, run with Node's built-in
// test runner. No dependencies, no DOM.
//
//   node --test wintcp/tests/webui/
//
// The functions under test are exported from js/charts/sparkline.js SEPARATELY
// from its DOM work on purpose. Importing that module in Node would need a
// `document`; splitting the arithmetic out means the part that can silently draw
// a wrong chart is covered, and the part that merely appends nodes is not
// pretending to be.
//
// Skipped automatically when Node is absent - these are never required to build
// or run the product.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  downsample,
  polylineSegments,
} from "../../webui/js/charts/sparkline.js";

test("downsample returns a copy when the series already fits", () => {
  const input = [1, 2, 3];
  const out = downsample(input, 10);
  assert.deepEqual(out, [1, 2, 3]);
  assert.notEqual(out, input, "must not alias the caller's array");
});

test("downsample keeps the series length at or below the pixel budget", () => {
  const long = Array.from({ length: 1000 }, (_, i) => i);
  assert.equal(downsample(long, 120).length, 120);
  assert.equal(downsample(long, 1).length, 1);
});

test("downsample buckets by mean, so a spike is not the only point kept", () => {
  // A stride would sample every 4th point. Depending on where the spike lands
  // that can either miss it entirely or make it the entire line. A mean keeps
  // the bucket honest either way.
  const withSpike = [0, 0, 0, 0, 100, 0, 0, 0];
  const out = downsample(withSpike, 2);
  assert.equal(out.length, 2);
  assert.equal(out[1], 25, "the spike's bucket averages 100 with three zeros");
});

test("downsample counts nulls out of the bucket rather than averaging them as zero", () => {
  const out = downsample([10, null, null, null], 1);
  assert.equal(out[0], 10, "a null must not drag the mean toward zero");
});

test("downsample returns null for an all-null bucket", () => {
  assert.deepEqual(downsample([null, null, null, null], 2), [null, null]);
});

test("polylineSegments returns null when nothing was measured", () => {
  // "No data" must be distinguishable from "flat line at zero": one is a gap in
  // the evidence, the other is a measurement.
  assert.equal(polylineSegments([], 100, 30), null);
  assert.equal(polylineSegments([null, null], 100, 30), null);
  assert.equal(polylineSegments([NaN, NaN], 100, 30), null);
});

test("a gap breaks the line instead of interpolating across it", () => {
  const segments = polylineSegments([1, 2, null, 4, 5], 100, 30);
  assert.equal(segments.length, 2, "one contiguous run is one polyline");
});

test("a trailing or leading gap produces no empty segment", () => {
  assert.equal(polylineSegments([null, 1, 2], 100, 30).length, 1);
  assert.equal(polylineSegments([1, 2, null], 100, 30).length, 1);
  assert.equal(polylineSegments([null, 1, null, 2, null], 100, 30).length, 2);
});

test("a flat series still produces a line, rather than dividing by zero", () => {
  // Every sample identical: max === min. Without a band of its own the
  // y computation divides by zero and the line collapses onto an edge, which
  // reads as "off scale" rather than "steady".
  const segments = polylineSegments([5, 5, 5], 100, 30);
  assert.equal(segments.length, 1);
  const ys = segments[0].split(" ").map((p) => Number(p.split(",")[1]));
  assert.ok(ys.every((y) => Number.isFinite(y)), "no NaN or Infinity");
  assert.equal(new Set(ys).size, 1, "a flat series is a flat line");
});

test("a non-negative series is zero-baselined", () => {
  // CPU between 40 and 60 must not be drawn as a mountain range. With the
  // baseline clamped to zero the scale tops out at 60, so 40 sits a third of the
  // way up. Let the axis float to [40,60] instead and every wiggle is doubled.
  const segments = polylineSegments([40, 50, 60], 100, 30);
  const points = segments[0].split(" ");
  const ys = points.map((p) => Number(p.split(",")[1]));
  assert.equal(ys[ys.length - 1], 0, "the maximum touches the baseline");
  assert.ok(ys[0] > 0, "the minimum sits away from the baseline, not on it");
  assert.equal(ys[0], 10, "40 of a 0..60 scale is a third of the way up");
  // Guard the actual regression: a floating 40..60 axis would put 40 at y=30.
  assert.notEqual(ys[0], 30);
});

test("a series that goes negative is not zero-baselined", () => {
  // Delta charts are legitimately signed. min is negative here, so the zero
  // clamp must NOT apply: folding the axis to zero would pile the negative half
  // on top of the positive half and make a gain/loss chart lie.
  const segments = polylineSegments([-10, 0, 10], 100, 30);
  const ys = segments[0].split(" ").map((p) => Number(p.split(",")[1]));
  assert.deepEqual(ys, [30, 15, 0],
    "a symmetric signed series maps linearly, with zero at the midpoint");
});

test("a series that is entirely positive but never zero keeps its own floor", () => {
  // 40..60 must render as 40..60 on a 0..60 scale, not as a full-height line:
  // the clamp is "lower the floor to zero when zero is in range", not
  // "always stretch the data to fill the box".
  const ys = polylineSegments([40, 60], 100, 30)[0].split(" ")
    .map((p) => Number(p.split(",")[1]));
  assert.deepEqual(ys, [10, 0]);
});

test("the first point is at x=0 and the last at x=width", () => {
  const segments = polylineSegments([1, 2, 3, 4, 5], 100, 30);
  const points = segments[0].split(" ");
  assert.equal(Number(points[0].split(",")[0]), 0);
  assert.equal(Number(points[points.length - 1].split(",")[0]), 100);
});

test("every emitted coordinate is finite", () => {
  // A single NaN anywhere poisons the whole SVG attribute, and the browser
  // silently drops the polyline - a chart that vanishes with no console error.
  const segments = polylineSegments([0, Infinity, 2, -Infinity, 4], 100, 30);
  for (const segment of segments) {
    for (const point of segment.split(" ")) {
      const [x, y] = point.split(",").map(Number);
      assert.ok(Number.isFinite(x), `x in ${point}`);
      assert.ok(Number.isFinite(y), `y in ${point}`);
    }
  }
});

test("a single sample draws one point, not a line that spans the box", () => {
  // With one sample there is no step, so the "line" is a single coordinate at
  // x=0. It must not be smeared across the full width, which would imply a
  // trend that was never measured.
  const segments = polylineSegments([42], 100, 30);
  assert.equal(segments.length, 1);
  assert.equal(segments[0].split(" ").length, 1);
});