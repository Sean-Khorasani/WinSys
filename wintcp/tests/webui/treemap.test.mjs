// wintcp/tests/webui/treemap.test.mjs
// SPDX-License-Identifier: Apache-2.0
//
// Tests for the squarified treemap layout.
//
//   node --test wintcp/tests/webui/
//
// The one property that makes a treemap a treemap is that AREA IS PROPORTIONAL
// TO VALUE. A layout that gets that wrong is worse than no treemap: it draws a
// picture that looks like data and is not. So that is asserted directly rather
// than inferred from "the rectangles look reasonable".

import { test } from "node:test";
import assert from "node:assert/strict";

import { squarify } from "../../webui/js/charts/treemap.js";

const WIDTH = 800;
const HEIGHT = 400;
const BOX_AREA = WIDTH * HEIGHT;

test("area is proportional to value", () => {
  const items = [
    { value: 50 }, { value: 25 }, { value: 15 }, { value: 10 },
  ];
  const total = 100;
  for (const cell of squarify(items, WIDTH, HEIGHT)) {
    const expected = (cell.item.value / total) * BOX_AREA;
    const actual = cell.width * cell.height;
    // 0.5% tolerance: the layout subtracts a 1px margin from each tile, and the
    // assertion is on the layout, not on the rendered margin.
    assert.ok(
      Math.abs(actual - expected) / expected < 0.005,
      `cell ${JSON.stringify(cell.item)} area ${actual} vs expected ${expected}`,
    );
  }
});

test("a single item fills the whole box", () => {
  const cells = squarify([{ value: 7 }], WIDTH, HEIGHT);
  assert.equal(cells.length, 1);
  assert.ok(Math.abs(cells[0].width - WIDTH) < 0.01);
  assert.ok(Math.abs(cells[0].height - HEIGHT) < 0.01);
});

test("two items in a 2:1 ratio come out as halves, not slivers", () => {
  const cells = squarify([{ value: 3 }, { value: 1 }], WIDTH, HEIGHT);
  assert.equal(cells.length, 2);
  const byValue = [...cells].sort((a, b) => b.item.value - a.item.value);
  const big = byValue[0];
  const small = byValue[1];
  assert.ok(Math.abs(big.width * big.height / (small.width * small.height) - 3) < 0.05,
    "area ratio must match the value ratio");
  // The regression this guards: the naive slice algorithm gives the small item a
  // 3x800 sliver here.
  assert.ok(small.width > 10 && small.height > 10,
    `small tile is ${small.width}x${small.height}, which is a sliver`);
});

test("zero, negative, NaN and non-finite values are excluded, not drawn as zero", () => {
  const items = [
    { value: 10 }, { value: 0 }, { value: -5 }, { value: NaN },
    { value: Infinity }, { value: null },
  ];
  const cells = squarify(items, WIDTH, HEIGHT);
  // A zero-area tile is indistinguishable from no data, and a negative area is
  // worse than either.
  assert.equal(cells.length, 1);
  assert.equal(cells[0].item.value, 10);
});

test("an empty or non-positive input produces nothing rather than throwing", () => {
  assert.deepEqual(squarify([], WIDTH, HEIGHT), []);
  assert.deepEqual(squarify(null, WIDTH, HEIGHT), []);
  assert.deepEqual(squarify([{ value: 5 }], 0, HEIGHT), []);
  assert.deepEqual(squarify([{ value: 5 }], WIDTH, 0), []);
  assert.deepEqual(squarify([{ value: 5 }], -10, -10), []);
});

test("tiles stay inside the box", () => {
  const items = Array.from({ length: 60 }, (_, i) => ({ value: (i % 7) + 1 }));
  for (const cell of squarify(items, WIDTH, HEIGHT)) {
    assert.ok(cell.x >= -0.01, `x ${cell.x} < 0`);
    assert.ok(cell.y >= -0.01, `y ${cell.y} < 0`);
    assert.ok(cell.x + cell.width <= WIDTH + 0.01,
      `right edge ${cell.x + cell.width} > ${WIDTH}`);
    assert.ok(cell.y + cell.height <= HEIGHT + 0.01,
      `bottom edge ${cell.y + cell.height} > ${HEIGHT}`);
  }
});

test("tiles do not overlap", () => {
  const items = Array.from({ length: 25 }, (_, i) => ({ value: i + 1 }));
  const cells = squarify(items, WIDTH, HEIGHT);
  for (let i = 0; i < cells.length; i += 1) {
    for (let j = i + 1; j < cells.length; j += 1) {
      const a = cells[i];
      const b = cells[j];
      const overlapX = Math.min(a.x + a.width, b.x + b.width) - Math.max(a.x, b.x);
      const overlapY = Math.min(a.y + a.height, b.y + b.height) - Math.max(a.y, b.y);
      const overlapping = overlapX > 0.01 && overlapY > 0.01;
      assert.ok(!overlapping,
        `cells ${i} and ${j} overlap by ${overlapX.toFixed(2)}x${overlapY.toFixed(2)}`);
    }
  }
});

test("every input item appears exactly once", () => {
  const items = Array.from({ length: 40 }, (_, i) => ({ value: i + 1, key: `k${i}` }));
  const cells = squarify(items, WIDTH, HEIGHT);
  assert.equal(cells.length, items.length);
  const keys = cells.map((c) => c.item.key).sort();
  assert.deepEqual(keys, items.map((i) => i.key).sort());
});

test("output order is independent of input order (packing is by area)", () => {
  const items = [{ value: 5, key: "a", label: "a" }, { value: 3, key: "b", label: "b" },
                 { value: 1, key: "c", label: "c" }, { value: 1, key: "d", label: "d" }];
  // Keyed by value, not position: a layout that packs by input order would give
  // the same data two visibly different pictures depending only on sort order,
  // which is exactly the flicker the table's PID tie-break exists to prevent.
  const shape = (list) => Object.fromEntries(
    squarify(list, WIDTH, HEIGHT)
      .filter((c) => c.width > 0 && c.height > 0)
      .map((c) => [c.item.key,
        `${c.x.toFixed(1)},${c.y.toFixed(1)},${c.width.toFixed(1)},${c.height.toFixed(1)}`]),
  );
  assert.deepEqual(shape(items), shape([...items].reverse()));
});

test("a very wide box still produces proportional areas", () => {
  // The layout picks the shorter side for each row; a 10:1 box is where a naive
  // implementation's aspect ratios blow up.
  const items = [{ value: 6 }, { value: 3 }, { value: 1 }];
  for (const cell of squarify(items, 2000, 200)) {
    const expected = (cell.item.value / 10) * (2000 * 200);
    assert.ok(Math.abs(cell.width * cell.height - expected) / expected < 0.005);
  }
});