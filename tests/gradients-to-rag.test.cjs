"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const guide = require("../docs/guide-core.js");

test("the gradient matches finite differences of the mean squared loss", () => {
  const w = 2.5;
  const b = 6;
  const epsilon = 1e-5;
  const gradient = guide.gradient(w, b);
  const dw = (guide.loss(w + epsilon, b) - guide.loss(w - epsilon, b)) / (2 * epsilon);
  const db = (guide.loss(w, b + epsilon) - guide.loss(w, b - epsilon)) / (2 * epsilon);
  assert.ok(Math.abs(gradient.dw - dw) < 1e-6);
  assert.ok(Math.abs(gradient.db - db) < 1e-6);
});

test("the default learning rate reduces loss and the plotted optimum is stationary", () => {
  let point = { w: 0, b: 0 };
  const initialLoss = guide.loss(point.w, point.b);
  for (let i = 0; i < 250; i += 1) point = guide.step(point.w, point.b, 0.012);
  assert.ok(guide.loss(point.w, point.b) < initialLoss * 0.01);
  const best = guide.optimum();
  const gradient = guide.gradient(best.w, best.b);
  assert.ok(Math.abs(gradient.dw) < 1e-10);
  assert.ok(Math.abs(gradient.db) < 1e-10);
  assert.ok(guide.loss(best.w, best.b) < guide.loss(point.w, point.b));
});

test("an excessive learning rate diverges from the same starting point", () => {
  let point = { w: 0, b: 0 };
  const initialLoss = guide.loss(point.w, point.b);
  for (let i = 0; i < 50; i += 1) point = guide.step(point.w, point.b, 0.04);
  assert.ok(guide.loss(point.w, point.b) > initialLoss * 100);
});

test("backpropagated gradients match the neuron loss on each side of ReLU", () => {
  const epsilon = 1e-5;
  for (const [x, w1, bias, w2, target] of [[2, 1.5, 0, 1, 5], [2, -1, 0, 1, 5]]) {
    const result = guide.neuron(x, w1, bias, w2, target);
    const dw1 = (
      guide.neuron(x, w1 + epsilon, bias, w2, target).loss
      - guide.neuron(x, w1 - epsilon, bias, w2, target).loss
    ) / (2 * epsilon);
    const dw2 = (
      guide.neuron(x, w1, bias, w2 + epsilon, target).loss
      - guide.neuron(x, w1, bias, w2 - epsilon, target).loss
    ) / (2 * epsilon);
    assert.ok(Math.abs(result.dLossDw1 - dw1) < 1e-8);
    assert.ok(Math.abs(result.dLossDw2 - dw2) < 1e-8);
  }
  assert.equal(guide.neuron(2, 1, -3, 1, 5).dLossDw1, 0);
});

test("temperature changes the probability distribution without numerical overflow", () => {
  const logits = [1000, 999, 998];
  const cool = guide.softmax(logits, 0.2);
  const warm = guide.softmax(logits, 2);
  assert.ok(cool[0] > warm[0]);
  assert.ok(cool[2] < warm[2]);
  assert.ok(Math.abs(cool.reduce((sum, p) => sum + p, 0) - 1) < 1e-12);
  assert.throws(() => guide.softmax(logits, 0), RangeError);
});

test("cosine uses all dimensions and handles a zero vector explicitly", () => {
  assert.equal(guide.cosine([1, 0], [1, 0]), 1);
  assert.equal(guide.cosine([1, 0], [0, 1]), 0);
  assert.equal(guide.cosine([0, 0], [1, 1]), null);
  assert.throws(() => guide.cosine([1], [1, 2]), RangeError);
  const results = guide.rankVectors([0.85, 0.05, 0.95, 0.05, 0.1]);
  assert.equal(results[0].name, "Crash fraud");
  assert.ok(results.find((item) => item.name === "Crash claim").similarity < 0.9);
});

test("retrieval enforces access before ranking and excludes another customer's payment", () => {
  const secured = guide.retrieve("Is my payment past due?", "dana", true, 3);
  assert.ok(secured.matches.some((chunk) => chunk.id === "D1"));
  assert.ok(secured.entries.find((chunk) => chunk.id === "L1").score === null);
  assert.ok(secured.matches.every((chunk) => chunk.permitted));

  const unsecured = guide.retrieve("Is my payment past due?", "dana", false, 3);
  assert.ok(unsecured.matches.some((chunk) => chunk.id === "L1" && !chunk.permitted));
});

test("retrieval keeps internal notes out of a customer prompt but lets the adjuster use them", () => {
  const query = "When does a claim go to fraud review?";
  const customer = guide.retrieve(query, "dana", true, 3);
  const adjuster = guide.retrieve(query, "mira", true, 3);
  const withoutFilter = guide.retrieve(query, "dana", false, 3);
  assert.ok(customer.matches.every((chunk) => chunk.id !== "I1"));
  assert.ok(adjuster.matches.some((chunk) => chunk.id === "I1"));
  assert.ok(withoutFilter.matches.some((chunk) => chunk.id === "I1"));
});

test("authorized public content can still contain a prompt injection", () => {
  const result = guide.retrieve("hail damage", "dana", true, 3);
  const faq = result.matches.find((chunk) => chunk.id === "P1");
  assert.ok(faq);
  assert.equal(faq.permitted, true);
  assert.match(faq.text, /ignore earlier directions/i);
  assert.match(faq.text, /external\.invalid/);
});

test("empty or unmatched queries return no passages and invalid controls fail explicitly", () => {
  assert.deepEqual(guide.retrieve("", "dana", true, 3).matches, []);
  assert.deepEqual(guide.retrieve("xylophone", "dana", true, 3).matches, []);
  assert.throws(() => guide.retrieve("payment", "nobody", true, 3), RangeError);
  assert.throws(() => guide.retrieve("payment", "dana", true, 0), RangeError);
});
