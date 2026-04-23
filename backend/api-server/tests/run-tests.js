const assert = require("node:assert/strict");

const { normalizeSecurityEvent } = require("../services/normalization.service");
const {
  appendUnique,
  mergeSeverity,
  buildSummary,
} = require("../services/incident.service");
const {
  inferCountryNode,
  severityToBand,
  topEntries,
} = require("../services/threat-intel.service");

const tests = [
  () => {
    const normalized = normalizeSecurityEvent(
      {
        source: "host-agent",
        eventType: "process.start",
        message: "powershell.exe spawned",
        metadata: {
          host: {
            processName: "powershell.exe",
            pid: "1234",
            elevated: true,
          },
          sourceType: "hids",
        },
      },
      {
        orgId: "org-1",
        assetId: "asset-1",
      }
    );

    assert.equal(normalized.metadata.normalized.category, "host");
    assert.equal(normalized.metadata.normalized.sourceType, "hids");
    assert.equal(normalized.metadata.host.pid, 1234);
    assert.equal(normalized.metadata.host.elevated, true);
    assert.ok(normalized.eventId);
  },
  () => {
    assert.deepEqual(appendUnique(["1.1.1.1"], "1.1.1.1"), ["1.1.1.1"]);
    assert.deepEqual(appendUnique(["1.1.1.1"], "2.2.2.2"), ["1.1.1.1", "2.2.2.2"]);
  },
  () => {
    assert.equal(mergeSeverity("Medium", "High"), "High");
    assert.equal(mergeSeverity("Critical", "Low"), "Critical");
  },
  () => {
    const summary = buildSummary({
      attackType: "Port Scan Activity",
      ip: "10.0.0.8",
      confidence: 0.88,
      risk_score: 77,
    });

    assert.match(summary, /Port Scan Activity/);
    assert.match(summary, /10.0.0.8/);
    assert.match(summary, /77/);
  },
  () => {
    const node = inferCountryNode("US");
    assert.equal(node.code, "US");
  },
  () => {
    assert.equal(severityToBand("Critical"), "high");
    assert.equal(severityToBand("Medium"), "medium");
    assert.equal(severityToBand("Low"), "low");
  },
  () => {
    const result = topEntries(
      [{ value: "a" }, { value: "b" }, { value: "a" }],
      (item) => item.value,
      () => 1,
      5
    );

    assert.equal(result[0].name, "a");
    assert.equal(result[0].value, 2);
  },
];

let passed = 0;

for (const [index, testFn] of tests.entries()) {
  try {
    testFn();
    passed += 1;
    console.log(`ok ${index + 1}`);
  } catch (error) {
    console.error(`not ok ${index + 1}`);
    console.error(error);
    process.exit(1);
  }
}

console.log(`\n${passed}/${tests.length} assertions passed`);
