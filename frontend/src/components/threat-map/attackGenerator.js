const COUNTRY_NODES = [
  { country: "United States", code: "US", coordinates: [-98.5795, 39.8283] },
  { country: "Canada", code: "CA", coordinates: [-106.3468, 56.1304] },
  { country: "Brazil", code: "BR", coordinates: [-51.9253, -14.235] },
  { country: "United Kingdom", code: "GB", coordinates: [-3.436, 55.3781] },
  { country: "Germany", code: "DE", coordinates: [10.4515, 51.1657] },
  { country: "France", code: "FR", coordinates: [2.2137, 46.2276] },
  { country: "Nigeria", code: "NG", coordinates: [8.6753, 9.082] },
  { country: "South Africa", code: "ZA", coordinates: [22.9375, -30.5595] },
  { country: "India", code: "IN", coordinates: [78.9629, 20.5937] },
  { country: "China", code: "CN", coordinates: [104.1954, 35.8617] },
  { country: "Japan", code: "JP", coordinates: [138.2529, 36.2048] },
  { country: "Singapore", code: "SG", coordinates: [103.8198, 1.3521] },
  { country: "Australia", code: "AU", coordinates: [133.7751, -25.2744] },
  { country: "Russia", code: "RU", coordinates: [105.3188, 61.524] },
  { country: "United Arab Emirates", code: "AE", coordinates: [53.8478, 23.4241] },
  { country: "South Korea", code: "KR", coordinates: [127.7669, 35.9078] },
  { country: "Israel", code: "IL", coordinates: [34.8516, 31.0461] },
  { country: "Turkey", code: "TR", coordinates: [35.2433, 38.9637] },
  { country: "Ukraine", code: "UA", coordinates: [31.1656, 48.3794] },
  { country: "Saudi Arabia", code: "SA", coordinates: [45.0792, 23.8859] },
  { country: "Indonesia", code: "ID", coordinates: [113.9213, -0.7893] },
  { country: "Mexico", code: "MX", coordinates: [-102.5528, 23.6345] },
  { country: "Argentina", code: "AR", coordinates: [-63.6167, -38.4161] },
  { country: "Spain", code: "ES", coordinates: [-3.7492, 40.4637] },
  { country: "Italy", code: "IT", coordinates: [12.5674, 41.8719] },
  { country: "Poland", code: "PL", coordinates: [19.1451, 51.9194] },
];

const randomItem = (items) => items[Math.floor(Math.random() * items.length)];

const weightedRandom = (items) => {
  const totalWeight = items.reduce((sum, item) => sum + item.weight, 0);
  let threshold = Math.random() * totalWeight;

  for (const item of items) {
    threshold -= item.weight;
    if (threshold <= 0) {
      return item.value;
    }
  }

  return items[items.length - 1]?.value;
};

const ATTACK_TYPE_WEIGHTS = [
  { value: "DDoS Attack", weight: 24 },
  { value: "Brute Force Attack", weight: 16 },
  { value: "SQL Injection", weight: 13 },
  { value: "XSS Attack", weight: 11 },
  { value: "Port Scanning", weight: 14 },
  { value: "Malware Activity", weight: 12 },
  { value: "Phishing Attempt", weight: 10 },
];

const SOURCE_WEIGHTS = {
  US: 18,
  CN: 16,
  RU: 15,
  IN: 12,
  TR: 10,
  DE: 9,
  SG: 8,
  BR: 8,
  GB: 8,
  NG: 7,
  KR: 7,
  AE: 7,
};

const TARGET_WEIGHTS = {
  US: 18,
  IN: 13,
  GB: 11,
  AU: 10,
  DE: 10,
  SG: 9,
  JP: 9,
  IL: 8,
  FR: 8,
  AE: 8,
};

const weightedNode = (weightMap) =>
  weightedRandom(
    COUNTRY_NODES.map((node) => ({
      value: node,
      weight: weightMap[node.code] || 4,
    }))
  );

const weightedSeverity = (attackType) => {
  const highBiasTypes = new Set(["DDoS Attack", "Malware Activity", "SQL Injection"]);
  const weights = highBiasTypes.has(attackType)
    ? [
        { value: "low", weight: 3 },
        { value: "medium", weight: 5 },
        { value: "high", weight: 7 },
      ]
    : [
        { value: "low", weight: 5 },
        { value: "medium", weight: 6 },
        { value: "high", weight: 4 },
      ];

  return weightedRandom(weights);
};

const createAttackId = () =>
  `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

export const generateAttack = () => {
  const attackType = weightedRandom(ATTACK_TYPE_WEIGHTS);
  const source = weightedNode(SOURCE_WEIGHTS);
  let target = weightedNode(TARGET_WEIGHTS);

  while (target.code === source.code) {
    target = weightedNode(TARGET_WEIGHTS);
  }

  return {
    id: createAttackId(),
    source,
    target,
    attackType,
    severity: weightedSeverity(attackType),
    timestamp: new Date().toISOString(),
    latencyMs: 28 + Math.floor(Math.random() * 250),
    vector: randomItem([
      "HTTP Flood",
      "Credential Abuse",
      "Command Injection",
      "Reconnaissance",
      "Exploit Delivery",
      "Suspicious Payload",
      "Application Layer Flood",
    ]),
  };
};

export const generateAttackBatch = (count = 12) =>
  Array.from({ length: count }, () => generateAttack());
