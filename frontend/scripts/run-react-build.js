const generatedBuildPath = `build-codex-verify-${Date.now()}`;
const buildPath = process.env.BUILD_PATH || process.argv[2] || generatedBuildPath;

process.env.BUILD_PATH = buildPath;

require("react-scripts/scripts/build");
