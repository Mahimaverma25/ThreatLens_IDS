const fs = require("fs");
const path = require("path");
const { normalizeEvent } = require("../utils/eventNormalizer");
const logger = require("../utils/logger");

class FilewatchCollector {
  constructor(options = {}) {
    this.paths = Array.isArray(options.paths) ? options.paths : [];
    this.watchers = [];
  }

  start(onEvent) {
    this.stop();

    this.watchers = this.paths
      .filter(Boolean)
      .map((targetPath) => {
        try {
          return fs.watch(targetPath, (eventType, filename) => {
            const resolvedPath = filename
              ? path.join(targetPath, filename.toString())
              : targetPath;

            const event = normalizeEvent({
              message: `File watch event: ${eventType}`,
              level: "info",
              source: "host",
              eventType: "file.change",
              metadata: {
                sensorType: "host",
                host: {
                  filePath: resolvedPath,
                  action: eventType,
                },
              },
            });

            if (typeof onEvent === "function") {
              onEvent(event);
            }
          });
        } catch (error) {
          logger.warn(`File watch could not start for ${targetPath}: ${error.message}`);
          return null;
        }
      })
      .filter(Boolean);

    return this.watchers.length;
  }

  stop() {
    this.watchers.forEach((watcher) => watcher.close());
    this.watchers = [];
  }
}

module.exports = FilewatchCollector;
