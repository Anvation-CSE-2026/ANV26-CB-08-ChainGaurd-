const { detectAbuse } = require('./detection-engine');
const { scoreRisk } = require('./risk-engine');

// Both the built-in demo API and future authenticated integrations use this path.
function analyzeObservedEvent(event, recentEvents) {
  event.risk = scoreRisk(event, recentEvents);
  const detections = detectAbuse(event, recentEvents);
  if (detections.length) event.detections = detections.map((detection) => detection.type);
  return { event, detections };
}

module.exports = { analyzeObservedEvent };
