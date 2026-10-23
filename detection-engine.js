/**
 * PII Guard — Detection Engine
 * Combines pattern matching, format validation, and field context
 * into a confidence-scored detection decision layer.
 *
 * Confidence scoring:
 *   - Pattern match alone: 0.4 base
 *   - Validation pass:    +0.3
 *   - Context supports:   +0.2
 *   - Context contradicts (non-PII field): -0.25
 *   - Context for different PII type: -0.1
 *
 * Warning thresholds:
 *   - Show warning: confidence >= 0.4
 *   - "Potential match": confidence < 0.7
 *   - "Format-validated match": confidence >= 0.7
 */
(() => {
  "use strict";

  // Confidence score components
  const SCORE = {
    PATTERN_MATCH: 0.50,
    VALIDATION_PASS: 0.30,
    CONTEXT_SUPPORTS: 0.20,
    CONTEXT_NON_PII: -0.25,
    CONTEXT_DIFFERENT_TYPE: -0.10,
    MINIMUM_WARN: 0.35,
    VALIDATED_THRESHOLD: 0.70,
  };

  // Low-confidence pattern types that are very prone to false positives
  // These need extra context support or validation to be shown
  const AMBIGUOUS_TYPES = new Set([
    "Indian PIN code",
    "Indian Voter ID (EPIC)",
  ]);

  /**
   * Run full detection pipeline on a value, considering field context.
   *
   * @param {string} text — The input value to analyze
   * @param {Object} fieldContext — Result from ContextAnalyzer.extractFieldContext()
   * @param {Array} patterns — PII_PATTERNS array
   * @returns {Array<Object>} Sorted detection results with confidence scores
   */
  function detectWithContext(text, fieldContext, patterns) {
    if (!text || !text.trim()) return [];

    const results = [];
    const seen = new Set();

    for (const pattern of patterns) {
      // Skip if input is too short for this pattern
      if (pattern.minLength && text.replace(/\s/g, "").length < pattern.minLength) {
        continue;
      }

      // Reset regex lastIndex to be safe (should be 0 for non-global, but belt-and-suspenders)
      if (pattern.regex.lastIndex !== undefined) {
        pattern.regex.lastIndex = 0;
      }

      // Try to find a match
      const match = pattern.regex.exec(text);
      if (!match) continue;
      if (seen.has(pattern.type)) continue;

      const matchedText = match[0];
      let confidence = SCORE.PATTERN_MATCH;
      let validated = false;
      let validationDetail = "";

      // ── Format validation ──────────────────────────────
      if (typeof pattern.validate === "function") {
        try {
          validated = pattern.validate(matchedText, fieldContext, text);
          if (validated) {
            confidence += SCORE.VALIDATION_PASS;
            if (typeof pattern.getDetail === "function") {
              validationDetail = pattern.getDetail(matchedText, fieldContext, text);
            }
          } else {
            if (pattern.requireValidation) {
              continue;
            }
            // Soft penalty: still allow pattern match warning (e.g. mock 12/16 digits in Notepad)
            confidence = Math.max(0.40, confidence - 0.05);
          }
        } catch {
          if (pattern.requireValidation) {
            continue;
          }
          confidence = Math.max(0.40, confidence - 0.05);
        }
      } else if (pattern.requireValidation) {
        continue;
      }

      // ── Context analysis ───────────────────────────────
      let contextRelation = "neutral"; // "supports", "contradicts", "neutral"

      if (fieldContext) {
        // Check if context indicates non-PII field
        if (fieldContext.nonPii) {
          confidence += SCORE.CONTEXT_NON_PII;
          contextRelation = "contradicts";
        }

        // Check if field context categories include this pattern's type
        if (fieldContext.categories && fieldContext.categories.length > 0) {
          const contextAnalyzer =
            (typeof window !== "undefined" && window.PIIContextAnalyzer) ||
            (typeof globalThis !== "undefined" && globalThis.PIIContextAnalyzer);

          if (contextAnalyzer) {
            let contextSupports = false;
            let contextForDifferentType = false;

            for (const category of fieldContext.categories) {
              const patternTypes = contextAnalyzer.getPatternTypesForCategory(category);
              if (patternTypes.includes(pattern.type)) {
                contextSupports = true;
                break;
              } else {
                contextForDifferentType = true;
              }
            }

            if (contextSupports) {
              confidence += SCORE.CONTEXT_SUPPORTS;
              contextRelation = "supports";
            } else if (contextForDifferentType && !fieldContext.nonPii) {
              // Field is labelled for a DIFFERENT PII type
              // This is mild evidence against, but NOT conclusive
              // (user might paste wrong data in wrong field)
              confidence += SCORE.CONTEXT_DIFFERENT_TYPE;
              contextRelation = "different_type";
            }
          }
        }
      }

      // ── Ambiguous pattern handling ─────────────────────
      // For highly ambiguous patterns (e.g., 6-digit PIN code), require
      // either context support or validation to reach warning threshold
      if (AMBIGUOUS_TYPES.has(pattern.type) && contextRelation !== "supports" && !validated) {
        confidence -= 0.10;
      }

      // Clamp confidence
      confidence = Math.max(0, Math.min(1, confidence));

      // Skip if below minimum warning threshold
      if (confidence < SCORE.MINIMUM_WARN) continue;

      seen.add(pattern.type);

      // Determine confidence label
      const confidenceLabel =
        confidence >= SCORE.VALIDATED_THRESHOLD
          ? "format-validated"
          : "potential";

      // Build description
      let message = pattern.description || `Detected: ${pattern.type}`;
      if (validated && validationDetail) {
        message = validationDetail;
      }
      if (confidenceLabel === "potential") {
        message += " Review before sharing.";
      }

      // Check if this pattern is a Phone / Contact number and customize label based on field context
      let displayType = pattern.type;
      if (pattern.type.includes("Phone") || pattern.type.includes("Contact")) {
        const normContext =
          ((fieldContext && fieldContext.normalized) || "") +
          " " +
          text.toLowerCase();
        if (normContext.includes("mobile")) {
          displayType = "Mobile number";
        } else if (normContext.includes("phone")) {
          displayType = "Phone number";
        } else if (normContext.includes("contact")) {
          displayType = "Contact number";
        } else {
          displayType = "Contact / Phone number";
        }
      }

      results.push({
        type: displayType,
        severity: pattern.severity || "warning",
        priority: pattern.priority || 2,
        confidence,
        confidenceLabel,
        validated,
        contextRelation,
        message,
        limitations: pattern.limitations || "",
      });
    }

    // Sort by priority (descending), then confidence (descending)
    results.sort((a, b) => {
      if (b.priority !== a.priority) return b.priority - a.priority;
      return b.confidence - a.confidence;
    });

    return results;
  }

  /**
   * Simple pattern-only detection (backward compatibility).
   * Used when context is unavailable.
   * @param {string} text
   * @param {Array} patterns
   * @returns {Array<Object>}
   */
  function detectPatternsOnly(text, patterns) {
    return detectWithContext(text, null, patterns);
  }

  // ─── Exports ─────────────────────────────────────────────────

  const DetectionEngine = {
    detectWithContext,
    detectPatternsOnly,
    SCORE,
  };

  if (typeof window !== "undefined") {
    window.PIIDetectionEngine = DetectionEngine;
  }
  if (typeof globalThis !== "undefined") {
    globalThis.PIIDetectionEngine = DetectionEngine;
  }
  if (typeof module !== "undefined" && module.exports) {
    module.exports = DetectionEngine;
  }
})();
