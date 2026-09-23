// =========================================================
// RAIVEN Risk Engine v0.8.0
// Stage A4.8
//
// A4.3 Risk Context & Scoring
// A4.4 Security Requirements
// A4.5 Risk Decision Consistency
// A4.6 Risk Decision Integrity
// A4.7 Risk Decision Determinism
// A4.8 Risk Consistency & Determinism
//
// IMPORTANT:
//
// RiskEngine NEVER grants permission.
// RiskEngine NEVER executes actions.
// RiskEngine ONLY:
//
// - evaluates risk
// - determines security requirements
// - produces decision traces
// - verifies decision integrity
// - verifies deterministic behavior
// - verifies consistency
//
// RiskEngine cannot grant itself authority.
// =========================================================


export class RiskEngine {

    constructor() {

        this.version = "0.8.0";

        this._decisionCounter = 0;
    }


    // =========================================================
    // RISK LEVELS
    // =========================================================

    static LEVELS = Object.freeze({

        LOW: 1,

        MEDIUM: 2,

        HIGH: 3,

        CRITICAL: 4
    });


    // =========================================================
    // VALID ENUMERATIONS
    // =========================================================

    static VALUES = Object.freeze({

        dataSensitivity: [
            "PUBLIC",
            "PRIVATE",
            "SENSITIVE"
        ],

        externalEffect: [
            "NONE",
            "DEVICE",
            "NETWORK"
        ],

        reversibility: [
            "REVERSIBLE",
            "IRREVERSIBLE"
        ],

        userImpact: [
            "LOW",
            "MEDIUM",
            "HIGH"
        ],

        scope: [
            "ONCE",
            "SESSION",
            "PERSISTENT"
        ],

        actionType: [
            "READ",
            "WRITE",
            "CAPTURE",
            "TRANSMIT",
            "DELETE",
            "EXECUTE"
        ],

        executionMode: [
            "LOCAL",
            "REMOTE"
        ],

        duration: [
            "SINGLE",
            "CONTINUOUS"
        ]
    });


    // =========================================================
    // A4.3 — ACTION VALIDATION
    // =========================================================

    validateAction(action) {

        if (
            !action ||
            typeof action !== "object" ||
            Array.isArray(action)
        ) {

            return {

                valid: false,

                reason:
                    "INVALID_ACTION"
            };
        }


        const requiredFields = [

            "dataSensitivity",

            "externalEffect",

            "reversibility",

            "userImpact",

            "scope",

            "actionType",

            "executionMode",

            "duration"
        ];


        for (const field of requiredFields) {

            const value =
                action[field];


            if (
                !RiskEngine.VALUES[field] ||
                !RiskEngine.VALUES[field].includes(value)
            ) {

                return {

                    valid: false,

                    reason:
                        `INVALID_${field.toUpperCase()}`
                };
            }
        }


        return {

            valid: true,

            reason:
                "VALID"
        };
    }


    // =========================================================
    // A4.3 — CONTEXT CLASSIFICATION
    // =========================================================

    classifyContext(action) {

        return {

            actionType:
                action.actionType,

            executionMode:
                action.executionMode,

            duration:
                action.duration,

            scope:
                action.scope,

            externalEffect:
                action.externalEffect,

            dataSensitivity:
                action.dataSensitivity
        };
    }


    // =========================================================
    // A4.3 — RISK SCORE
    // =========================================================

    calculateScore(action) {

        let score = 0;


        if (
            action.permission &&
            action.permission !== "NONE"
        ) {

            score += 1;
        }


        if (
            action.dataSensitivity === "PRIVATE"
        ) {

            score += 1;
        }


        if (
            action.dataSensitivity === "SENSITIVE"
        ) {

            score += 2;
        }


        if (
            action.externalEffect === "DEVICE"
        ) {

            score += 1;
        }


        if (
            action.externalEffect === "NETWORK"
        ) {

            score += 2;
        }


        if (
            action.reversibility === "IRREVERSIBLE"
        ) {

            score += 2;
        }


        if (
            action.userImpact === "MEDIUM"
        ) {

            score += 1;
        }


        if (
            action.userImpact === "HIGH"
        ) {

            score += 2;
        }


        if (
            action.scope === "SESSION"
        ) {

            score += 1;
        }


        if (
            action.scope === "PERSISTENT"
        ) {

            score += 2;
        }


        if (
            action.actionType === "WRITE"
        ) {

            score += 1;
        }


        if (
            action.actionType === "CAPTURE"
        ) {

            score += 1;
        }


        if (
            action.actionType === "TRANSMIT"
        ) {

            score += 2;
        }


        if (
            action.actionType === "DELETE"
        ) {

            score += 2;
        }


        if (
            action.actionType === "EXECUTE"
        ) {

            score += 2;
        }


        if (
            action.executionMode === "REMOTE"
        ) {

            score += 1;
        }


        if (
            action.duration === "CONTINUOUS"
        ) {

            score += 1;
        }


        return score;
    }


    // =========================================================
    // A4.3 — SCORE CLASSIFICATION
    // =========================================================

    classifyScore(score) {

        if (score <= 1)
            return "LOW";


        if (score <= 3)
            return "MEDIUM";


        if (score <= 6)
            return "HIGH";


        return "CRITICAL";
    }


    // =========================================================
    // A4.3 — RISK FLOORS
    // =========================================================

    applyRiskFloor(action, currentLevel) {

        let level =
            RiskEngine.LEVELS[currentLevel];


        if (
            action.dataSensitivity === "SENSITIVE" &&
            action.externalEffect === "NETWORK"
        ) {

            level = Math.max(
                level,
                RiskEngine.LEVELS.HIGH
            );
        }


        if (
            action.reversibility === "IRREVERSIBLE"
        ) {

            level = Math.max(
                level,
                RiskEngine.LEVELS.HIGH
            );
        }


        if (
            action.reversibility === "IRREVERSIBLE" &&
            action.userImpact === "HIGH"
        ) {

            level = Math.max(
                level,
                RiskEngine.LEVELS.CRITICAL
            );
        }


        if (
            action.scope === "PERSISTENT" &&
            action.dataSensitivity === "SENSITIVE"
        ) {

            level = Math.max(
                level,
                RiskEngine.LEVELS.HIGH
            );
        }


        if (
            action.actionType === "DELETE"
        ) {

            level = Math.max(
                level,
                RiskEngine.LEVELS.HIGH
            );
        }


        if (
            action.actionType === "EXECUTE" &&
            action.executionMode === "REMOTE"
        ) {

            level = Math.max(
                level,
                RiskEngine.LEVELS.HIGH
            );
        }


        if (
            action.dataSensitivity === "SENSITIVE" &&
            action.duration === "CONTINUOUS"
        ) {

            level = Math.max(
                level,
                RiskEngine.LEVELS.HIGH
            );
        }


        return Object.keys(
            RiskEngine.LEVELS
        ).find(
            key =>
                RiskEngine.LEVELS[key] === level
        );
    }


    // =========================================================
    // A4.4 — SECURITY REQUIREMENTS
    // =========================================================

    getRequirements(riskLevel, action) {

        const requirements = {

            requiresConfirmation: false,

            requiresExplicitConfirmation: false,

            requiresAdditionalAuthentication: false,

            requiresAuditLog: true,

            requiresIsolation: false,

            requiresPreExecutionReview: false,

            requiresEmergencyProtection: false
        };


        if (riskLevel === "MEDIUM") {

            requirements.requiresConfirmation = true;
        }


        if (riskLevel === "HIGH") {

            requirements.requiresConfirmation = true;

            requirements.requiresExplicitConfirmation = true;

            requirements.requiresPreExecutionReview = true;

            requirements.requiresEmergencyProtection = true;
        }


        if (riskLevel === "CRITICAL") {

            requirements.requiresConfirmation = true;

            requirements.requiresExplicitConfirmation = true;

            requirements.requiresAdditionalAuthentication = true;

            requirements.requiresPreExecutionReview = true;

            requirements.requiresIsolation = true;

            requirements.requiresEmergencyProtection = true;
        }


        if (
            action.actionType === "EXECUTE" &&
            action.executionMode === "REMOTE"
        ) {

            requirements.requiresExplicitConfirmation = true;

            requirements.requiresPreExecutionReview = true;

            requirements.requiresEmergencyProtection = true;
        }


        if (
            action.actionType === "DELETE"
        ) {

            requirements.requiresExplicitConfirmation = true;

            requirements.requiresPreExecutionReview = true;

            requirements.requiresEmergencyProtection = true;
        }


        if (
            action.dataSensitivity === "SENSITIVE" &&
            action.duration === "CONTINUOUS"
        ) {

            requirements.requiresExplicitConfirmation = true;

            requirements.requiresAdditionalAuthentication = true;

            requirements.requiresIsolation = true;

            requirements.requiresPreExecutionReview = true;

            requirements.requiresEmergencyProtection = true;
        }


        if (
            action.externalEffect === "NETWORK" &&
            action.actionType === "TRANSMIT"
        ) {

            requirements.requiresExplicitConfirmation = true;

            requirements.requiresPreExecutionReview = true;
        }


        return requirements;
    }


    // =========================================================
    // A4.4 — REQUIREMENT VALIDATION
    // =========================================================

    validateRequirementSet(requirements) {

        if (
            !requirements ||
            typeof requirements !== "object"
        ) {

            return {

                valid: false,

                reason:
                    "INVALID_REQUIREMENTS"
            };
        }


        const fields = [

            "requiresConfirmation",

            "requiresExplicitConfirmation",

            "requiresAdditionalAuthentication",

            "requiresAuditLog",

            "requiresIsolation",

            "requiresPreExecutionReview",

            "requiresEmergencyProtection"
        ];


        for (const field of fields) {

            if (
                typeof requirements[field] !== "boolean"
            ) {

                return {

                    valid: false,

                    reason:
                        `INVALID_REQUIREMENT_${field.toUpperCase()}`
                };
            }
        }


        if (
            requirements.requiresExplicitConfirmation &&
            !requirements.requiresConfirmation
        ) {

            return {

                valid: false,

                reason:
                    "EXPLICIT_CONFIRMATION_WITHOUT_CONFIRMATION"
            };
        }


        if (
            requirements.requiresAdditionalAuthentication &&
            !requirements.requiresConfirmation
        ) {

            return {

                valid: false,

                reason:
                    "AUTHENTICATION_WITHOUT_CONFIRMATION"
            };
        }


        if (
            requirements.requiresIsolation &&
            !requirements.requiresPreExecutionReview
        ) {

            return {

                valid: false,

                reason:
                    "ISOLATION_WITHOUT_PRE_EXECUTION_REVIEW"
            };
        }


        if (
            requirements.requiresEmergencyProtection &&
            !requirements.requiresAuditLog
        ) {

            return {

                valid: false,

                reason:
                    "EMERGENCY_PROTECTION_WITHOUT_AUDIT_LOG"
            };
        }


        return {

            valid: true,

            reason:
                "VALID_REQUIREMENTS"
        };
    }


    // =========================================================
    // A4.5 — REQUIREMENT COMPARISON
    // =========================================================

    getRequirementLevel(requirement) {

        return requirement === true
            ? 1
            : 0;
    }


    compareRequirements(
        lowerRequirements,
        higherRequirements
    ) {

        const validationLow =
            this.validateRequirementSet(
                lowerRequirements
            );


        const validationHigh =
            this.validateRequirementSet(
                higherRequirements
            );


        if (
            !validationLow.valid ||
            !validationHigh.valid
        ) {

            return {

                consistent: false,

                reason:
                    "INVALID_REQUIREMENT_SET"
            };
        }


        const fields = [

            "requiresConfirmation",

            "requiresExplicitConfirmation",

            "requiresAdditionalAuthentication",

            "requiresAuditLog",

            "requiresIsolation",

            "requiresPreExecutionReview",

            "requiresEmergencyProtection"
        ];


        for (const field of fields) {

            const lower =
                this.getRequirementLevel(
                    lowerRequirements[field]
                );


            const higher =
                this.getRequirementLevel(
                    higherRequirements[field]
                );


            if (higher < lower) {

                return {

                    consistent: false,

                    reason:
                        `SECURITY_REGRESSION_${field.toUpperCase()}`,

                    field
                };
            }
        }


        return {

            consistent: true,

            reason:
                "CONSISTENT"
        };
    }


    // =========================================================
    // A4.5 — MONOTONICITY
    // =========================================================

    validateRequirementMonotonicity() {

        const levels = [

            "LOW",

            "MEDIUM",

            "HIGH",

            "CRITICAL"
        ];


        const profiles = {};


        const baseAction = {

            actionType: "READ",

            executionMode: "LOCAL",

            duration: "SINGLE",

            dataSensitivity: "PUBLIC",

            externalEffect: "NONE",

            reversibility: "REVERSIBLE",

            userImpact: "LOW",

            scope: "ONCE"
        };


        for (const level of levels) {

            profiles[level] =
                this.getRequirements(
                    level,
                    baseAction
                );
        }


        for (
            let i = 0;
            i < levels.length - 1;
            i++
        ) {

            const lower =
                levels[i];

            const higher =
                levels[i + 1];


            const comparison =
                this.compareRequirements(
                    profiles[lower],
                    profiles[higher]
                );


            if (
                !comparison.consistent
            ) {

                return {

                    valid: false,

                    reason:
                        comparison.reason,

                    lower,

                    higher,

                    field:
                        comparison.field ||
                        null
                };
            }
        }


        return {

            valid: true,

            reason:
                "REQUIREMENT_MONOTONICITY_VALID",

            profiles
        };
    }


    // =========================================================
    // A4.6 — DECISION ID
    // =========================================================

    createDecisionId() {

        this._decisionCounter++;


        return (
            `DECISION-${Date.now()}-${this._decisionCounter}`
        );
    }


    // =========================================================
    // A4.6 — STABLE SERIALIZATION
    // =========================================================

    stableStringify(value) {

        if (
            value === null ||
            typeof value !== "object"
        ) {

            return JSON.stringify(value);
        }


        if (Array.isArray(value)) {

            return "[" +
                value
                    .map(
                        item =>
                            this.stableStringify(item)
                    )
                    .join(",") +
                "]";
        }


        return "{" +
            Object.keys(value)
                .sort()
                .map(
                    key =>
                        JSON.stringify(key) +
                        ":" +
                        this.stableStringify(
                            value[key]
                        )
                )
                .join(",") +
            "}";
    }


    // =========================================================
    // A4.6 — DECISION FINGERPRINT
    // =========================================================

    generateFingerprint(decision) {

        const copy = {};


        for (
            const key of Object.keys(decision)
        ) {

            if (key !== "integrity") {

                copy[key] =
                    decision[key];
            }
        }


        const input =
            this.stableStringify(copy);


        let hash = 2166136261;


        for (
            let i = 0;
            i < input.length;
            i++
        ) {

            hash ^=
                input.charCodeAt(i);


            hash +=
                (hash << 1) +
                (hash << 4) +
                (hash << 7) +
                (hash << 8) +
                (hash << 24);


            hash >>>= 0;
        }


        return hash
            .toString(16)
            .padStart(8, "0");
    }


    // =========================================================
    // A4.6 — ATTACH INTEGRITY
    // =========================================================

    attachDecisionIntegrity(decision) {

        if (
            !decision ||
            typeof decision !== "object"
        ) {

            throw new TypeError(
                "Cannot attach integrity to invalid decision."
            );
        }


        const decisionId =
            this.createDecisionId();


        const baseDecision = {

            ...decision,

            decisionId
        };


        const fingerprint =
            this.generateFingerprint(
                baseDecision
            );


        return Object.freeze({

            ...baseDecision,

            integrity:
                Object.freeze({

                    algorithm: "FNV1A",

                    fingerprint,

                    valid: true
                })
        });
    }


    // =========================================================
    // A4.6 — VERIFY INTEGRITY
    // =========================================================

    verifyDecisionIntegrity(decision) {

        if (
            !decision ||
            typeof decision !== "object"
        ) {

            return {

                valid: false,

                reason:
                    "INVALID_DECISION"
            };
        }


        if (
            typeof decision.decisionId !== "string" ||
            decision.decisionId.length === 0
        ) {

            return {

                valid: false,

                reason:
                    "MISSING_DECISION_ID"
            };
        }


        if (
            !decision.integrity ||
            typeof decision.integrity !== "object"
        ) {

            return {

                valid: false,

                reason:
                    "MISSING_DECISION_INTEGRITY"
            };
        }


        if (
            typeof decision.integrity.fingerprint !== "string" ||
            decision.integrity.fingerprint.length === 0
        ) {

            return {

                valid: false,

                reason:
                    "MISSING_DECISION_FINGERPRINT"
            };
        }


        const expectedFingerprint =
            this.generateFingerprint(
                decision
            );


        if (
            expectedFingerprint !==
            decision.integrity.fingerprint
        ) {

            return {

                valid: false,

                reason:
                    "DECISION_TAMPER_DETECTED",

                expectedFingerprint,

                fingerprint:
                    decision.integrity.fingerprint
            };
        }


        return {

            valid: true,

            reason:
                "DECISION_INTEGRITY_VALID",

            decisionId:
                decision.decisionId,

            fingerprint:
                decision.integrity.fingerprint
        };
    }


    // =========================================================
    // A4.6 — FAIL CLOSED
    // =========================================================

    enforceDecisionIntegrity(decision) {

        const verification =
            this.verifyDecisionIntegrity(
                decision
            );


        if (!verification.valid) {

            return {

                allowed: false,

                trusted: false,

                reason:
                    "DECISION_INTEGRITY_FAILURE",

                integrity:
                    verification
            };
        }


        return {

            allowed:
                decision.allowed === true,

            trusted: true,

            reason:
                "DECISION_INTEGRITY_VALID",

            integrity:
                verification
        };
    }


    // =========================================================
    // A4.7 — DETERMINISTIC SNAPSHOT
    // =========================================================

    getDeterministicDecision(result) {

        if (
            !result ||
            typeof result !== "object"
        ) {

            return null;
        }


        return {

            allowed:
                result.allowed ?? false,

            riskScore:
                result.riskScore ?? null,

            baseRiskLevel:
                result.baseRiskLevel ?? null,

            riskLevel:
                result.riskLevel ?? null,

            reason:
                result.reason ?? null,

            context:
                result.context
                    ? {

                        actionType:
                            result.context.actionType,

                        executionMode:
                            result.context.executionMode,

                        duration:
                            result.context.duration,

                        scope:
                            result.context.scope,

                        externalEffect:
                            result.context.externalEffect,

                        dataSensitivity:
                            result.context.dataSensitivity
                    }
                    : null,

            requirements:
                result.requirements
                    ? {

                        requiresConfirmation:
                            result.requirements.requiresConfirmation,

                        requiresExplicitConfirmation:
                            result.requirements.requiresExplicitConfirmation,

                        requiresAdditionalAuthentication:
                            result.requirements.requiresAdditionalAuthentication,

                        requiresAuditLog:
                            result.requirements.requiresAuditLog,

                        requiresIsolation:
                            result.requirements.requiresIsolation,

                        requiresPreExecutionReview:
                            result.requirements.requiresPreExecutionReview,

                        requiresEmergencyProtection:
                            result.requirements.requiresEmergencyProtection
                    }
                    : null,

            consistency:
                result.consistency
                    ? {

                        valid:
                            result.consistency.valid,

                        reason:
                            result.consistency.reason
                    }
                    : null
        };
    }


    // =========================================================
    // A4.7 — COMPARE DETERMINISTIC DECISIONS
    // =========================================================

    compareDeterministicDecisions(
        first,
        second
    ) {

        const a =
            this.getDeterministicDecision(
                first
            );


        const b =
            this.getDeterministicDecision(
                second
            );


        if (!a || !b) {

            return {

                deterministic: false,

                reason:
                    "INVALID_DECISION"
            };
        }


        const firstJSON =
            JSON.stringify(a);


        const secondJSON =
            JSON.stringify(b);


        if (
            firstJSON !==
            secondJSON
        ) {

            return {

                deterministic: false,

                reason:
                    "DECISION_MISMATCH",

                first: a,

                second: b
            };
        }


        return {

            deterministic: true,

            reason:
                "DECISION_DETERMINISTIC"
        };
    }


    // =========================================================
    // A4.7 — REPEATED DETERMINISM TEST
    // =========================================================

    validateDeterminism(
        action,
        iterations = 10
    ) {

        if (
            !Number.isInteger(iterations) ||
            iterations < 2
        ) {

            return {

                valid: false,

                reason:
                    "INVALID_ITERATION_COUNT"
            };
        }


        const results = [];


        for (
            let i = 0;
            i < iterations;
            i++
        ) {

            results.push(
                this.evaluate(action)
            );
        }


        const baseline =
            results[0];


        for (
            let i = 1;
            i < results.length;
            i++
        ) {

            const comparison =
                this.compareDeterministicDecisions(
                    baseline,
                    results[i]
                );


            if (
                !comparison.deterministic
            ) {

                return {

                    valid: false,

                    reason:
                        comparison.reason,

                    iteration:
                        i + 1
                };
            }
        }


        return {

            valid: true,

            reason:
                "RISK_DECISION_DETERMINISTIC",

            iterations,

            decision:
                this.getDeterministicDecision(
                    baseline
                )
        };
    }


    // =========================================================
    // A4.7 — EVALUATION PURITY
    // =========================================================

    validateEvaluationPurity(action) {

        if (
            !action ||
            typeof action !== "object"
        ) {

            return {

                valid: false,

                reason:
                    "INVALID_ACTION"
            };
        }


        const before =
            JSON.stringify(action);


        this.evaluate(action);


        const after =
            JSON.stringify(action);


        if (before !== after) {

            return {

                valid: false,

                reason:
                    "ACTION_MUTATED_DURING_EVALUATION"
            };
        }


        return {

            valid: true,

            reason:
                "EVALUATION_PURITY_VALID"
        };
    }


    // =========================================================
    // A4.8 — DECISION CONSISTENCY
    // =========================================================

    validateDecisionConsistency(decision) {

        if (
            !decision ||
            typeof decision !== "object"
        ) {

            return {

                valid: false,

                reason:
                    "INVALID_DECISION"
            };
        }


        const requiredFields = [

            "riskScore",

            "baseRiskLevel",

            "riskLevel",

            "requirements",

            "consistency"
        ];


        for (const field of requiredFields) {

            if (
                !Object.prototype.hasOwnProperty.call(
                    decision,
                    field
                )
            ) {

                return {

                    valid: false,

                    reason:
                        `MISSING_DECISION_FIELD_${field.toUpperCase()}`
                };
            }
        }


        // -----------------------------------------------------
        // Risk score validation
        // -----------------------------------------------------

        if (
            decision.riskScore !== null &&
            (
                typeof decision.riskScore !== "number" ||
                !Number.isFinite(
                    decision.riskScore
                ) ||
                decision.riskScore < 0
            )
        ) {

            return {

                valid: false,

                reason:
                    "INVALID_RISK_SCORE"
            };
        }


        // -----------------------------------------------------
        // Validate base risk level
        // -----------------------------------------------------

        if (
            !Object.prototype.hasOwnProperty.call(
                RiskEngine.LEVELS,
                decision.baseRiskLevel
            )
        ) {

            return {

                valid: false,

                reason:
                    "INVALID_BASE_RISK_LEVEL"
            };
        }


        // -----------------------------------------------------
        // Validate final risk level
        // -----------------------------------------------------

        if (
            !Object.prototype.hasOwnProperty.call(
                RiskEngine.LEVELS,
                decision.riskLevel
            )
        ) {

            return {

                valid: false,

                reason:
                    "INVALID_RISK_LEVEL"
            };
        }


        // -----------------------------------------------------
        // Risk level must never regress
        // -----------------------------------------------------

        if (
            RiskEngine.LEVELS[
                decision.riskLevel
            ] <
            RiskEngine.LEVELS[
                decision.baseRiskLevel
            ]
        ) {

            return {

                valid: false,

                reason:
                    "RISK_LEVEL_REGRESSION"
            };
        }


        // -----------------------------------------------------
        // Validate requirements
        // -----------------------------------------------------

        const requirementValidation =
            this.validateRequirementSet(
                decision.requirements
            );


        if (
            !requirementValidation.valid
        ) {

            return {

                valid: false,

                reason:
                    "INVALID_DECISION_REQUIREMENTS"
            };
        }


        // -----------------------------------------------------
        // Validate expected requirements
        // -----------------------------------------------------

        if (decision.context) {

            const expectedRequirements =
                this.getRequirements(
                    decision.riskLevel,
                    decision.context
                );


            const requirementComparison =
                this.compareRequirements(
                    expectedRequirements,
                    decision.requirements
                );


            if (
                !requirementComparison.consistent
            ) {

                return {

                    valid: false,

                    reason:
                        "REQUIREMENT_REGRESSION",

                    field:
                        requirementComparison.field ||
                        null
                };
            }
        }


        // -----------------------------------------------------
        // Validate consistency flag
        // -----------------------------------------------------

        if (
            decision.consistency &&
            decision.consistency.valid !== true
        ) {

            return {

                valid: false,

                reason:
                    "DECISION_CONSISTENCY_FLAG_INVALID"
            };
        }


        return {

            valid: true,

            reason:
                "DECISION_CONSISTENT"
        };
    }


    // =========================================================
    // A4.8 — REPEATED CONSISTENCY
    // =========================================================

    validateRepeatedConsistency(
        action,
        iterations = 10
    ) {

        if (
            !Number.isInteger(iterations) ||
            iterations < 2
        ) {

            return {

                valid: false,

                reason:
                    "INVALID_ITERATION_COUNT"
            };
        }


        const results = [];


        for (
            let i = 0;
            i < iterations;
            i++
        ) {

            const decision =
                this.evaluate(action);


            const consistency =
                this.validateDecisionConsistency(
                    decision
                );


            if (
                !consistency.valid
            ) {

                return {

                    valid: false,

                    reason:
                        "DECISION_CONSISTENCY_FAILURE",

                    iteration:
                        i + 1,

                    details:
                        consistency
                };
            }


            results.push(
                decision
            );
        }


        const baseline =
            results[0];


        for (
            let i = 1;
            i < results.length;
            i++
        ) {

            const comparison =
                this.compareDeterministicDecisions(
                    baseline,
                    results[i]
                );


            if (
                !comparison.deterministic
            ) {

                return {

                    valid: false,

                    reason:
                        "REPEATED_DECISION_MISMATCH",

                    iteration:
                        i + 1
                };
            }
        }


        return {

            valid: true,

            reason:
                "REPEATED_DECISION_CONSISTENT",

            iterations
        };
    }


    // =========================================================
    // A4.8 — CROSS-DECISION CONSISTENCY
    // =========================================================

    validateCrossDecisionConsistency(
        firstAction,
        secondAction
    ) {

        const firstValidation =
            this.validateAction(
                firstAction
            );


        const secondValidation =
            this.validateAction(
                secondAction
            );


        if (
            !firstValidation.valid ||
            !secondValidation.valid
        ) {

            return {

                valid: false,

                reason:
                    "INVALID_COMPARISON_ACTION"
            };
        }


        const firstDecision =
            this.evaluate(
                firstAction
            );


        const secondDecision =
            this.evaluate(
                secondAction
            );


        const firstSnapshot =
            this.getDeterministicDecision(
                firstDecision
            );


        const secondSnapshot =
            this.getDeterministicDecision(
                secondDecision
            );


        const firstContext =
            firstSnapshot.context;


        const secondContext =
            secondSnapshot.context;


        // Equivalent security contexts must
        // produce equivalent security decisions.

        if (
            JSON.stringify(firstContext) ===
            JSON.stringify(secondContext)
        ) {

            const comparison =
                this.compareDeterministicDecisions(
                    firstDecision,
                    secondDecision
                );


            if (
                !comparison.deterministic
            ) {

                return {

                    valid: false,

                    reason:
                        "EQUIVALENT_CONTEXT_DECISION_MISMATCH"
                };
            }
        }


        return {

            valid: true,

            reason:
                "CROSS_DECISION_CONSISTENT"
        };
    }


    // =========================================================
    // A4.8 — INTEGRITY + CONSISTENCY
    // =========================================================

    validateIntegrityConsistency(
        decision
    ) {

        const consistency =
            this.validateDecisionConsistency(
                decision
            );


        if (
            !consistency.valid
        ) {

            return {

                valid: false,

                reason:
                    "DECISION_CONSISTENCY_FAILURE",

                details:
                    consistency
            };
        }


        const integrity =
            this.verifyDecisionIntegrity(
                decision
            );


        if (
            !integrity.valid
        ) {

            return {

                valid: false,

                reason:
                    "DECISION_INTEGRITY_FAILURE",

                details:
                    integrity
            };
        }


        return {

            valid: true,

            reason:
                "INTEGRITY_AND_CONSISTENCY_VALID"
        };
    }


    // =========================================================
    // A4.8 — DETERMINISTIC REPLAY
    // =========================================================

    validateDeterministicReplay(
        action
    ) {

        const first =
            this.evaluate(
                action
            );


        const second =
            this.evaluate(
                action
            );


        const consistencyFirst =
            this.validateDecisionConsistency(
                first
            );


        const consistencySecond =
            this.validateDecisionConsistency(
                second
            );


        if (
            !consistencyFirst.valid ||
            !consistencySecond.valid
        ) {

            return {

                valid: false,

                reason:
                    "REPLAY_CONSISTENCY_FAILURE"
            };
        }


        const comparison =
            this.compareDeterministicDecisions(
                first,
                second
            );


        if (
            !comparison.deterministic
        ) {

            return {

                valid: false,

                reason:
                    "REPLAY_DETERMINISM_FAILURE"
            };
        }


        return {

            valid: true,

            reason:
                "DETERMINISTIC_REPLAY_VALID"
        };
    }


    // =========================================================
    // A4.8 — FAIL-CLOSED CONSISTENCY
    // =========================================================

    validateFailClosedConsistency() {

        const invalidInputs = [

            null,

            undefined,

            {},

            {
                actionType: "INVALID"
            },

            {
                actionType: "READ",

                executionMode: "INVALID",

                duration: "SINGLE",

                dataSensitivity: "PUBLIC",

                externalEffect: "NONE",

                reversibility: "REVERSIBLE",

                userImpact: "LOW",

                scope: "ONCE"
            }
        ];


        for (
            let i = 0;
            i < invalidInputs.length;
            i++
        ) {

            const decision =
                this.evaluate(
                    invalidInputs[i]
                );


            // Must deny.

            if (
                decision.allowed !== false
            ) {

                return {

                    valid: false,

                    reason:
                        "FAIL_CLOSED_BYPASS",

                    case:
                        i + 1
                };
            }


            // Must be critical.

            if (
                decision.riskLevel !==
                "CRITICAL"
            ) {

                return {

                    valid: false,

                    reason:
                        "FAIL_CLOSED_RISK_REGRESSION",

                    case:
                        i + 1
                };
            }


            // Must remain internally consistent.

            const consistency =
                this.validateDecisionConsistency(
                    decision
                );


            if (
                !consistency.valid
            ) {

                return {

                    valid: false,

                    reason:
                        "FAIL_CLOSED_CONSISTENCY_FAILURE",

                    case:
                        i + 1
                };
            }


            // Must retain integrity.

            const integrity =
                this.verifyDecisionIntegrity(
                    decision
                );


            if (
                !integrity.valid
            ) {

                return {

                    valid: false,

                    reason:
                        "FAIL_CLOSED_INTEGRITY_FAILURE",

                    case:
                        i + 1
                };
            }
        }


        return {

            valid: true,

            reason:
                "FAIL_CLOSED_CONSISTENCY_VALID",

            cases:
                invalidInputs.length
        };
    }


    // =========================================================
    // A4.8 — COMPLETE VERIFICATION
    // =========================================================

    validateA48(action) {

        if (
            !action ||
            typeof action !== "object"
        ) {

            return {

                valid: false,

                reason:
                    "INVALID_A48_ACTION"
            };
        }


        // -----------------------------------------------------
        // 1. Decision consistency
        // -----------------------------------------------------

        const decision =
            this.evaluate(
                action
            );


        const decisionConsistency =
            this.validateDecisionConsistency(
                decision
            );


        if (
            !decisionConsistency.valid
        ) {

            return {

                valid: false,

                stage:
                    "DECISION_CONSISTENCY",

                details:
                    decisionConsistency
            };
        }


        // -----------------------------------------------------
        // 2. Integrity + consistency
        // -----------------------------------------------------

        const integrityConsistency =
            this.validateIntegrityConsistency(
                decision
            );


        if (
            !integrityConsistency.valid
        ) {

            return {

                valid: false,

                stage:
                    "INTEGRITY_CONSISTENCY",

                details:
                    integrityConsistency
            };
        }


        // -----------------------------------------------------
        // 3. Repeated consistency
        // -----------------------------------------------------

        const repeatedConsistency =
            this.validateRepeatedConsistency(
                action,
                10
            );


        if (
            !repeatedConsistency.valid
        ) {

            return {

                valid: false,

                stage:
                    "REPEATED_CONSISTENCY",

                details:
                    repeatedConsistency
            };
        }


        // -----------------------------------------------------
        // 4. Deterministic replay
        // -----------------------------------------------------

        const replay =
            this.validateDeterministicReplay(
                action
            );


        if (
            !replay.valid
        ) {

            return {

                valid: false,

                stage:
                    "DETERMINISTIC_REPLAY",

                details:
                    replay
            };
        }


        // -----------------------------------------------------
        // 5. Fail-closed consistency
        // -----------------------------------------------------

        const failClosed =
            this.validateFailClosedConsistency();


        if (
            !failClosed.valid
        ) {

            return {

                valid: false,

                stage:
                    "FAIL_CLOSED_CONSISTENCY",

                details:
                    failClosed
            };
        }


        // -----------------------------------------------------
        // A4.8 PASS
        // -----------------------------------------------------

        return {

            valid: true,

            reason:
                "A4.8_RISK_CONSISTENCY_AND_DETERMINISM_VALID",

            tests: {

                decisionConsistency:
                    true,

                integrityConsistency:
                    true,

                repeatedConsistency:
                    true,

                deterministicReplay:
                    true,

                failClosedConsistency:
                    true
            },

            engineVersion:
                this.version
        };
    }


    // =========================================================
    // MAIN EVALUATION
    // =========================================================

    evaluate(action) {

        const validation =
            this.validateAction(
                action
            );


        // =====================================================
        // FAIL CLOSED — INVALID ACTION
        // =====================================================

        if (!validation.valid) {

            const criticalAction = {

                actionType:
                    "EXECUTE",

                executionMode:
                    "REMOTE",

                duration:
                    "SINGLE",

                dataSensitivity:
                    "SENSITIVE",

                externalEffect:
                    "NETWORK",

                reversibility:
                    "IRREVERSIBLE",

                userImpact:
                    "HIGH",

                scope:
                    "PERSISTENT"
            };


            const criticalRequirements =
                this.getRequirements(
                    "CRITICAL",
                    criticalAction
                );


            return this.attachDecisionIntegrity({

                allowed:
                    false,

                action:
                    action?.name ||
                    "UNKNOWN_ACTION",

                riskScore:
                    null,

                baseRiskLevel:
                    "CRITICAL",

                riskLevel:
                    "CRITICAL",

                reason:
                    validation.reason,

                requirements:
                    Object.freeze(
                        criticalRequirements
                    ),

                consistency:
                    Object.freeze({

                        valid:
                            true,

                        reason:
                            "FAIL_CLOSED_CRITICAL"
                    }),

                evaluatedAt:
                    Date.now(),

                engineVersion:
                    this.version
            });
        }


        // =====================================================
        // VALID ACTION
        // =====================================================

        const context =
            this.classifyContext(
                action
            );


        const score =
            this.calculateScore(
                action
            );


        const baseLevel =
            this.classifyScore(
                score
            );


        const riskLevel =
            this.applyRiskFloor(
                action,
                baseLevel
            );


        const requirements =
            this.getRequirements(
                riskLevel,
                action
            );


        const requirementValidation =
            this.validateRequirementSet(
                requirements
            );


        // =====================================================
        // REQUIREMENT FAILURE — FAIL CLOSED
        // =====================================================

        if (
            !requirementValidation.valid
        ) {

            return this.attachDecisionIntegrity({

                allowed:
                    false,

                action:
                    action.name ||
                    "UNKNOWN_ACTION",

                riskScore:
                    score,

                baseRiskLevel:
                    baseLevel,

                riskLevel:
                    "CRITICAL",

                reason:
                    "SECURITY_REQUIREMENT_INCONSISTENCY",

                requirementError:
                    requirementValidation.reason,

                requirements:
                    Object.freeze(
                        this.getRequirements(
                            "CRITICAL",
                            action
                        )
                    ),

                consistency:
                    Object.freeze({

                        valid:
                            false,

                        reason:
                            requirementValidation.reason
                    }),

                evaluatedAt:
                    Date.now(),

                engineVersion:
                    this.version
            });
        }


        // =====================================================
        // NORMAL VALID DECISION
        // =====================================================

        return this.attachDecisionIntegrity({

            allowed:
                true,

            action:
                action.name ||
                "UNKNOWN_ACTION",

            permission:
                action.permission ||
                "NONE",

            riskScore:
                score,

            baseRiskLevel:
                baseLevel,

            riskLevel:
                riskLevel,

            context:
                Object.freeze(
                    context
                ),

            requirements:
                Object.freeze(
                    requirements
                ),

            consistency:
                Object.freeze({

                    valid:
                        true,

                    reason:
                        "SECURITY_REQUIREMENTS_CONSISTENT"
                }),

            evaluatedAt:
                Date.now(),

            engineVersion:
                this.version
        });
    }
}
