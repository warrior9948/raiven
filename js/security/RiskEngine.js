// RAIVEN Risk Engine v0.7
// Stage A4.7
//
// Risk Decision Determinism
//
// IMPORTANT:
// RiskEngine NEVER grants permission.
// RiskEngine NEVER executes actions.
// RiskEngine ONLY evaluates risk,
// determines security requirements,
// produces decision traces,
// and verifies deterministic behavior.

export class RiskEngine {

    constructor() {
        this.version = "0.7";
    }

    static LEVELS = Object.freeze({
        LOW: 1,
        MEDIUM: 2,
        HIGH: 3,
        CRITICAL: 4
    });

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

    validateAction(action) {

        if (!action || typeof action !== "object") {
            return {
                valid: false,
                reason: "INVALID_ACTION"
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

            const value = action[field];

            if (
                !RiskEngine.VALUES[field] ||
                !RiskEngine.VALUES[field].includes(value)
            ) {
                return {
                    valid: false,
                    reason: `INVALID_${field.toUpperCase()}`
                };
            }
        }

        return {
            valid: true,
            reason: "VALID"
        };
    }

    classifyContext(action) {

        return {
            actionType: action.actionType,
            executionMode: action.executionMode,
            duration: action.duration,
            scope: action.scope,
            externalEffect: action.externalEffect,
            dataSensitivity: action.dataSensitivity
        };
    }

    calculateScore(action) {

        let score = 0;

        if (action.permission &&
            action.permission !== "NONE") score += 1;

        if (action.dataSensitivity === "PRIVATE")
            score += 1;

        if (action.dataSensitivity === "SENSITIVE")
            score += 2;

        if (action.externalEffect === "DEVICE")
            score += 1;

        if (action.externalEffect === "NETWORK")
            score += 2;

        if (action.reversibility === "IRREVERSIBLE")
            score += 2;

        if (action.userImpact === "MEDIUM")
            score += 1;

        if (action.userImpact === "HIGH")
            score += 2;

        if (action.scope === "SESSION")
            score += 1;

        if (action.scope === "PERSISTENT")
            score += 2;

        if (action.actionType === "WRITE")
            score += 1;

        if (action.actionType === "CAPTURE")
            score += 1;

        if (action.actionType === "TRANSMIT")
            score += 2;

        if (action.actionType === "DELETE")
            score += 2;

        if (action.actionType === "EXECUTE")
            score += 2;

        if (action.executionMode === "REMOTE")
            score += 1;

        if (action.duration === "CONTINUOUS")
            score += 1;

        return score;
    }

    classifyScore(score) {

        if (score <= 1) return "LOW";
        if (score <= 3) return "MEDIUM";
        if (score <= 6) return "HIGH";

        return "CRITICAL";
    }

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

        if (action.actionType === "DELETE") {

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

        if (action.actionType === "DELETE") {

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

    validateRequirementSet(requirements) {

        if (
            !requirements ||
            typeof requirements !== "object"
        ) {
            return {
                valid: false,
                reason: "INVALID_REQUIREMENTS"
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
            reason: "VALID_REQUIREMENTS"
        };
    }

    getRequirementLevel(requirement) {

        return requirement === true ? 1 : 0;
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
            reason: "CONSISTENT"
        };
    }

    /*
     * A4.5
     * Requirement monotonicity verification.
     */
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

            const lower = levels[i];

            const higher = levels[i + 1];

            const comparison =
                this.compareRequirements(
                    profiles[lower],
                    profiles[higher]
                );

            if (!comparison.consistent) {

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

    /*
     * A4.7
     *
     * Creates a deterministic representation
     * of the security-relevant decision.
     *
     * Dynamic fields such as timestamps are
     * deliberately excluded.
     */
    getDeterministicDecision(result) {

        if (!result || typeof result !== "object") {

            return null;
        }

        return {
            allowed: result.allowed ?? false,

            riskScore:
                result.riskScore ?? null,

            baseRiskLevel:
                result.baseRiskLevel ?? null,

            riskLevel:
                result.riskLevel ?? null,

            reason:
                result.reason ?? null,

            requirements:
                result.requirements
                    ? {
                        requiresConfirmation:
                            result.requirements
                                .requiresConfirmation,

                        requiresExplicitConfirmation:
                            result.requirements
                                .requiresExplicitConfirmation,

                        requiresAdditionalAuthentication:
                            result.requirements
                                .requiresAdditionalAuthentication,

                        requiresAuditLog:
                            result.requirements
                                .requiresAuditLog,

                        requiresIsolation:
                            result.requirements
                                .requiresIsolation,

                        requiresPreExecutionReview:
                            result.requirements
                                .requiresPreExecutionReview,

                        requiresEmergencyProtection:
                            result.requirements
                                .requiresEmergencyProtection
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

    /*
     * A4.7
     *
     * Compare two decisions while ignoring
     * dynamic metadata such as timestamps.
     */
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
                reason: "INVALID_DECISION"
            };
        }

        const firstJSON =
            JSON.stringify(a);

        const secondJSON =
            JSON.stringify(b);

        if (firstJSON !== secondJSON) {

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

    /*
     * A4.7
     *
     * Evaluates the same action repeatedly and
     * verifies that every security-relevant
     * decision remains identical.
     */
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

            if (!comparison.deterministic) {

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

    /*
     * A4.7
     *
     * Verify that evaluation does not mutate
     * the caller's action object.
     */
    validateEvaluationPurity(action) {

        if (
            !action ||
            typeof action !== "object"
        ) {
            return {
                valid: false,
                reason: "INVALID_ACTION"
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

    evaluate(action) {

        const validation =
            this.validateAction(action);

        /*
         * FAIL CLOSED
         */
        if (!validation.valid) {

            const criticalAction = {

                actionType: "EXECUTE",

                executionMode: "REMOTE",

                duration: "SINGLE",

                dataSensitivity: "SENSITIVE",

                externalEffect: "NETWORK",

                reversibility: "IRREVERSIBLE",

                userImpact: "HIGH",

                scope: "PERSISTENT"
            };

            const criticalRequirements =
                this.getRequirements(
                    "CRITICAL",
                    criticalAction
                );

            return Object.freeze({

                allowed: false,

                action:
                    action?.name ||
                    "UNKNOWN_ACTION",

                riskScore: null,

                riskLevel: "CRITICAL",

                reason:
                    validation.reason,

                requirements:
                    Object.freeze(
                        criticalRequirements
                    ),

                consistency:
                    Object.freeze({

                        valid: true,

                        reason:
                            "FAIL_CLOSED_CRITICAL"
                    }),

                evaluatedAt:
                    Date.now(),

                engineVersion:
                    this.version
            });
        }

        const context =
            this.classifyContext(action);

        const score =
            this.calculateScore(action);

        const baseLevel =
            this.classifyScore(score);

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

        if (!requirementValidation.valid) {

            return Object.freeze({

                allowed: false,

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

                evaluatedAt:
                    Date.now(),

                engineVersion:
                    this.version
            });
        }

        return Object.freeze({

            allowed: true,

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

                    valid: true,

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
