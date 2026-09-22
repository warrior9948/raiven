// RAIVEN Risk Engine v0.6
// Stage A4.6
//
// Risk Decision Integrity
//
// IMPORTANT:
// RiskEngine NEVER grants permission.
// RiskEngine NEVER executes actions.
// RiskEngine ONLY evaluates risk,
// determines security requirements,
// verifies requirement consistency,
// and protects decision integrity.

export class RiskEngine {

    constructor() {
        this.version = "0.6";
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

    static REQUIREMENT_ORDER = Object.freeze({
        requiresConfirmation: 1,
        requiresExplicitConfirmation: 2,
        requiresAdditionalAuthentication: 3,
        requiresAuditLog: 1,
        requiresIsolation: 4,
        requiresPreExecutionReview: 3,
        requiresEmergencyProtection: 3
    });


    /*
     * A4.1–A4.5
     * ACTION VALIDATION
     */

    validateAction(action) {

        if (
            !action ||
            typeof action !== "object"
        ) {
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

        for (
            const field of requiredFields
        ) {

            const value =
                action[field];

            if (
                !RiskEngine.VALUES[field]
                    .includes(value)
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
            reason: "VALID"
        };
    }


    /*
     * ACTION CONTEXT
     */

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


    /*
     * RISK SCORE
     */

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


    classifyScore(score) {

        if (score <= 1) {
            return "LOW";
        }

        if (score <= 3) {
            return "MEDIUM";
        }

        if (score <= 6) {
            return "HIGH";
        }

        return "CRITICAL";
    }


    /*
     * RISK FLOORS
     */

    applyRiskFloor(
        action,
        currentLevel
    ) {

        let level =
            RiskEngine.LEVELS[
                currentLevel
            ];

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


    /*
     * SECURITY REQUIREMENTS
     */

    getRequirements(
        riskLevel,
        action
    ) {

        const requirements = {

            requiresConfirmation: false,

            requiresExplicitConfirmation: false,

            requiresAdditionalAuthentication: false,

            requiresAuditLog: true,

            requiresIsolation: false,

            requiresPreExecutionReview: false,

            requiresEmergencyProtection: false
        };


        if (
            riskLevel === "MEDIUM"
        ) {

            requirements
                .requiresConfirmation = true;
        }


        if (
            riskLevel === "HIGH"
        ) {

            requirements
                .requiresConfirmation = true;

            requirements
                .requiresExplicitConfirmation = true;

            requirements
                .requiresPreExecutionReview = true;

            requirements
                .requiresEmergencyProtection = true;
        }


        if (
            riskLevel === "CRITICAL"
        ) {

            requirements
                .requiresConfirmation = true;

            requirements
                .requiresExplicitConfirmation = true;

            requirements
                .requiresAdditionalAuthentication = true;

            requirements
                .requiresPreExecutionReview = true;

            requirements
                .requiresIsolation = true;

            requirements
                .requiresEmergencyProtection = true;
        }


        /*
         * Context escalation
         */

        if (
            action &&
            action.actionType === "EXECUTE" &&
            action.executionMode === "REMOTE"
        ) {

            requirements
                .requiresExplicitConfirmation = true;

            requirements
                .requiresPreExecutionReview = true;

            requirements
                .requiresEmergencyProtection = true;
        }


        if (
            action &&
            action.actionType === "DELETE"
        ) {

            requirements
                .requiresExplicitConfirmation = true;

            requirements
                .requiresPreExecutionReview = true;

            requirements
                .requiresEmergencyProtection = true;
        }


        if (
            action &&
            action.dataSensitivity === "SENSITIVE" &&
            action.duration === "CONTINUOUS"
        ) {

            requirements
                .requiresExplicitConfirmation = true;

            requirements
                .requiresAdditionalAuthentication = true;

            requirements
                .requiresIsolation = true;

            requirements
                .requiresPreExecutionReview = true;

            requirements
                .requiresEmergencyProtection = true;
        }


        if (
            action &&
            action.externalEffect === "NETWORK" &&
            action.actionType === "TRANSMIT"
        ) {

            requirements
                .requiresExplicitConfirmation = true;

            requirements
                .requiresPreExecutionReview = true;
        }


        /*
         * CRITICAL = ALL PROTECTIONS
         */

        if (
            riskLevel === "CRITICAL"
        ) {

            requirements
                .requiresConfirmation = true;

            requirements
                .requiresExplicitConfirmation = true;

            requirements
                .requiresAdditionalAuthentication = true;

            requirements
                .requiresAuditLog = true;

            requirements
                .requiresIsolation = true;

            requirements
                .requiresPreExecutionReview = true;

            requirements
                .requiresEmergencyProtection = true;
        }


        return requirements;
    }


    /*
     * A4.5
     * REQUIREMENT VALIDATION
     */

    getRequirementLevel(
        requirement
    ) {

        if (
            requirement === true
        ) {
            return 1;
        }

        return 0;
    }


    validateRequirementSet(
        requirements
    ) {

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


        for (
            const field of fields
        ) {

            if (
                typeof requirements[field] !==
                "boolean"
            ) {

                return {
                    valid: false,
                    reason:
                        `INVALID_REQUIREMENT_${field.toUpperCase()}`
                };
            }
        }


        if (
            requirements
                .requiresExplicitConfirmation &&
            !requirements
                .requiresConfirmation
        ) {

            return {
                valid: false,
                reason:
                    "EXPLICIT_CONFIRMATION_WITHOUT_CONFIRMATION"
            };
        }


        if (
            requirements
                .requiresAdditionalAuthentication &&
            !requirements
                .requiresConfirmation
        ) {

            return {
                valid: false,
                reason:
                    "AUTHENTICATION_WITHOUT_CONFIRMATION"
            };
        }


        if (
            requirements
                .requiresIsolation &&
            !requirements
                .requiresPreExecutionReview
        ) {

            return {
                valid: false,
                reason:
                    "ISOLATION_WITHOUT_PRE_EXECUTION_REVIEW"
            };
        }


        if (
            requirements
                .requiresEmergencyProtection &&
            !requirements
                .requiresAuditLog
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


        for (
            const field of fields
        ) {

            const lower =
                this.getRequirementLevel(
                    lowerRequirements[field]
                );

            const higher =
                this.getRequirementLevel(
                    higherRequirements[field]
                );


            if (
                higher < lower
            ) {

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


        for (
            const level of levels
        ) {

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


    /*
     * ==================================================
     * A4.6
     * RISK DECISION INTEGRITY
     * ==================================================
     *
     * The fingerprint is a deterministic representation
     * of the security-relevant decision fields.
     *
     * This is tamper DETECTION.
     *
     * It is NOT a cryptographic signature.
     *
     * Browser-side JavaScript cannot provide a
     * trustworthy cryptographic authority against
     * someone who can modify the application itself.
     */


    createDecisionId() {

        return (

            "RD-" +

            Date.now().toString(36) +

            "-" +

            Math.random()
                .toString(36)
                .slice(2, 10)

        ).toUpperCase();
    }


    createDecisionFingerprint(
        decision
    ) {

        if (
            !decision ||
            typeof decision !== "object"
        ) {

            return null;
        }


        const integrityData = {

            action:
                decision.action ||
                null,

            permission:
                decision.permission ||
                "NONE",

            riskScore:
                decision.riskScore ??
                null,

            baseRiskLevel:
                decision.baseRiskLevel ||
                null,

            riskLevel:
                decision.riskLevel ||
                null,

            context:
                decision.context ||
                null,

            requirements:
                decision.requirements ||
                null
        };


        const serialized =
            JSON.stringify(
                integrityData
            );


        /*
         * Deterministic non-cryptographic hash.
         */

        let hash = 2166136261;


        for (
            let i = 0;
            i < serialized.length;
            i++
        ) {

            hash ^=
                serialized.charCodeAt(i);

            hash +=
                (hash << 1) +
                (hash << 4) +
                (hash << 7) +
                (hash << 8) +
                (hash << 24);
        }


        hash =
            hash >>> 0;


        return (
            "RI-" +
            hash
                .toString(16)
                .padStart(8, "0")
                .toUpperCase()
        );
    }


    attachDecisionIntegrity(
        decision
    ) {

        if (
            !decision ||
            typeof decision !== "object"
        ) {

            return null;
        }


        const decisionId =
            this.createDecisionId();


        const decisionWithId = {

            ...decision,

            decisionId
        };


        const fingerprint =
            this.createDecisionFingerprint(
                decisionWithId
            );


        return Object.freeze({

            ...decisionWithId,

            integrity:
                Object.freeze({

                    decisionId,

                    fingerprint,

                    valid: true,

                    method:
                        "DETERMINISTIC_TAMPER_DETECTION",

                    integrityVersion:
                        "0.1"
                })
        });
    }


    verifyDecisionIntegrity(
        decision
    ) {

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
            !decision.integrity ||
            typeof decision.integrity !==
            "object"
        ) {

            return {

                valid: false,

                reason:
                    "INTEGRITY_DATA_MISSING"
            };
        }


        if (
            !decision.integrity.decisionId ||
            !decision.integrity.fingerprint
        ) {

            return {

                valid: false,

                reason:
                    "INTEGRITY_DATA_INCOMPLETE"
            };
        }


        if (
            decision.decisionId !==
            decision.integrity.decisionId
        ) {

            return {

                valid: false,

                reason:
                    "DECISION_ID_MISMATCH"
            };
        }


        const recalculatedFingerprint =
            this.createDecisionFingerprint(
                decision
            );


        if (
            recalculatedFingerprint !==
            decision.integrity.fingerprint
        ) {

            return {

                valid: false,

                reason:
                    "DECISION_TAMPER_DETECTED",

                expected:
                    decision.integrity.fingerprint,

                actual:
                    recalculatedFingerprint
            };
        }


        return {

            valid: true,

            reason:
                "DECISION_INTEGRITY_VALID",

            decisionId:
                decision.decisionId,

            fingerprint:
                recalculatedFingerprint
        };
    }


    /*
     * A4.6 FAIL-CLOSED INTEGRITY CHECK
     */

    enforceDecisionIntegrity(
        decision
    ) {

        const verification =
            this.verifyDecisionIntegrity(
                decision
            );


        if (
            !verification.valid
        ) {

            return Object.freeze({

                allowed: false,

                trusted: false,

                reason:
                    "DECISION_INTEGRITY_FAILURE",

                integrity:
                    Object.freeze(
                        verification
                    ),

                evaluatedAt:
                    Date.now(),

                engineVersion:
                    this.version
            });
        }


        return Object.freeze({

            allowed:
                decision.allowed === true,

            trusted: true,

            reason:
                "DECISION_INTEGRITY_VALID",

            decisionId:
                verification.decisionId,

            fingerprint:
                verification.fingerprint,

            integrity:
                Object.freeze(
                    verification
                )
        });
    }


    /*
     * ==================================================
     * EVALUATE
     * ==================================================
     */

    evaluate(action) {

        const validation =
            this.validateAction(
                action
            );


        /*
         * FAIL CLOSED
         */

        if (
            !validation.valid
        ) {

            const criticalRequirements =
                this.getRequirements(
                    "CRITICAL",
                    {
                        actionType: "EXECUTE",
                        executionMode: "REMOTE",
                        duration: "SINGLE",
                        dataSensitivity: "SENSITIVE",
                        externalEffect: "NETWORK",
                        reversibility: "IRREVERSIBLE",
                        userImpact: "HIGH",
                        scope: "PERSISTENT"
                    }
                );


            const failClosedDecision =
                {

                    allowed: false,

                    action:
                        action?.name ||
                        "UNKNOWN_ACTION",

                    riskScore: null,

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

                            valid: true,

                            reason:
                                "FAIL_CLOSED_CRITICAL"
                        }),

                    evaluatedAt:
                        Date.now(),

                    engineVersion:
                        this.version
                };


            return this.attachDecisionIntegrity(
                failClosedDecision
            );
        }


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


        /*
         * Requirement inconsistency
         * also fails closed.
         */

        if (
            !requirementValidation.valid
        ) {

            const criticalRequirements =
                this.getRequirements(
                    "CRITICAL",
                    action
                );


            const inconsistentDecision =
                {

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
                            criticalRequirements
                        ),

                    evaluatedAt:
                        Date.now(),

                    engineVersion:
                        this.version
                };


            return this.attachDecisionIntegrity(
                inconsistentDecision
            );
        }


        const decision = {

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
        };


        /*
         * A4.6 integrity is attached
         * after the complete decision exists.
         */

        return this.attachDecisionIntegrity(
            decision
        );
    }
}
