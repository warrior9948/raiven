// RAIVEN Risk Engine v0.5
// Stage A4.5
//
// Risk Decision Consistency
//
// IMPORTANT:
// RiskEngine NEVER grants permission.
// RiskEngine NEVER executes actions.
// RiskEngine ONLY evaluates risk,
// determines security requirements,
// and verifies requirement consistency.

export class RiskEngine {

    constructor() {
        this.version = "0.5";
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


    /*
     * A4.5
     *
     * Security controls ordered from
     * weakest to strongest.
     *
     * A stronger risk level must never
     * lose a control required by a
     * weaker risk level.
     */

    static REQUIREMENT_ORDER = Object.freeze({

        requiresConfirmation: 1,

        requiresExplicitConfirmation: 2,

        requiresAdditionalAuthentication: 3,

        requiresAuditLog: 1,

        requiresIsolation: 4,

        requiresPreExecutionReview: 3,

        requiresEmergencyProtection: 3
    });


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
     * A4.4
     *
     * Determines required security
     * controls.
     *
     * DOES NOT enforce them.
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
            action.externalEffect === "NETWORK" &&
            action.actionType === "TRANSMIT"
        ) {

            requirements
                .requiresExplicitConfirmation = true;

            requirements
                .requiresPreExecutionReview = true;
        }


        /*
         * CRITICAL safety invariant
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
     *
     * Converts a requirement set into
     * a comparable security profile.
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


    /*
     * A4.5
     *
     * Checks whether every required
     * security control is present.
     */

    validateRequirementSet(
        requirements
    ) {

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

        for (
            const field of fields
        ) {

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

        /*
         * Explicit confirmation logically
         * requires ordinary confirmation.
         */

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

        /*
         * Additional authentication is
         * only meaningful when confirmation
         * exists.
         */

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

        /*
         * Isolation requires pre-execution
         * review.
         */

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

        /*
         * Emergency protection must always
         * have an audit trail.
         */

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


    /*
     * A4.5
     *
     * Compares two requirement sets.
     *
     * Returns false if the higher-risk
     * requirement set loses a protection.
     */

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
                reason: "INVALID_REQUIREMENT_SET"
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
            reason: "CONSISTENT"
        };
    }


    /*
     * A4.5
     *
     * Verifies that the complete
     * LOW → MEDIUM → HIGH → CRITICAL
     * security progression is monotonic.
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


    evaluate(action) {

        const validation =
            this.validateAction(action);


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

            return Object.freeze({

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
            });
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


        /*
         * A4.5 consistency validation
         */

        const requirementValidation =
            this.validateRequirementSet(
                requirements
            );


        /*
         * If the engine generates an
         * internally inconsistent security
         * profile, fail closed.
         */

        if (
            !requirementValidation.valid
        ) {

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
