// RAIVEN Risk Engine v0.4
// Stage A4.4
//
// Security Requirement Escalation
//
// IMPORTANT:
// RiskEngine NEVER grants permission.
// RiskEngine NEVER executes actions.
// RiskEngine ONLY evaluates risk
// and determines required security controls.

export class RiskEngine {

    constructor() {
        this.version = "0.4";
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
     * Determines the security controls
     * required before an action may proceed.
     *
     * This method DOES NOT enforce them.
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


        /*
         * Risk-level requirements
         */

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
         * Context-aware escalation
         */

        if (
            action
                .actionType === "EXECUTE" &&
            action
                .executionMode === "REMOTE"
        ) {

            requirements
                .requiresExplicitConfirmation = true;

            requirements
                .requiresPreExecutionReview = true;

            requirements
                .requiresEmergencyProtection = true;
        }


        if (
            action
                .actionType === "DELETE"
        ) {

            requirements
                .requiresExplicitConfirmation = true;

            requirements
                .requiresPreExecutionReview = true;

            requirements
                .requiresEmergencyProtection = true;
        }


        if (
            action
                .dataSensitivity === "SENSITIVE" &&
            action
                .duration === "CONTINUOUS"
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
            action
                .externalEffect === "NETWORK" &&
            action
                .actionType === "TRANSMIT"
        ) {

            requirements
                .requiresExplicitConfirmation = true;

            requirements
                .requiresPreExecutionReview = true;
        }


        /*
         * Final safety rule:
         *
         * Any CRITICAL action must have
         * every security control enabled.
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

            evaluatedAt:
                Date.now(),

            engineVersion:
                this.version
        });
    }
}
