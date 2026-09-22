// RAIVEN Risk Engine v0.3
// Stage A4.3
//
// Risk Context & Action Classification
//
// IMPORTANT:
// RiskEngine NEVER grants permission.
// RiskEngine NEVER executes actions.
// RiskEngine ONLY evaluates and classifies risk.


export class RiskEngine {

    constructor() {

        this.version = "0.3";

    }


    // ==================================================
    // RISK LEVELS
    // ==================================================

    static LEVELS = Object.freeze({

        LOW: 1,

        MEDIUM: 2,

        HIGH: 3,

        CRITICAL: 4

    });


    // ==================================================
    // ALLOWED VALUES
    // ==================================================

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


    // ==================================================
    // VALIDATE ACTION
    // ==================================================

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


    // ==================================================
    // CLASSIFY ACTION CONTEXT
    // ==================================================

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


    // ==================================================
    // CALCULATE SCORE
    // ==================================================

    calculateScore(action) {

        let score = 0;


        // ----------------------------------------------
        // PERMISSION
        // ----------------------------------------------

        if (
            action.permission &&
            action.permission !== "NONE"
        ) {

            score += 1;

        }


        // ----------------------------------------------
        // DATA SENSITIVITY
        // ----------------------------------------------

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


        // ----------------------------------------------
        // EXTERNAL EFFECT
        // ----------------------------------------------

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


        // ----------------------------------------------
        // REVERSIBILITY
        // ----------------------------------------------

        if (
            action.reversibility === "IRREVERSIBLE"
        ) {

            score += 2;

        }


        // ----------------------------------------------
        // USER IMPACT
        // ----------------------------------------------

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


        // ----------------------------------------------
        // SCOPE
        // ----------------------------------------------

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


        // ----------------------------------------------
        // ACTION TYPE
        // ----------------------------------------------

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


        // ----------------------------------------------
        // REMOTE EXECUTION
        // ----------------------------------------------

        if (
            action.executionMode === "REMOTE"
        ) {

            score += 1;

        }


        // ----------------------------------------------
        // CONTINUOUS EXECUTION
        // ----------------------------------------------

        if (
            action.duration === "CONTINUOUS"
        ) {

            score += 1;

        }


        return score;

    }


    // ==================================================
    // BASE CLASSIFICATION
    // ==================================================

    classifyScore(score) {

        if (
            score <= 1
        ) {

            return "LOW";

        }


        if (
            score <= 3
        ) {

            return "MEDIUM";

        }


        if (
            score <= 6
        ) {

            return "HIGH";

        }


        return "CRITICAL";

    }


    // ==================================================
    // RISK FLOORS
    // ==================================================

    applyRiskFloor(
        action,
        currentLevel
    ) {

        let level =
            RiskEngine.LEVELS[
                currentLevel
            ];


        // Sensitive + Network
        if (
            action.dataSensitivity === "SENSITIVE" &&
            action.externalEffect === "NETWORK"
        ) {

            level = Math.max(

                level,

                RiskEngine.LEVELS.HIGH

            );

        }


        // Irreversible
        if (
            action.reversibility === "IRREVERSIBLE"
        ) {

            level = Math.max(

                level,

                RiskEngine.LEVELS.HIGH

            );

        }


        // Irreversible + High impact
        if (
            action.reversibility === "IRREVERSIBLE" &&
            action.userImpact === "HIGH"
        ) {

            level = Math.max(

                level,

                RiskEngine.LEVELS.CRITICAL

            );

        }


        // Persistent + Sensitive
        if (
            action.scope === "PERSISTENT" &&
            action.dataSensitivity === "SENSITIVE"
        ) {

            level = Math.max(

                level,

                RiskEngine.LEVELS.HIGH

            );

        }


        // Delete
        if (
            action.actionType === "DELETE"
        ) {

            level = Math.max(

                level,

                RiskEngine.LEVELS.HIGH

            );

        }


        // Execute remotely
        if (
            action.actionType === "EXECUTE" &&
            action.executionMode === "REMOTE"
        ) {

            level = Math.max(

                level,

                RiskEngine.LEVELS.HIGH

            );

        }


        // Sensitive continuous access
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


    // ==================================================
    // SECURITY REQUIREMENTS
    // ==================================================

    getRequirements(riskLevel) {

        switch (riskLevel) {

            case "LOW":

                return {

                    requiresConfirmation: false,

                    requiresExplicitConfirmation: false,

                    requiresAdditionalAuthentication: false,

                    requiresAuditLog: true

                };


            case "MEDIUM":

                return {

                    requiresConfirmation: true,

                    requiresExplicitConfirmation: false,

                    requiresAdditionalAuthentication: false,

                    requiresAuditLog: true

                };


            case "HIGH":

                return {

                    requiresConfirmation: true,

                    requiresExplicitConfirmation: true,

                    requiresAdditionalAuthentication: false,

                    requiresAuditLog: true

                };


            case "CRITICAL":

                return {

                    requiresConfirmation: true,

                    requiresExplicitConfirmation: true,

                    requiresAdditionalAuthentication: true,

                    requiresAuditLog: true

                };


            default:

                return {

                    requiresConfirmation: true,

                    requiresExplicitConfirmation: true,

                    requiresAdditionalAuthentication: true,

                    requiresAuditLog: true

                };

        }

    }


    // ==================================================
    // FULL EVALUATION
    // ==================================================

    evaluate(action) {

        const validation =
            this.validateAction(
                action
            );


        // ----------------------------------------------
        // FAIL CLOSED
        // ----------------------------------------------

        if (
            !validation.valid
        ) {

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
                    this.getRequirements(
                        "CRITICAL"
                    ),

                evaluatedAt:
                    Date.now(),

                engineVersion:
                    this.version

            });

        }


        // ----------------------------------------------
        // CONTEXT
        // ----------------------------------------------

        const context =
            this.classifyContext(
                action
            );


        // ----------------------------------------------
        // SCORE
        // ----------------------------------------------

        const score =
            this.calculateScore(
                action
            );


        // ----------------------------------------------
        // BASE LEVEL
        // ----------------------------------------------

        const baseLevel =
            this.classifyScore(
                score
            );


        // ----------------------------------------------
        // FINAL LEVEL
        // ----------------------------------------------

        const riskLevel =
            this.applyRiskFloor(

                action,

                baseLevel

            );


        // ----------------------------------------------
        // REQUIREMENTS
        // ----------------------------------------------

        const requirements =
            this.getRequirements(
                riskLevel
            );


        // ----------------------------------------------
        // IMMUTABLE RESULT
        // ----------------------------------------------

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
