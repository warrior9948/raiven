// RAIVEN Risk Engine v0.2
// Stage A4.2
//
// Purpose:
// Strong, deterministic risk classification.
//
// IMPORTANT:
// RiskEngine NEVER grants permission.
// RiskEngine NEVER executes actions.
// RiskEngine ONLY evaluates risk and
// security requirements.


export class RiskEngine {

    constructor() {

        this.version = "0.2";

    }


    // --------------------------------------------------
    // RISK LEVELS
    // --------------------------------------------------

    static LEVELS = Object.freeze({

        LOW: 1,

        MEDIUM: 2,

        HIGH: 3,

        CRITICAL: 4

    });


    // --------------------------------------------------
    // ALLOWED VALUES
    // --------------------------------------------------

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
        ]

    });


    // --------------------------------------------------
    // VALIDATE ACTION
    // --------------------------------------------------

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


        const fields = [
            "dataSensitivity",
            "externalEffect",
            "reversibility",
            "userImpact",
            "scope"
        ];


        for (const field of fields) {

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


    // --------------------------------------------------
    // CALCULATE SCORE
    // --------------------------------------------------

    calculateScore(action) {

        let score = 0;


        // Permission

        if (
            action.permission &&
            action.permission !== "NONE"
        ) {

            score += 1;

        }


        // Data sensitivity

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


        // External effect

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


        // Reversibility

        if (
            action.reversibility === "IRREVERSIBLE"
        ) {

            score += 2;

        }


        // User impact

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


        // Scope

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


        return score;

    }


    // --------------------------------------------------
    // BASE CLASSIFICATION
    // --------------------------------------------------

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


    // --------------------------------------------------
    // RISK FLOOR
    // --------------------------------------------------

    applyRiskFloor(action, currentLevel) {

        let level =
            RiskEngine.LEVELS[currentLevel];


        /*
        ----------------------------------------------
        SENSITIVE DATA + NETWORK

        Cannot be below HIGH.
        ----------------------------------------------
        */

        if (
            action.dataSensitivity === "SENSITIVE" &&
            action.externalEffect === "NETWORK"
        ) {

            level = Math.max(
                level,
                RiskEngine.LEVELS.HIGH
            );

        }


        /*
        ----------------------------------------------
        IRREVERSIBLE ACTION

        Cannot be below HIGH.
        ----------------------------------------------
        */

        if (
            action.reversibility === "IRREVERSIBLE"
        ) {

            level = Math.max(
                level,
                RiskEngine.LEVELS.HIGH
            );

        }


        /*
        ----------------------------------------------
        IRREVERSIBLE + HIGH IMPACT

        Must be CRITICAL.
        ----------------------------------------------
        */

        if (
            action.reversibility === "IRREVERSIBLE" &&
            action.userImpact === "HIGH"
        ) {

            level = Math.max(
                level,
                RiskEngine.LEVELS.CRITICAL
            );

        }


        /*
        ----------------------------------------------
        PERSISTENT + SENSITIVE

        Must be at least HIGH.
        ----------------------------------------------
        */

        if (
            action.scope === "PERSISTENT" &&
            action.dataSensitivity === "SENSITIVE"
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


    // --------------------------------------------------
    // SECURITY REQUIREMENTS
    // --------------------------------------------------

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


    // --------------------------------------------------
    // FULL EVALUATION
    // --------------------------------------------------

    evaluate(action) {

        const validation =
            this.validateAction(action);


        /*
        ----------------------------------------------
        FAIL CLOSED

        Invalid input becomes CRITICAL.
        ----------------------------------------------
        */

        if (!validation.valid) {

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
                    this.getRequirements(
                        "CRITICAL"
                    ),

                evaluatedAt:
                    Date.now(),

                engineVersion:
                    this.version

            });

        }


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
                riskLevel
            );


        /*
        ----------------------------------------------
        IMMUTABLE RESULT

        The caller cannot directly modify
        the evaluation result.
        ----------------------------------------------
        */

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
