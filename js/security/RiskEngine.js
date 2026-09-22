// RAIVEN Risk Engine v0.1
// Stage A4.1
//
// Purpose:
// Determine the security risk of a requested action.
//
// IMPORTANT:
// RiskEngine NEVER grants permission.
// RiskEngine NEVER executes actions.
// RiskEngine ONLY evaluates risk and returns
// security requirements.


export class RiskEngine {

    constructor() {

        this.version = "0.1";

    }


    // --------------------------------------------------
    // RISK LEVELS
    // --------------------------------------------------

    static LEVELS = {

        LOW: 1,

        MEDIUM: 2,

        HIGH: 3,

        CRITICAL: 4

    };


    // --------------------------------------------------
    // RISK EVALUATION
    // --------------------------------------------------

    evaluate(action) {

        if (!action || typeof action !== "object") {

            return {

                allowed: false,

                reason: "INVALID_ACTION",

                riskLevel: "CRITICAL"

            };

        }


        const permission =
            action.permission || "NONE";


        const dataSensitivity =
            action.dataSensitivity || "PUBLIC";


        const externalEffect =
            action.externalEffect || "NONE";


        const reversibility =
            action.reversibility || "REVERSIBLE";


        const userImpact =
            action.userImpact || "LOW";


        const scope =
            action.scope || "ONCE";


        // --------------------------------------------------
        // CALCULATE RISK
        // --------------------------------------------------

        let riskScore = 0;


        // Permission factor

        if (permission !== "NONE") {

            riskScore += 1;

        }


        // Data sensitivity

        if (
            dataSensitivity === "PRIVATE"
        ) {

            riskScore += 1;

        }


        if (
            dataSensitivity === "SENSITIVE"
        ) {

            riskScore += 2;

        }


        // External effect

        if (
            externalEffect === "DEVICE"
        ) {

            riskScore += 1;

        }


        if (
            externalEffect === "NETWORK"
        ) {

            riskScore += 2;

        }


        // Reversibility

        if (
            reversibility === "IRREVERSIBLE"
        ) {

            riskScore += 2;

        }


        // User impact

        if (
            userImpact === "MEDIUM"
        ) {

            riskScore += 1;

        }


        if (
            userImpact === "HIGH"
        ) {

            riskScore += 2;

        }


        // Scope

        if (
            scope === "SESSION"
        ) {

            riskScore += 1;

        }


        if (
            scope === "PERSISTENT"
        ) {

            riskScore += 2;

        }


        // --------------------------------------------------
        // DETERMINE RISK LEVEL
        // --------------------------------------------------

        let riskLevel;


        if (riskScore <= 1) {

            riskLevel = "LOW";

        }
        else if (riskScore <= 3) {

            riskLevel = "MEDIUM";

        }
        else if (riskScore <= 6) {

            riskLevel = "HIGH";

        }
        else {

            riskLevel = "CRITICAL";

        }


        // --------------------------------------------------
        // SECURITY REQUIREMENTS
        // --------------------------------------------------

        const requiresConfirmation =
            riskLevel !== "LOW";


        const requiresExplicitConfirmation =
            riskLevel === "HIGH" ||
            riskLevel === "CRITICAL";


        const requiresAdditionalAuthentication =
            riskLevel === "CRITICAL";


        // --------------------------------------------------
        // FINAL RESULT
        // --------------------------------------------------

        return {

            allowed: true,

            action:
                action.name || "UNKNOWN_ACTION",

            permission,

            riskScore,

            riskLevel,

            requirements: {

                requiresConfirmation,

                requiresExplicitConfirmation,

                requiresAdditionalAuthentication

            },

            evaluatedAt:
                Date.now(),

            engineVersion:
                this.version

        };

    }

}
