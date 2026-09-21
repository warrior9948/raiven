// RAIVEN Action Guard v0.1
// Stage A3

export class ActionGuard {

    constructor(permissionManager, securityState, logger) {

        this.permissionManager = permissionManager;

        this.securityState = securityState;

        this.logger = logger;
    }


    authorize(permission, action) {

        // ---------------------------------------------
        // EMERGENCY STOP
        // ---------------------------------------------

        if (this.securityState.emergencyStopped) {

            this.logger(
                `ACTION BLOCKED: ${action} — Emergency STOP`
            );

            return {
                allowed: false,
                reason: "EMERGENCY_STOP"
            };
        }


        // ---------------------------------------------
        // SECURITY CORE
        // ---------------------------------------------

        if (!this.securityState.active) {

            this.logger(
                `ACTION BLOCKED: ${action} — Security Core inactive`
            );

            return {
                allowed: false,
                reason: "SECURITY_CORE_INACTIVE"
            };
        }


        // ---------------------------------------------
        // PERMISSION CHECK
        // ---------------------------------------------

        if (
            !this.permissionManager.check(permission)
        ) {

            this.logger(
                `ACTION BLOCKED: ${action} — Permission missing`
            );

            return {
                allowed: false,
                reason: "PERMISSION_MISSING"
            };
        }


        // ---------------------------------------------
        // AUTHORIZED
        // ---------------------------------------------

        this.logger(
            `ACTION AUTHORIZED: ${action}`
        );


        return {
            allowed: true,
            reason: "AUTHORIZED"
        };
    }


    consume(permission, action) {

        const consumed =
            this.permissionManager.consume(
                permission
            );


        if (!consumed) {

            this.logger(
                `ACTION CONSUME FAILED: ${action}`
            );

            return false;
        }


        this.logger(
            `PERMISSION CONSUMED: ${permission}`
        );


        return true;
    }


    execute(
        permission,
        action,
        callback
    ) {

        const authorization =
            this.authorize(
                permission,
                action
            );


        // ---------------------------------------------
        // BLOCK
        // ---------------------------------------------

        if (!authorization.allowed) {

            return authorization;
        }


        // ---------------------------------------------
        // EXECUTE
        // ---------------------------------------------

        let result;


        try {

            result = callback();


        } catch (error) {

            this.logger(
                `ACTION FAILED: ${action}`
            );


            return {
                allowed: true,
                executed: false,
                reason: "EXECUTION_ERROR",
                error: error.message
            };
        }


        // ---------------------------------------------
        // CONSUME ONE-TIME PERMISSION
        // ---------------------------------------------

        this.consume(
            permission,
            action
        );


        // ---------------------------------------------
        // SUCCESS
        // ---------------------------------------------

        this.logger(
            `ACTION COMPLETED: ${action}`
        );


        return {

            allowed: true,

            executed: true,

            reason: "SUCCESS",

            result: result

        };
    }
}
