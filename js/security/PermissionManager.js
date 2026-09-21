// RAIVEN Permission Manager v0.1
// Stage A2

export class PermissionManager {

    constructor() {
        this.permissions = new Map();
    }

    request(permission, scope = "ONCE") {
        return {
            permission,
            scope,
            status: "PENDING",
            requestedAt: Date.now()
        };
    }

    grant(permission, scope = "ONCE") {

        const record = {
            permission,
            scope,
            grantedAt: Date.now(),
            usesRemaining: scope === "ONCE" ? 1 : Infinity
        };

        this.permissions.set(permission, record);

        return true;
    }

    deny(permission) {

        this.permissions.delete(permission);

        return false;
    }

    check(permission) {

        const record = this.permissions.get(permission);

        if (!record) {
            return false;
        }

        if (
            record.scope === "ONCE" &&
            record.usesRemaining <= 0
        ) {
            this.permissions.delete(permission);
            return false;
        }

        return true;
    }

    consume(permission) {

        const record = this.permissions.get(permission);

        if (!record) {
            return false;
        }

        if (record.scope === "ONCE") {

            record.usesRemaining--;

            if (record.usesRemaining <= 0) {
                this.permissions.delete(permission);
            }
        }

        return true;
    }

    revoke(permission) {
        this.permissions.delete(permission);
    }

    clearAll() {
        this.permissions.clear();
    }

    get(permission) {
        return this.permissions.get(permission) || null;
    }

    getAll() {
        return Object.fromEntries(this.permissions);
    }
}
