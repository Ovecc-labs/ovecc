/**
 * Reaches db directly, which only repository may touch, and telemetry, which
 * its own cannot_depend_on forbids. Both MUST be flagged. The auth and
 * repository imports are legal and must NOT be.
 */
import { guard } from "../auth/guard";
import { users } from "../repository/users";
import { pool } from "../db/pool";
import { sdk } from "../telemetry/sdk";

export const orders = [guard, users, pool, sdk];
