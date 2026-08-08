/**
 * Imports legacy, which is consumed_by nothing, and never reaches auth, which
 * every api file must. Both MUST be flagged.
 */
import { users } from "../repository/users";
import { legacyStore } from "../legacy/store";

export const prices = [users, legacyStore];
