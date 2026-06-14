import { User } from "./model";

export function getUser(id: string): User {
  return { id, name: "demo", status: "active" };
}
