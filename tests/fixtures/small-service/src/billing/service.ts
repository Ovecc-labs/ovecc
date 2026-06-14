import { User } from "../user/model";
import express from "express";

export function createInvoice(user: User): string {
  return `invoice-for-${user.id}`;
}

export const app = express();
