import express from "express";
import { getUser } from "./service";

export const app = express();

app.get("/users/:id", getUser);
app.post("/charge", (req, res) => {
  res.send(getUser(String(req.body.userId)));
});
