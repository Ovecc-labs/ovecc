const app = { get: (path, handler) => handler };

export function getOrder(req, res) {
  return res.json({ id: req.params.id });
}

app.get("/orders/:id", getOrder);
