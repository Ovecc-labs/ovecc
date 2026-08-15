export const client = { query: (sql) => sql };

export function findOrders() {
  return client.query("SELECT id FROM orders");
}
