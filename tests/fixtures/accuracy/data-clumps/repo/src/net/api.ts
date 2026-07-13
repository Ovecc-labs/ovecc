export function connect(host: string, port: number, timeout: number): string {
  return host + String(port) + String(timeout);
}

export function reconnect(host: string, port: number, timeout: number, retries: number): string {
  return host + String(port) + String(timeout) + String(retries);
}

export function healthcheck(timeout: number, host: string, port: number): boolean {
  return timeout > 0 && host.length > 0 && port > 0;
}

export function ping(host: string, port: number): boolean {
  return host.length > 0 && port > 0;
}

export function trace(host: string, port: number): boolean {
  return host.length > 0 && port > 0;
}
