export class Transport {
  m01(): number { return 1; }
  m02(): number { return 2; }
  m03(): number { return 3; }
  m04(): number { return 4; }
  m05(): number { return 5; }
  m06(): number { return 6; }
  m07(): number { return 7; }
  m08(): number { return 8; }
  m09(): number { return 9; }
  m10(): number { return 10; }
  m11(): number { return 11; }
  m12(): number { return 12; }
  m13(): number { return 13; }
  m14(): number { return 14; }
  m15(): number { return 15; }
  m16(): number { return 16; }
  m17(): number { return 17; }
  m18(): number { return 18; }
  m19(): number { return 19; }
  m20(): number { return 20; }
  m21(): number { return 21; }
}

export function connect(host: string, port: number, timeout: number): string {
  return `${host}:${port}:${timeout}`;
}

export function reconnect(host: string, port: number, timeout: number, retries: number): string {
  return `${host}:${port}:${timeout}:${retries}`;
}

export function healthcheck(timeout: number, host: string, port: number): boolean {
  return timeout > 0 && host.length > 0 && port > 0;
}
