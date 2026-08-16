// Every type below is the public API surface of this module: the options a
// caller passes, the value it gets back, the element type of a list it reads.
// None is imported by name, and all three are needed to annotate a variable.
export interface CreateHttpServerOptions {
  port: number;
}

export type HttpApp = {
  close(): void;
};

export interface DeadLetterRecord {
  id: string;
}

// Named only by an unexported declaration, so it is genuinely internal.
export type OrphanedOptions = {
  unused: boolean;
};

export function createHttpServer(options: CreateHttpServerOptions): HttpApp {
  return { close() {} };
}

export function listDeadLetters(): DeadLetterRecord[] {
  return [{ id: `${1}` }];
}
