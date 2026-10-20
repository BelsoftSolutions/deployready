/**
 * Detect a local server listening on common ports by attempting a TCP
 * connection. Liveness is a connect only: no HTTP request is ever sent, because
 * every URL path (even "/") would be one the scan has no evidence exists.
 *
 * Interface contract:
 *   const found = await LocalhostDetector.find([3000, 5000, ...]);
 *   // -> { port, baseUrl } | null
 */
import * as net from 'net';

export interface DetectedApp {
  port: number;
  baseUrl: string;
}

export class LocalhostDetector {
  static async find(ports: number[]): Promise<DetectedApp | null> {
    for (const port of ports) {
      if (await LocalhostDetector.isPortOpen(port)) return LocalhostDetector.app(port);
    }
    return null;
  }

  /** All ports from the candidate list that accept a TCP connection. */
  static async findAll(ports: number[]): Promise<DetectedApp[]> {
    const apps: DetectedApp[] = [];
    for (const port of ports) {
      if (await LocalhostDetector.isPortOpen(port)) apps.push(LocalhostDetector.app(port));
    }
    return apps;
  }

  private static app(port: number): DetectedApp {
    return { port, baseUrl: `http://localhost:${port}` };
  }

  private static isPortOpen(port: number, timeoutMs = 400): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      const done = (open: boolean) => {
        socket.destroy();
        resolve(open);
      };
      socket.setTimeout(timeoutMs);
      socket.once('connect', () => done(true));
      socket.once('timeout', () => done(false));
      socket.once('error', () => done(false));
      socket.connect(port, '127.0.0.1');
    });
  }
}
