/**
 * Detect a running app on common local ports by attempting a TCP connection,
 * then confirming an HTTP server responds.
 *
 * Interface contract:
 *   const found = await LocalhostDetector.find([3000, 5000, ...]);
 *   // -> { port, baseUrl } | null
 */
import * as net from 'net';
import { createClient } from './httpClient';

export interface DetectedApp {
  port: number;
  baseUrl: string;
}

export class LocalhostDetector {
  static async find(ports: number[]): Promise<DetectedApp | null> {
    for (const port of ports) {
      if (await LocalhostDetector.isPortOpen(port)) {
        const baseUrl = `http://localhost:${port}`;
        if (await LocalhostDetector.isHttp(baseUrl)) {
          return { port, baseUrl };
        }
      }
    }
    return null;
  }

  /** All open ports from the candidate list (for reporting multiple apps). */
  static async findAll(ports: number[]): Promise<DetectedApp[]> {
    const apps: DetectedApp[] = [];
    for (const port of ports) {
      if ((await LocalhostDetector.isPortOpen(port)) && (await LocalhostDetector.isHttp(`http://localhost:${port}`))) {
        apps.push({ port, baseUrl: `http://localhost:${port}` });
      }
    }
    return apps;
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

  private static async isHttp(baseUrl: string): Promise<boolean> {
    try {
      const client = createClient(baseUrl);
      const res = await client.get('/');
      return typeof res.status === 'number';
    } catch {
      return false;
    }
  }
}
