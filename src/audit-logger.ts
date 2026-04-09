/**
 * Audit logger - appends JSONL entries to a local file.
 *
 * One entry per tool invocation. No rotation in v1.
 */

import * as fs from 'fs';
import * as path from 'path';

export interface AuditEntry {
  /** ISO 8601 timestamp */
  ts: string;
  /** Tool name */
  tool: string;
  /** Decision: "allowed" | "blocked" */
  decision: 'allowed' | 'blocked';
  /** Reason for block, if applicable */
  reason?: string;
  /** User/session identifier (from hook context) */
  user?: string;
  /** Session ID */
  sessionId?: string;
  /** Sensitivity level if detected */
  sensitivity?: 'S1' | 'S2' | 'S3';
  /** Duration of tool execution in ms (if allowed and completed) */
  durationMs?: number;
}

export class AuditLogger {
  private logPath: string;
  private stream: fs.WriteStream | null = null;

  constructor(logDir: string = './logs') {
    fs.mkdirSync(logDir, { recursive: true });
    this.logPath = path.join(logDir, `audit-${new Date().toISOString().slice(0, 10)}.jsonl`);
  }

  /**
   * Write an audit entry. Append-only, fire-and-forget.
   */
  log(entry: AuditEntry): void {
    const line = JSON.stringify(entry) + '\n';
    this.getStream().write(line);
  }

  /**
   * Flush and close the write stream.
   */
  close(): Promise<void> {
    return new Promise((resolve) => {
      if (this.stream) {
        this.stream.end(() => {
          this.stream = null;
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  /** Get current log file path */
  getLogPath(): string {
    return this.logPath;
  }

  private getStream(): fs.WriteStream {
    if (!this.stream) {
      this.stream = fs.createWriteStream(this.logPath, { flags: 'a' });
    }
    return this.stream;
  }
}
