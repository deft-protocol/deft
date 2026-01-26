/**
 * DEFT Protocol JavaScript/TypeScript SDK
 * Delta-Enabled File Transfer Client
 */

export enum TransferPriority {
  URGENT = "urgent",
  NORMAL = "normal",
  BATCH = "batch",
}

export enum TransferStatus {
  ACTIVE = "active",
  INTERRUPTED = "interrupted",
  COMPLETE = "complete",
  FAILED = "failed",
  QUEUED = "queued",
}

export interface Transfer {
  id: string;
  virtual_file: string;
  partner_id: string;
  direction: "send" | "receive";
  status: TransferStatus;
  bytes_transferred: number;
  total_bytes: number;
  progress_percent: number;
}

export interface VirtualFile {
  name: string;
  path: string;
  direction: "send" | "receive";
  partner_id?: string;
  size?: number;
}

export interface Partner {
  id: string;
  allowed_certs: string[];
  virtual_files: VirtualFile[];
}

export interface TrustedServer {
  name: string;
  address: string;
  cert_fingerprint?: string;
}

export interface DeftClientOptions {
  baseUrl?: string;
  apiKey?: string;
  timeout?: number;
}

export class DeftError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeftError";
  }
}

export class AuthenticationError extends DeftError {
  constructor(message: string) {
    super(message);
    this.name = "AuthenticationError";
  }
}

export class TransferError extends DeftError {
  transferId?: string;

  constructor(message: string, transferId?: string) {
    super(message);
    this.name = "TransferError";
    this.transferId = transferId;
  }
}

export class DeftClient {
  private baseUrl: string;
  private apiKey?: string;
  private timeout: number;

  constructor(options: DeftClientOptions = {}) {
    this.baseUrl = (options.baseUrl || "http://127.0.0.1:7752").replace(
      /\/$/,
      ""
    );
    this.apiKey = options.apiKey;
    this.timeout = options.timeout || 30000;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    if (this.apiKey) {
      headers["X-API-Key"] = this.apiKey;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.status === 401) {
        throw new AuthenticationError("Invalid or missing API key");
      }

      const data = await response.json();

      if (!response.ok) {
        throw new DeftError(data.error || `HTTP ${response.status}`);
      }

      return data as T;
    } catch (error) {
      clearTimeout(timeoutId);
      if (error instanceof DeftError) throw error;
      throw new DeftError(`Request failed: ${error}`);
    }
  }

  /**
   * Initialize client by fetching API key (localhost only)
   */
  async init(): Promise<void> {
    if (!this.apiKey) {
      const data = await this.request<{ api_key?: string }>(
        "GET",
        "/api/auth/key"
      );
      this.apiKey = data.api_key;
    }
  }

  // ============ System ============

  async health(): Promise<{ status: string }> {
    return this.request("GET", "/api/health");
  }

  async status(): Promise<{
    version: string;
    uptime_seconds: number;
    active_transfers: number;
  }> {
    return this.request("GET", "/api/status");
  }

  async metrics(): Promise<Record<string, unknown>> {
    return this.request("GET", "/api/metrics");
  }

  // ============ Authentication ============

  async rotateKey(): Promise<string> {
    const data = await this.request<{ api_key: string }>(
      "POST",
      "/api/auth/rotate"
    );
    this.apiKey = data.api_key;
    return data.api_key;
  }

  // ============ Transfers ============

  async listTransfers(): Promise<Transfer[]> {
    return this.request("GET", "/api/transfers");
  }

  async getTransfer(transferId: string): Promise<Transfer> {
    return this.request("GET", `/api/transfers/${transferId}`);
  }

  async cancelTransfer(transferId: string): Promise<void> {
    await this.request("DELETE", `/api/transfers/${transferId}`);
  }

  async pauseTransfer(transferId: string): Promise<{ status: string }> {
    return this.request("POST", `/api/transfers/${transferId}/interrupt`);
  }

  async resumeTransfer(transferId: string): Promise<{ status: string }> {
    return this.request("POST", `/api/transfers/${transferId}/resume`);
  }

  async retryTransfer(transferId: string): Promise<Transfer> {
    return this.request("POST", `/api/transfers/${transferId}/retry`);
  }

  async history(): Promise<Transfer[]> {
    return this.request("GET", "/api/history");
  }

  // ============ Client Operations ============

  async connect(
    serverName: string,
    ourIdentity: string
  ): Promise<{ success: boolean; virtual_files: VirtualFile[] }> {
    const data = await this.request<{
      success: boolean;
      virtual_files: VirtualFile[];
      error?: string;
    }>("POST", "/api/client/connect", {
      server_name: serverName,
      our_identity: ourIdentity,
    });

    if (!data.success) {
      throw new DeftError(data.error || "Connection failed");
    }

    return data;
  }

  async push(
    filePath: string,
    virtualFile: string,
    options: { partnerId?: string; priority?: TransferPriority } = {}
  ): Promise<{ success: boolean; transfer_id: string; bytes: number }> {
    const data = await this.request<{
      success: boolean;
      transfer_id: string;
      bytes: number;
      error?: string;
    }>("POST", "/api/client/push", {
      file_path: filePath,
      virtual_file: virtualFile,
      partner_id: options.partnerId,
      priority: options.priority || TransferPriority.NORMAL,
    });

    if (!data.success) {
      throw new TransferError(data.error || "Push failed", data.transfer_id);
    }

    return data;
  }

  async pull(
    virtualFile: string,
    outputPath: string,
    options: { priority?: TransferPriority } = {}
  ): Promise<{ success: boolean; bytes: number }> {
    const data = await this.request<{
      success: boolean;
      bytes: number;
      error?: string;
    }>("POST", "/api/client/pull", {
      virtual_file: virtualFile,
      output_path: outputPath,
      priority: options.priority || TransferPriority.NORMAL,
    });

    if (!data.success) {
      throw new TransferError(data.error || "Pull failed");
    }

    return data;
  }

  // ============ Virtual Files ============

  async listVirtualFiles(): Promise<VirtualFile[]> {
    return this.request("GET", "/api/virtual-files");
  }

  async createVirtualFile(
    name: string,
    path: string,
    direction: "send" | "receive",
    partnerId?: string
  ): Promise<VirtualFile> {
    return this.request("POST", "/api/virtual-files", {
      name,
      path,
      direction,
      partner_id: partnerId,
    });
  }

  async deleteVirtualFile(name: string): Promise<void> {
    await this.request("DELETE", `/api/virtual-files/${name}`);
  }

  // ============ Partners ============

  async listPartners(): Promise<Partner[]> {
    return this.request("GET", "/api/partners");
  }

  async createPartner(
    id: string,
    allowedCerts?: string[]
  ): Promise<Partner> {
    return this.request("POST", "/api/partners", {
      id,
      allowed_certs: allowedCerts,
    });
  }

  async deletePartner(id: string): Promise<void> {
    await this.request("DELETE", `/api/partners/${id}`);
  }

  // ============ Trusted Servers ============

  async listTrustedServers(): Promise<TrustedServer[]> {
    return this.request("GET", "/api/trusted-servers");
  }

  async addTrustedServer(
    name: string,
    address: string,
    certFingerprint?: string
  ): Promise<TrustedServer> {
    return this.request("POST", "/api/trusted-servers", {
      name,
      address,
      cert_fingerprint: certFingerprint,
    });
  }

  async removeTrustedServer(name: string): Promise<void> {
    await this.request("DELETE", `/api/trusted-servers/${name}`);
  }
}

export default DeftClient;
