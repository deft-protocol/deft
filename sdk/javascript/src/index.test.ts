/**
 * Tests for DEFT JavaScript/TypeScript SDK
 * 
 * Run with: npm test
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
    AuthenticationError,
    DeftClient,
    DeftError,
    TransferError,
    TransferPriority,
    TransferStatus,
} from './index';

describe('TransferPriority', () => {
  it('should have correct values', () => {
    expect(TransferPriority.URGENT).toBe('urgent');
    expect(TransferPriority.NORMAL).toBe('normal');
    expect(TransferPriority.BATCH).toBe('batch');
  });
});

describe('TransferStatus', () => {
  it('should have correct values', () => {
    expect(TransferStatus.ACTIVE).toBe('active');
    expect(TransferStatus.INTERRUPTED).toBe('interrupted');
    expect(TransferStatus.COMPLETE).toBe('complete');
    expect(TransferStatus.FAILED).toBe('failed');
    expect(TransferStatus.QUEUED).toBe('queued');
  });
});

describe('DeftError', () => {
  it('should create error with message', () => {
    const error = new DeftError('Test error');
    expect(error.message).toBe('Test error');
    expect(error.name).toBe('DeftError');
  });
});

describe('AuthenticationError', () => {
  it('should extend DeftError', () => {
    const error = new AuthenticationError('Invalid key');
    expect(error).toBeInstanceOf(DeftError);
    expect(error.name).toBe('AuthenticationError');
  });
});

describe('TransferError', () => {
  it('should store transfer ID', () => {
    const error = new TransferError('Transfer failed', 'txn_123');
    expect(error.message).toBe('Transfer failed');
    expect(error.transferId).toBe('txn_123');
    expect(error.name).toBe('TransferError');
  });

  it('should work without transfer ID', () => {
    const error = new TransferError('Transfer failed');
    expect(error.transferId).toBeUndefined();
  });
});

describe('DeftClient', () => {
  describe('constructor', () => {
    it('should use default values', () => {
      const client = new DeftClient();
      expect(client['baseUrl']).toBe('http://127.0.0.1:7752');
      expect(client['apiKey']).toBeUndefined();
      expect(client['timeout']).toBe(30000);
    });

    it('should accept custom options', () => {
      const client = new DeftClient({
        baseUrl: 'http://custom:8080/',
        apiKey: 'test-key',
        timeout: 60000,
      });
      expect(client['baseUrl']).toBe('http://custom:8080');
      expect(client['apiKey']).toBe('test-key');
      expect(client['timeout']).toBe(60000);
    });

    it('should strip trailing slash from URL', () => {
      const client = new DeftClient({ baseUrl: 'http://localhost:7752/' });
      expect(client['baseUrl']).toBe('http://localhost:7752');
    });
  });

  describe('request method', () => {
    let client: DeftClient;

    beforeEach(() => {
      client = new DeftClient({ apiKey: 'test-key' });
    });

    it('should throw AuthenticationError on 401', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 401,
        ok: false,
        json: () => Promise.resolve({ error: 'Invalid API key' }),
      });

      await expect(client['request']('GET', '/api/status')).rejects.toThrow(
        AuthenticationError
      );
    });

    it('should throw DeftError on other errors', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 500,
        ok: false,
        json: () => Promise.resolve({ error: 'Server error' }),
      });

      await expect(client['request']('GET', '/api/status')).rejects.toThrow(
        DeftError
      );
    });

    it('should return data on success', async () => {
      const mockData = { status: 'ok' };
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: () => Promise.resolve(mockData),
      });

      const result = await client['request']('GET', '/api/health');
      expect(result).toEqual(mockData);
    });

    it('should include API key in headers', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: () => Promise.resolve({}),
      });

      await client['request']('GET', '/api/test');

      expect(global.fetch).toHaveBeenCalledWith(
        'http://127.0.0.1:7752/api/test',
        expect.objectContaining({
          headers: expect.objectContaining({
            'X-API-Key': 'test-key',
          }),
        })
      );
    });
  });

  describe('API methods', () => {
    let client: DeftClient;

    beforeEach(() => {
      client = new DeftClient({ apiKey: 'test-key' });
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: () => Promise.resolve({}),
      });
    });

    it('health() should call correct endpoint', async () => {
      await client.health();
      expect(global.fetch).toHaveBeenCalledWith(
        'http://127.0.0.1:7752/api/health',
        expect.any(Object)
      );
    });

    it('status() should call correct endpoint', async () => {
      await client.status();
      expect(global.fetch).toHaveBeenCalledWith(
        'http://127.0.0.1:7752/api/status',
        expect.any(Object)
      );
    });

    it('listTransfers() should call correct endpoint', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: () => Promise.resolve([]),
      });

      const transfers = await client.listTransfers();
      expect(transfers).toEqual([]);
    });

    it('pauseTransfer() should call correct endpoint', async () => {
      await client.pauseTransfer('txn_123');
      expect(global.fetch).toHaveBeenCalledWith(
        'http://127.0.0.1:7752/api/transfers/txn_123/interrupt',
        expect.objectContaining({ method: 'POST' })
      );
    });

    it('resumeTransfer() should call correct endpoint', async () => {
      await client.resumeTransfer('txn_123');
      expect(global.fetch).toHaveBeenCalledWith(
        'http://127.0.0.1:7752/api/transfers/txn_123/resume',
        expect.objectContaining({ method: 'POST' })
      );
    });

    it('connect() should throw on failure', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: () => Promise.resolve({ success: false, error: 'Connection refused' }),
      });

      await expect(client.connect('server', 'identity')).rejects.toThrow(
        DeftError
      );
    });

    it('push() should throw TransferError on failure', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: () => Promise.resolve({ success: false, error: 'Push failed' }),
      });

      await expect(
        client.push('/path/to/file', 'virtual-file')
      ).rejects.toThrow(TransferError);
    });

    it('push() should include priority', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: () => Promise.resolve({ success: true, transfer_id: 'txn_1', bytes: 100 }),
      });

      await client.push('/file', 'vf', { priority: TransferPriority.URGENT });

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: expect.stringContaining('"priority":"urgent"'),
        })
      );
    });
  });

  describe('init method', () => {
    it('should fetch API key when not provided', async () => {
      const client = new DeftClient();
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: () => Promise.resolve({ api_key: 'fetched-key' }),
      });

      await client.init();

      expect(client['apiKey']).toBe('fetched-key');
    });

    it('should not fetch when key already set', async () => {
      const client = new DeftClient({ apiKey: 'preset-key' });
      global.fetch = vi.fn();

      await client.init();

      expect(global.fetch).not.toHaveBeenCalled();
    });
  });

  describe('rotateKey method', () => {
    it('should update internal key after rotation', async () => {
      const client = new DeftClient({ apiKey: 'old-key' });
      global.fetch = vi.fn().mockResolvedValue({
        status: 200,
        ok: true,
        json: () => Promise.resolve({ api_key: 'new-key' }),
      });

      const newKey = await client.rotateKey();

      expect(newKey).toBe('new-key');
      expect(client['apiKey']).toBe('new-key');
    });
  });
});

// Integration tests (require running DEFT daemon)
describe.skip('Integration Tests', () => {
  it('should complete full workflow', async () => {
    const client = new DeftClient();
    await client.init();

    const status = await client.status();
    expect(status.version).toBeDefined();

    const transfers = await client.listTransfers();
    expect(Array.isArray(transfers)).toBe(true);
  });
});
