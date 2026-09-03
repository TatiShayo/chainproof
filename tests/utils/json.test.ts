import { describe, it, expect } from 'vitest';
import { safeJsonParse, safeJsonStringify } from '../../src/utils/json.js';

describe('JSON Utilities', () => {
  it('should parse valid JSON strings', () => {
    const raw = '{"name":"chainproof","version":"1.0.0","active":true}';
    const res = safeJsonParse<{ name: string; version: string; active: boolean }>(raw);
    expect(res.success).toBe(true);
    expect(res.data?.name).toBe('chainproof');
    expect(res.data?.version).toBe('1.0.0');
    expect(res.data?.active).toBe(true);
  });

  it('should strip UTF-8 BOM if present in string', () => {
    const raw = '\uFEFF{"bom":true}';
    const res = safeJsonParse(raw);
    expect(res.success).toBe(true);
    expect(res.data).toEqual({ bom: true });
  });

  it('should parse UTF-8 Buffer with BOM', () => {
    const buf = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"bom":"utf8"}', 'utf8')]);
    const res = safeJsonParse(buf);
    expect(res.success).toBe(true);
    expect(res.data).toEqual({ bom: 'utf8' });
  });

  it('should parse UTF-16LE Buffer with BOM', () => {
    const content = Buffer.from('{"bom":"utf16le"}', 'utf16le');
    const buf = Buffer.concat([Buffer.from([0xff, 0xfe]), content]);
    const res = safeJsonParse(buf);
    expect(res.success).toBe(true);
    expect(res.data).toEqual({ bom: 'utf16le' });
  });

  it('should parse UTF-16BE Buffer with BOM', () => {
    const str = '{"bom":"utf16be"}';
    const beBuf = Buffer.alloc(2 + str.length * 2);
    beBuf[0] = 0xfe;
    beBuf[1] = 0xff;
    for (let i = 0; i < str.length; i++) {
      beBuf.writeUInt16BE(str.charCodeAt(i), 2 + i * 2);
    }
    const res = safeJsonParse(beBuf);
    expect(res.success).toBe(true);
    expect(res.data).toEqual({ bom: 'utf16be' });
  });

  it('should recover from trailing commas in JSON', () => {
    const raw = '{"items": [1, 2, 3, ], "config": { "debug": true, }, }';
    const res = safeJsonParse(raw);
    expect(res.success).toBe(true);
    expect(res.data).toEqual({ items: [1, 2, 3], config: { debug: true } });
  });

  it('should handle unparseable malformed JSON gracefully', () => {
    const raw = 'This is definitely not JSON {{{{';
    const res = safeJsonParse(raw);
    expect(res.success).toBe(false);
    expect(res.error).toBeDefined();
  });

  it('should handle empty input', () => {
    const res = safeJsonParse('   ');
    expect(res.success).toBe(false);
    expect(res.error).toContain('empty');
  });

  it('should safely stringify objects with circular references', () => {
    const obj: any = { name: 'circular-test' };
    obj.self = obj;
    const str = safeJsonStringify(obj);
    expect(str).toContain('[Circular]');
    expect(str).toContain('"name": "circular-test"');
  });
});
