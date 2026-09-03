import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { FleetAggregator } from '../../src/fleet/aggregator.js';
import { FleetConfig } from '../../src/types/index.js';

describe('Fleet Aggregator & Multi-Repository Governance', () => {
  const fleetConfigPath = path.resolve('fleet.config.json');

  it('should parse and evaluate fleet configuration file', () => {
    if (fs.existsSync(fleetConfigPath)) {
      const summary = FleetAggregator.evaluateFleet(fleetConfigPath);
      expect(summary.totalRepositories).toBeGreaterThan(0);
      expect(summary.repositories.length).toBe(summary.totalRepositories);
      expect(summary.timestamp).toBeDefined();
    }
  });

  it('should handle missing repositories with ERROR status in fleet summary', () => {
    const mockConfig: FleetConfig = {
      repositories: [
        'c:/non/existent/repo/path/alpha',
        'c:/non/existent/repo/path/beta'
      ]
    };

    const summary = FleetAggregator.evaluateFleet(mockConfig);
    expect(summary.totalRepositories).toBe(2);
    expect(summary.errorCount).toBe(2);
    expect(summary.overallStatus).toBe('FAIL');
    expect(summary.repositories[0].status).toBe('ERROR');
  });

  it('should generate well-formatted markdown report with matrix', () => {
    const mockConfig: FleetConfig = {
      repositories: [
        'c:/mock/repo1'
      ]
    };

    const summary = FleetAggregator.evaluateFleet(mockConfig);
    const md = FleetAggregator.generateMarkdownReport(summary);

    expect(md).toContain('# CHAINPROOF — Fleet Supply Chain Security Report');
    expect(md).toContain('| Repository | Status |');
    expect(md).toContain('repo1');
    expect(md).toContain('HERMES v6');
  });

  it('should reject invalid fleet config path', () => {
    expect(() => FleetAggregator.evaluateFleet('invalid-fleet-config-does-not-exist.json')).toThrow(/not found/i);
  });
});
