import * as path from 'path';
import { ConfigLoader, DEFAULT_CONFIG } from '../config';

describe('ConfigLoader.loadConfig', () => {
  // Regression: a relative start dir like "../x" used to loop forever,
  // because path.dirname(".") === "." never equals the filesystem root.
  it('returns for a relative start dir instead of hanging', () => {
    const loader = new ConfigLoader();
    const config = loader.loadConfig('../definitely-not-a-real-dir-xyz');
    expect(config.riskThresholds).toEqual(DEFAULT_CONFIG.riskThresholds);
  });

  it('returns for "." and an absolute path', () => {
    const loader = new ConfigLoader();
    expect(loader.loadConfig('.')).toBeDefined();
    expect(loader.loadConfig(path.parse(process.cwd()).root)).toBeDefined();
  });
});
