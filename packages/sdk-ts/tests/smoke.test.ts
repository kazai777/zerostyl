import { describe, expect, it } from 'vitest';
import { SDK_VERSION } from '../src/index.js';

describe('@zerostyl/sdk-ts smoke', () => {
  it('exposes a non-empty SDK_VERSION', () => {
    expect(SDK_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
