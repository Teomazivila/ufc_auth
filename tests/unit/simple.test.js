/**
 * Simple Test to Verify Jest Setup
 */

describe('Jest Setup Verification', () => {
  it('should run basic tests', () => {
    expect(1 + 1).toBe(2);
  });

  it('should support async tests', async () => {
    const result = await Promise.resolve('test');
    expect(result).toBe('test');
  });

  it('should have access to global test utils', () => {
    expect(global.testUtils).toBeDefined();
    expect(global.testUtils.createTestUser).toBeInstanceOf(Function);
  });
}); 