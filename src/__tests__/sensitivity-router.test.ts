import { describe, it, expect } from 'vitest';
import { SensitivityRouter } from '../sensitivity-router';

describe('SensitivityRouter', () => {
  it('classifies normal text as S1', () => {
    const router = new SensitivityRouter();
    expect(router.classify('你好，请帮我查一下天气')).toBe('S1');
    expect(router.classify('What is the capital of France?')).toBe('S1');
    expect(router.classify('')).toBe('S1');
  });

  it('classifies S3 sensitive data correctly', () => {
    const router = new SensitivityRouter();
    expect(router.classify('我的银行卡 6222021234567890123')).toBe('S3');
    expect(router.classify('身份证 110101199001011234')).toBe('S3');
    expect(router.classify('密码是 abc123')).toBe('S3');
    expect(router.classify('secret_key=sk-xxx')).toBe('S3');
    expect(router.classify('api_key: sk-12345')).toBe('S3');
    expect(router.classify('这是一份机密文件')).toBe('S3');
    expect(router.classify('绝密信息请勿外传')).toBe('S3');
  });

  it('classifies S2 internal data correctly', () => {
    const router = new SensitivityRouter();
    expect(router.classify('这是内部文件')).toBe('S2');
    expect(router.classify('员工薪酬调整通知')).toBe('S2');
    expect(router.classify('本季度财务报表')).toBe('S2');
    expect(router.classify('客户名单已更新')).toBe('S2');
    expect(router.classify('绩效考核结果')).toBe('S2');
  });

  it('S3 takes priority over S2', () => {
    const router = new SensitivityRouter();
    // Contains both S2 and S3 patterns
    expect(router.classify('内部机密文件')).toBe('S3');
  });

  it('returns correct routing actions', () => {
    const router = new SensitivityRouter();
    const s1 = router.getRoutingAction('S1');
    expect(s1.forceLocal).toBe(false);
    expect(s1.audit).toBe(false);

    const s2 = router.getRoutingAction('S2');
    expect(s2.forceLocal).toBe(false);
    expect(s2.audit).toBe(true);

    const s3 = router.getRoutingAction('S3');
    expect(s3.forceLocal).toBe(true);
    expect(s3.audit).toBe(true);
  });

  it('supports custom patterns', () => {
    const router = new SensitivityRouter({
      s3Patterns: [/COMPANY_SECRET/i],
      s2Patterns: [/internal/i],
      scanArguments: true,
    });
    expect(router.classify('This is COMPANY_SECRET data')).toBe('S3');
    expect(router.classify('This is internal memo')).toBe('S2');
    expect(router.classify('Hello world')).toBe('S1');
  });
});
