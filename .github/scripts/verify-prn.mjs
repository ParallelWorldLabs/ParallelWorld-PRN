// PRN 集中仓守卫脚本：push 后自动校验合同目录完整性，失败时由 workflow 自动回退违规提交。
// 校验内容与插件内核（src/core/remote.js、src/core/protocol.js）保持同一套密码学规则：
//   1. 名单单调性——当前索引签署方必须完整包含父提交版本名单（防"少写某人"删减攻击）；
//   2. 签名文件逐个验签——身份摘要自洽（card.id=公钥摘要）+ ed25519 验签（防伪造/篡改）；
//   3. 成员快照摘要重算——按已验签记录重算 memberSnapshotDigest 与索引比对（防索引伪造）；
//   4. 信封收件人覆盖——envelope.keys 必须为名单中每人保留解密钥匙（防排斥解密）；
//   5. 目录单向校验——名单每位签署方的签名文件必须存在于目录（防删他人文件）；
//      目录多于名单属合法待收编状态（成员直写先于发起方收编），放行。
// 整目录删除（合法删除流程）豁免全部校验。任一项失败即以非零退出码结束。
import { createHash, createPublicKey, verify } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const run = (args) =>
  execFileSync('git', args, { cwd: process.env.GITHUB_WORKSPACE ?? '.', encoding: 'utf8' }).trim();
// git cat-file -e 的存在性探测：失败（对象不存在）抛错时按不存在处理，stdio 静默避免噪声。
const gitOk = args => {
  try { execFileSync('git', args, { cwd: process.env.GITHUB_WORKSPACE ?? '.', stdio: 'ignore' }); return true; }
  catch { return false; }
};
const BEFORE = process.env.PRN_BEFORE, AFTER = process.env.PRN_AFTER;
if (!AFTER) { console.error('缺少 PRN_AFTER 提交标识，无法校验'); process.exit(1); }

// canonical 序列化与摘要：与插件 protocol.js 同规则（键排序 JSON.stringify + sha256）。
function canonical(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean' || Number.isSafeInteger(value))
    return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object')
    return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  throw new Error('协议外类型');
}
const digest = value => createHash('sha256').update(canonical(value)).digest('hex');
const decode = value => Buffer.from(value, 'base64url');
const idPattern = /^[a-f0-9]{64}$/;

// 单调性判定：current 相对 previous 缺失的签署方（空数组=合法只增不减）。
const missingFrom = (current, previous) => {
  const set = new Set(current);
  return previous.filter(signer => !set.has(signer));
};

// 逐签名文件验签：身份摘要自洽 + 签名绑定合同与身份 + ed25519 验签。
function verifyMember(contractId, file) {
  if (file?.protocol !== 'prn-public-signature/1' || file.contract !== contractId)
    throw new Error('签名文件协议头或合同绑定不符');
  const card = file.member?.card, signature = file.member?.signature;
  if (!card || !signature) throw new Error('签名文件结构不完整');
  if (!idPattern.test(card.id) || digest({ signKey: card.signKey, boxKey: card.boxKey }) !== card.id)
    throw new Error('身份与公钥摘要不匹配');
  const message = { protocol: signature.protocol, contract: signature.contract, signer: signature.signer };
  if (signature.protocol !== 'prn-contract-signature/1' || message.contract !== contractId
    || message.signer !== card.id) throw new Error('加入签名未绑定当前合同和身份');
  if (decode(signature.signature).toString('base64url') !== signature.signature)
    throw new Error('签名编码表示无效');
  const key = createPublicKey({ key: decode(card.signKey), format: 'der', type: 'spki' });
  if (!verify(null, Buffer.from(canonical(message)), key, decode(signature.signature)))
    throw new Error('签名验证失败');
  return card.id;
}

// 找出本次推送涉及的合同目录：BEFORE 无效（新分支首推）时退回与父提交比对，再退回全树列举。
let changed;
if (BEFORE && !/^0+$/.test(BEFORE) && gitOk(['cat-file', '-e', `${BEFORE}^{commit}`]))
  changed = run(['diff', '--name-only', BEFORE, AFTER]);
else if (gitOk(['cat-file', '-e', `${AFTER}^`]))
  changed = run(['diff', '--name-only', `${AFTER}^`, AFTER]);
else
  changed = run(['ls-tree', '-r', '--name-only', AFTER]);
const contracts = [...new Set(changed.split('\n')
  .map(line => line.match(/^agreements\/([a-f0-9]{64})\//)?.[1]).filter(Boolean))];
console.log(`待校验合同 ${contracts.length} 份${contracts.length ? '：' + contracts.map(id => id.slice(0, 12)).join('、') : ''}`);

const failures = [];
for (const contractId of contracts) {
  const prefix = `agreements/${contractId}`;
  try {
    // 整目录删除（合法删除流程）豁免：索引随目录消失即跳过。
    if (!gitOk(['cat-file', '-e', `${AFTER}:${prefix}/index.json`])) {
      console.log(`合同 ${contractId.slice(0, 12)} 已整体删除（合法删除流程），豁免校验`);
      continue;
    }
    // 索引解析与最小结构校验。
    const index = JSON.parse(run(['show', `${AFTER}:${prefix}/index.json`]));
    if (index.protocol !== 'prn-remote-index/1' || index.contract !== contractId
      || !Array.isArray(index.signers) || !idPattern.test(String(index.memberSnapshotDigest)))
      throw new Error('索引结构或合同绑定无效');
    // 名单单调性：与父提交版本名单比对（历史不可改写由仓库"禁 force push"规则保证）。
    const history = run(['log', '--format=%H', '-n', '2', AFTER, '--', `${prefix}/index.json`]).split('\n');
    if (history.length === 2 && history[1]) {
      const prior = JSON.parse(run(['show', `${history[1]}:${prefix}/index.json`]));
      const missing = missingFrom(index.signers, prior.signers ?? []);
      if (missing.length) throw new Error(`名单比父版本少 ${missing.length} 人（${missing.map(id => id.slice(0, 12)).join('、')}）`);
    }
    // 签名文件逐个验签 + 摘要重算 + 目录交叉（每文件只读取解析一次）。
    const records = {};
    for (const signer of index.signers) {
      if (!idPattern.test(signer)) throw new Error('名单包含非法身份标识');
      const file = JSON.parse(run(['show', `${AFTER}:${prefix}/signatures/${signer}.json`]));
      if (verifyMember(contractId, file) !== signer) throw new Error('签名文件与名单条目不一致');
      records[signer] = file.member.signature;
    }
    const sorted = [...index.signers].sort();
    const recalculated = digest({ protocol: index.membership === 'open' ? 'prn-open-seal/1' : 'prn-seal/1',
      contract: contractId, signatures: sorted.map(id => records[id]) });
    if (recalculated !== index.memberSnapshotDigest) throw new Error('成员快照摘要与签名集合不一致');
    // 单向目录校验：名单中每个签署方的签名文件必须存在于目录（防删他人文件）。
    // 目录比名单多是合法状态——成员直写后、发起方收编前的窗口期（两阶段协议常态），
    // 非 id 形式的无关文件已被过滤；语义与插件 syncContract 的目录扫描一致。
    const listed = new Set(run(['ls-tree', '--name-only', `${AFTER}:${prefix}/signatures/`]).split('\n')
      .map(name => name.replace(/\.json$/, '')).filter(name => idPattern.test(name)));
    const absent = sorted.filter(signer => !listed.has(signer));
    if (absent.length) throw new Error(`名单中 ${absent.length} 名签署方的签名文件缺失（${absent.map(id => id.slice(0, 12)).join('、')}）`);
    // 信封收件人覆盖：每名成员必须保留解密钥匙条目（防排斥解密删减）。
    const envelope = JSON.parse(run(['show', `${AFTER}:${prefix}/envelope.prn.json`]));
    const recipients = new Set((envelope.keys ?? []).map(item => item.recipient));
    const uncovered = index.signers.filter(signer => !recipients.has(signer));
    if (uncovered.length) throw new Error(`信封缺少 ${uncovered.length} 名成员的解密钥匙（${uncovered.map(id => id.slice(0, 12)).join('、')}）`);
    console.log(`合同 ${contractId.slice(0, 12)} 校验通过（${index.signers.length} 名签署方）`);
  } catch (error) {
    failures.push(`合同 ${contractId.slice(0, 12)}：${error.message}`);
  }
}
if (failures.length) {
  console.error('PRN 守卫校验失败：\n' + failures.map(line => '  - ' + line).join('\n'));
  process.exit(1);
}
console.log('全部合同校验通过。');
