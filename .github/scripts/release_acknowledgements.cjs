const { execFileSync } = require('node:child_process');

const START = '<!-- samwaf-acknowledgements:start -->';
const END = '<!-- samwaf-acknowledgements:end -->';
const STABLE_TAG = /^v\d+\.\d+\.\d+$/;

function git(...args) {
  return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

function previousTag(tag, runGit = git) {
  const args = ['describe', '--tags', '--abbrev=0', '--match', 'v[0-9]*', '--exclude', tag];
  if (STABLE_TAG.test(tag)) args.push('--exclude', '*-*');
  try {
    return runGit(...args, tag);
  } catch (error) {
    // 首次发布没有基线；其他 git 错误仍交给调用方处理。
    const tags = runGit('tag', '--merged', tag).split('\n').filter(Boolean);
    const candidates = tags.filter(value => value !== tag && (!STABLE_TAG.test(tag) || STABLE_TAG.test(value)));
    if (candidates.length) throw error;
    return '';
  }
}

function references(text, repository) {
  const numbers = new Set();
  const add = (repo, number) => {
    if (repo.toLowerCase() === repository.toLowerCase()) numbers.add(Number(number));
  };
  const remainder = (text || '')
    .replace(/https?:\/\/github\.com\/([\w.-]+\/[\w.-]+)\/(?:issues|pull)\/(\d+)\b[^\s)]*/gi,
      (_, repo, number) => { add(repo, number); return ' '; })
    .replace(/([\w.-]+\/[\w.-]+)#(\d+)\b/g,
      (_, repo, number) => { add(repo, number); return ' '; });
  for (const match of remainder.matchAll(/(?<![\w/#])#([1-9]\d*)\b/g)) numbers.add(Number(match[1]));
  return [...numbers].sort((a, b) => a - b);
}

function replaceSection(body, section) {
  const start = body.indexOf(START);
  const end = body.indexOf(END);
  if (start >= 0 || end >= 0) {
    if (start < 0 || end < start) throw new Error('Incomplete acknowledgements markers');
    return body.slice(0, start) + section + body.slice(end + END.length);
  }
  return section ? `${body.trimEnd()}\n\n${section}\n` : body;
}

async function collect({ github, core, owner, repo, tag, from, exclude = [], runGit = git }) {
  const repository = `${owner}/${repo}`;
  const baseline = from === undefined ? previousTag(tag, runGit) : from;
  const messages = runGit('log', '--format=%B', baseline ? `${baseline}..${tag}` : tag);
  const roots = references(messages, repository);
  const excluded = new Set([owner, ...exclude].map(login => login.toLowerCase()));
  const people = new Map();
  const cache = new Map();
  let failures = 0;

  async function issue(number) {
    if (!cache.has(number)) {
      try {
        const { data } = await github.rest.issues.get({ owner, repo, issue_number: number });
        cache.set(number, data);
      } catch (error) {
        failures++;
        core.warning(`Acknowledgements: could not read ${repository}#${number} (HTTP ${error.status || 'unknown'})`);
        cache.set(number, null);
      }
    }
    return cache.get(number);
  }

  function credit(record, kind) {
    const user = record?.user;
    if (!user || user.type === 'Bot' || /\[bot\]$/i.test(user.login) || excluded.has(user.login.toLowerCase())) return;
    if (!/^[a-z\d](?:[a-z\d-]{0,38})$/i.test(user.login)) return;
    const key = user.login.toLowerCase();
    if (!people.has(key)) people.set(key, { login: user.login, issues: new Set(), prs: new Set() });
    people.get(key)[kind].add(record.number);
  }

  for (const number of roots) {
    const record = await issue(number);
    if (!record) continue;
    if (!record.pull_request) {
      credit(record, 'issues');
      continue;
    }
    // 本版本提交引用的 PR 才展开关联，issue 正文中的引用不继续展开。
    const { data: pr } = await github.rest.pulls.get({ owner, repo, pull_number: number });
    if (!pr.merged_at) continue;
    credit(record, 'prs');
    const linked = new Set(references(`${pr.title}\n${pr.body || ''}`, repository));
    if (github.graphql) {
      let cursor = null;
      do {
        const response = await github.graphql(`query($owner: String!, $repo: String!, $number: Int!, $cursor: String) {
          repository(owner: $owner, name: $repo) {
            pullRequest(number: $number) {
              closingIssuesReferences(first: 100, after: $cursor) {
                nodes { number repository { nameWithOwner } }
                pageInfo { hasNextPage endCursor }
              }
            }
          }
        }`, { owner, repo, number, cursor });
        const connection = response.repository.pullRequest.closingIssuesReferences;
        for (const node of connection.nodes) {
          if (node.repository.nameWithOwner.toLowerCase() === repository.toLowerCase()) linked.add(node.number);
        }
        cursor = connection.pageInfo.hasNextPage ? connection.pageInfo.endCursor : null;
      } while (cursor);
    }
    for (const linkedNumber of [...linked].sort((a, b) => a - b)) {
      const linkedIssue = await issue(linkedNumber);
      if (linkedIssue && !linkedIssue.pull_request) credit(linkedIssue, 'issues');
    }
  }
  if (failures) throw new Error(`Acknowledgements: ${failures} references could not be resolved`);

  const rows = [...people.values()].sort((a, b) => a.login.toLowerCase().localeCompare(b.login.toLowerCase()));
  const link = (number, kind) => `[#${number}](https://github.com/${repository}/${kind}/${number})`;
  const lines = rows.map(person => {
    const contributions = [];
    if (person.issues.size) contributions.push(`Issue: ${[...person.issues].sort((a, b) => a - b).map(n => link(n, 'issues')).join(', ')}`);
    if (person.prs.size) contributions.push(`PR: ${[...person.prs].sort((a, b) => a - b).map(n => link(n, 'pull')).join(', ')}`);
    return `- @${person.login} — ${contributions.join('; ')}`;
  });
  const section = lines.length ? [START, '### 🙏 致谢 / Thanks', '',
    '感谢以下朋友为本版本报告问题、提出建议或贡献代码（按账号排序）。',
    'Thanks for reporting issues, suggesting improvements, and contributing code to this release.',
    '', ...lines, END].join('\n') : '';
  core.info(`Acknowledgements: ${baseline || '(first release)'}..${tag}, ${roots.length} references, ${rows.length} people`);
  return { section, baseline, people: rows };
}

async function updateRelease(options) {
  const { github, core, owner, repo, tag } = options;
  const { section } = await collect(options);
  if (section && core.summary) await core.summary.addRaw(`${section}\n`).write();
  const { data: release } = await github.rest.repos.getReleaseByTag({ owner, repo, tag });
  const previous = release.body || '';
  const body = replaceSection(previous, section);
  if (body !== previous) {
    await github.rest.repos.updateRelease({ owner, repo, release_id: release.id, body });
    core.info(`Acknowledgements updated for ${tag}`);
  }
}

module.exports = { collect, updateRelease, previousTag, references, replaceSection, START, END };
