const assert = require('node:assert/strict');
const test = require('node:test');
const { execFileSync } = require('node:child_process');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const credits = require('./release_acknowledgements.cjs');

const core = { info() {}, warning() {} };
const user = login => ({ login, type: 'User' });
const issue = (number, login) => ({ number, user: user(login) });
const pr = (number, login) => ({ ...issue(number, login), pull_request: {} });

function fixture(records, pulls = {}) {
  const calls = [];
  const github = { rest: {
    issues: { async get({ issue_number }) {
      calls.push(issue_number);
      if (!records[issue_number]) throw Object.assign(new Error('Not found'), { status: 404 });
      return { data: records[issue_number] };
    } },
    pulls: { async get({ pull_number }) { return { data: pulls[pull_number] }; } },
  } };
  return { github, calls };
}

function options(github, messages) {
  return { github, core, owner: 'samwafgo', repo: 'SamWaf', tag: 'v1.3.25-beta.8', from: 'v1.3.25-beta.7',
    runGit: () => messages };
}

test('recognizes local references and excludes foreign repository references', () => {
  assert.deepEqual(credits.references('(#1014) #1002 #1002 #IKJN44 samwafgo/SamWaf#938 other/repo#22 https://github.com/other/repo/issues/55 https://github.com/samwafgo/SamWaf/issues/1010#issuecomment-999', 'samwafgo/SamWaf'), [938, 1002, 1010, 1014]);
});

test('credits issue authors behind maintainer PRs and groups repeated accounts', async () => {
  const { github, calls } = fixture({ 1014: pr(1014, 'samwafgo'), 1002: issue(1002, 'wxf26054'),
    1010: issue(1010, 'wxf26054'), 1011: pr(1011, 'contributor'), 900: issue(900, 'dependabot[bot]') },
  { 1014: { merged_at: '2026-10-13', title: 'Fix', body: '#1002 #1010' },
    1011: { merged_at: '2026-10-13', title: 'Feature', body: '' } });
  const result = await credits.collect(options(github, 'Merge (#1014) #1002\nFeature (#1011) #900'));
  assert.deepEqual(result.people.map(p => p.login), ['contributor', 'wxf26054']);
  assert.deepEqual([...result.people[1].issues], [1002, 1010]);
  assert.equal(calls.filter(n => n === 1002).length, 1);
  assert.match(result.section, /@wxf26054/);
  assert.doesNotMatch(result.section, /@samwafgo|@dependabot/);
});

test('reads paginated GitHub closing issue links and skips foreign links', async () => {
  const { github } = fixture({ 20: pr(20, 'author'), 30: issue(30, 'reporter'), 31: issue(31, 'reporter') },
    { 20: { merged_at: '2026-10-13', title: 'Feature', body: '' } });
  const cursors = [];
  github.graphql = async (_, variables) => {
    cursors.push(variables.cursor);
    return { repository: { pullRequest: { closingIssuesReferences: {
      nodes: variables.cursor ? [{ number: 31, repository: { nameWithOwner: 'samwafgo/SamWaf' } }] : [
        { number: 30, repository: { nameWithOwner: 'samwafgo/SamWaf' } },
        { number: 999, repository: { nameWithOwner: 'other/repo' } }],
      pageInfo: { hasNextPage: !variables.cursor, endCursor: 'next' },
    } } } };
  };
  const result = await credits.collect(options(github, '(#20)'));
  assert.deepEqual(cursors, [null, 'next']);
  assert.deepEqual([...result.people.find(p => p.login === 'reporter').issues], [30, 31]);
});

test('does not traverse arbitrary issue body references or unmerged PRs', async () => {
  const { github, calls } = fixture({ 10: { ...issue(10, 'reporter'), body: '#999' }, 20: pr(20, 'author') },
    { 20: { merged_at: null, body: '#998' } });
  const result = await credits.collect(options(github, '#10 #20'));
  assert.deepEqual(result.people.map(p => p.login), ['reporter']);
  assert.deepEqual(calls, [10, 20]);
});

test('a missing API record does not produce a partial list', async () => {
  const { github } = fixture({ 10: issue(10, 'reporter') });
  await assert.rejects(credits.collect(options(github, '#10 #999')), /could not be resolved/);
});

test('release updates are idempotent and preserve manually written text', () => {
  const body = 'Release notes\n\nContact information\n';
  const first = `${credits.START}\n@first\n${credits.END}`;
  const next = `${credits.START}\n@next\n${credits.END}`;
  const updated = credits.replaceSection(body, first);
  assert.equal(credits.replaceSection(updated, first), updated);
  assert.equal(credits.replaceSection(updated, next), `${body.trimEnd()}\n\n${next}\n`);
  assert.equal(credits.replaceSection(updated, ''), `${body.trimEnd()}\n\n\n`);
  assert.throws(() => credits.replaceSection(credits.START, first), /Incomplete/);
});

test('release API update keeps notes and does not write again when unchanged', async () => {
  const { github } = fixture({ 10: issue(10, 'reporter') });
  let body = 'Human-written release notes\n\nSupport footer';
  let writes = 0;
  github.rest.repos = {
    async getReleaseByTag() { return { data: { id: 42, body } }; },
    async updateRelease(parameters) {
      assert.equal(parameters.release_id, 42);
      assert.match(parameters.body, /^Human-written release notes\n\nSupport footer/);
      body = parameters.body;
      writes++;
    },
  };
  await credits.updateRelease(options(github, '#10'));
  await credits.updateRelease(options(github, '#10'));
  assert.equal(writes, 1);
  assert.match(body, /@reporter/);
});

test('stable baseline spans betas while beta baseline follows the previous tag', () => {
  const directory = mkdtempSync(join(tmpdir(), 'samwaf-credits-'));
  const runGit = (...args) => execFileSync('git', ['-C', directory, ...args], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
  try {
    runGit('init');
    let index = 0;
    const commit = tag => {
      index++;
      const parent = index > 1 ? 'from refs/heads/test^0\n' : '';
      const history = `commit refs/heads/test\nmark :${index}\ncommitter Test <test@example.com> ${1700000000 + index} +0000\ndata 4\ntest\n${parent}\nreset refs/tags/${tag}\nfrom :${index}\n\ndone\n`;
      execFileSync('git', ['-C', directory, 'fast-import', '--quiet'], {
        input: history, stdio: ['pipe', 'pipe', 'pipe'],
      });
    };
    commit('v1.3.24');
    assert.equal(credits.previousTag('v1.3.24', runGit), '');
    commit('v1.3.25-beta.1');
    commit('v1.3.25-beta.2');
    commit('v1.3.25');
    assert.equal(credits.previousTag('v1.3.25', runGit), 'v1.3.24');
    assert.equal(credits.previousTag('v1.3.25-beta.2', runGit), 'v1.3.25-beta.1');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
