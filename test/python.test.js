import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compareVersions, satisfies, maxSatisfying } from '../src/pep440.js';
import { evaluateMarker, DEFAULT_ENV } from '../src/markers.js';
import { parsePep508, parseRequirements, parsePyproject, detectInput } from '../src/parse.js';

test('PEP 440 ordering follows the spec', () => {
  const ordered = ['1.0.dev0', '1.0a1', '1.0a2.dev1', '1.0a2', '1.0b1', '1.0rc1', '1.0', '1.0.post1', '1.0.1', '1!0.1'];
  const shuffled = [...ordered].reverse();
  assert.deepEqual(shuffled.sort(compareVersions), ordered);
  assert.equal(compareVersions('1.0', '1.0.0'), 0);
  assert.equal(compareVersions('2.0', '10.0'), -1);
});

test('PEP 440 specifiers', () => {
  assert.ok(satisfies('2.19.1', '>=2.19,<3'));
  assert.ok(!satisfies('3.0.0', '>=2.19,<3'));
  assert.ok(satisfies('1.4.2', '~=1.4'));
  assert.ok(!satisfies('2.0', '~=1.4'));
  assert.ok(satisfies('1.4.9', '~=1.4.2'));
  assert.ok(!satisfies('1.5.0', '~=1.4.2'));
  assert.ok(satisfies('1.1.7', '==1.1.*'));
  assert.ok(!satisfies('1.2.0', '==1.1.*'));
  assert.ok(satisfies('1.0+local.1', '==1.0'));
  assert.ok(!satisfies('3.0rc1', '<3.0'), '"<3.0" excludes pre-releases of 3.0');
  assert.ok(!satisfies('1.0.post1', '>1.0'), '">1.0" excludes post-releases of 1.0');
  assert.ok(satisfies('1.0', ''), 'an empty specifier accepts any version');
  assert.ok(satisfies('2024.1', '>dev'), 'legacy non-PEP 440 clauses are ignored');
  assert.ok(satisfies('2024.1', '>dev,>=2020'));
  assert.ok(!satisfies('2019.1', '>dev,>=2020'));
  assert.ok(!satisfies('not-a-version', ''));
});

test('maxSatisfying skips pre-releases unless asked', () => {
  const versions = ['1.0', '1.1', '2.0b1', '1.2.dev3'];
  assert.equal(maxSatisfying(versions, ''), '1.1');
  assert.equal(maxSatisfying(versions, '>=2.0b1'), '2.0b1');
  assert.equal(maxSatisfying(['3.0a1'], '>=1'), '3.0a1', 'falls back to pre-releases when nothing else matches');
  assert.equal(maxSatisfying(versions, '>5'), null);
});

test('environment markers', () => {
  const none = new Set();
  assert.equal(evaluateMarker('python_version < "3.8"', DEFAULT_ENV, none), false);
  assert.equal(evaluateMarker('python_version >= "3.8"', DEFAULT_ENV, none), true);
  assert.equal(evaluateMarker('python_version > "3.9"', DEFAULT_ENV, none), true, 'versions compare numerically, not as strings');
  assert.equal(evaluateMarker('sys_platform == "win32" or os_name == "posix"', DEFAULT_ENV, none), true);
  assert.equal(evaluateMarker("(platform_python_implementation == \"CPython\") and extra == 'brotli'", DEFAULT_ENV, none), false);
  assert.equal(evaluateMarker("(platform_python_implementation == \"CPython\") and extra == 'brotli'", DEFAULT_ENV, new Set(['brotli'])), true);
  assert.equal(evaluateMarker('"linux" in sys_platform', DEFAULT_ENV, none), true);
  assert.equal(evaluateMarker('platform_machine not in "arm64 aarch64"', DEFAULT_ENV, none), true);
  assert.equal(evaluateMarker('this is ((( not valid', DEFAULT_ENV, none), true, 'unparseable markers include the dependency');
});

test('PEP 508 requirement parsing', () => {
  assert.deepEqual(parsePep508('requests[socks, security] (>=2.8.1,<3) ; python_version >= "3.7"'), {
    name: 'requests',
    displayName: 'requests',
    extras: ['socks', 'security'],
    specifier: '>=2.8.1,<3',
    marker: 'python_version >= "3.7"',
  });
  assert.equal(parsePep508('Flask_SQLAlchemy>=3').name, 'flask-sqlalchemy');
  assert.equal(parsePep508('pkg @ https://example.com/pkg.whl'), null);
});

test('requirements.txt parsing skips options, URLs and comments', () => {
  const { requirements, skipped } = parseRequirements(`
    # comment
    -r base.txt
    --index-url https://example.com/simple
    django==4.2  # inline comment
    requests>=2 \\
      --hash=sha256:abc
    git+https://github.com/x/y.git
    -e .
  `);
  assert.deepEqual(requirements.map(r => `${r.name}${r.specifier}`), ['django==4.2', 'requests>=2']);
  assert.equal(skipped.length, 4);
});

test('pyproject.toml dependencies with extras inside brackets', () => {
  const { name, requirements } = parsePyproject(`
[build-system]
requires = ["hatchling"]

[project]
name = "demo"
dependencies = [
  "httpx[http2]>=0.27",  # comment with ] bracket
  'rich',
]

[project.optional-dependencies]
dev = ["pytest"]
`);
  assert.equal(name, 'demo');
  assert.deepEqual(requirements.map(r => r.name), ['httpx', 'rich']);
  assert.deepEqual(requirements[0].extras, ['http2']);
});

test('detectInput identifies each format', () => {
  assert.equal(detectInput('{"dependencies":{"a":"1"}}').kind, 'npm-manifest');
  assert.equal(detectInput('{"lockfileVersion":3,"packages":{}}').kind, 'npm-lock');
  assert.equal(detectInput('flask==2.0').kind, 'pypi');
  assert.equal(detectInput('[project]\nname = "x"\ndependencies = ["a"]\n').label, 'pyproject.toml');
  assert.throws(() => detectInput('   '), /Nothing to analyze/);
  assert.throws(() => detectInput('{"foo": 1}'), /doesn't look like/);
});
