module.exports = function (jsdom) {
  class StringWrapper {
    constructor(s) {
      this.s = s;
    }

    toString() {
      return this.s;
    }
  }

  function loadDOMPurify(assert, head, setup, onload) {
    const testDone = assert.async();
    jsdom.env({
      html: '<head>' + head + '</head>',
      features: {
        FetchExternalResources: ['script'],
        ProcessExternalResources: ['script'],
      },
      created(err, window) {
        if (setup) {
          setup(window);
        }
      },
      done(err, window) {
        assert.ok(window.DOMPurify.sanitize);
        // Sanity check
        assert.equal(
          window.DOMPurify.sanitize('<img src=x onerror=alert(1)>'),
          '<img src="x">'
        );
        if (onload) {
          onload(window);
        }
        testDone();
      },
    });
  }

  QUnit.test('works in a non-Trusted Type environment', function (assert) {
    let policyCreated;

    loadDOMPurify(
      assert,
      '<script src="dist/purify.js"></script>',
      function setup(window) {
        delete window.trustedTypes;
      },
      function onload(window) {
        const output = window.DOMPurify.sanitize('<img>');
        assert.ok(typeof output === 'string');
      }
    );
  });

  QUnit.test('works in a Trusted Type environment', function (assert) {
    let policyCreated;

    loadDOMPurify(
      assert,
      '<script src="dist/purify.js"></script>',
      function setup(window) {
        window.trustedTypes = {
          createPolicy(name, rules) {
            policyCreated = name;
            return {
              createHTML(s) {
                return new StringWrapper(rules.createHTML(s));
              },
            };
          },
        };
      },
      function onload(window) {
        assert.equal(policyCreated, 'dompurify');
        const output = window.DOMPurify.sanitize('<img>', {
          RETURN_TRUSTED_TYPE: true,
        });
        assert.equal(output, '<img>');
        assert.ok(output instanceof StringWrapper);
      }
    );
  });

  QUnit.test(
    'supports configuring the policy suffix via an attribute',
    function (assert) {
      let policyCreated;

      loadDOMPurify(
        assert,
        '<script data-tt-policy-suffix="suffix" src="dist/purify.js"></script>',
        function setup(window) {
          window.trustedTypes = {
            createPolicy(name, rules) {
              policyCreated = name;
              return rules;
            },
          };
        },
        function onload(window) {
          assert.equal(policyCreated, 'dompurify#suffix');
        }
      );
    }
  );

  // Regression tests for GHSA-vxr8-fq34-vvx9. These live in the bootstrap
  // (jsdom) suite, not test-suite.js, because they need a fresh realm per test:
  // Trusted Types policy names are unique per realm, so a shared browser page
  // cannot recreate the internal `dompurify` policy for a fresh instance.
  // This version has no TRUSTED_TYPES_POLICY option: the instance's own
  // policy is the only one ever used to sign RETURN_TRUSTED_TYPE output.
  function withCountingTrustedTypes(created) {
    return function setup(window) {
      window.trustedTypes = {
        createPolicy(name, rules) {
          created.push(name);
          return {
            createHTML(s) {
              return new StringWrapper(rules.createHTML(s));
            },
          };
        },
      };
    };
  }

  // A caller-supplied policy that ignores its input and always emits a fixed
  // payload — stands in for an unsafe/foreign policy installed by a
  // less-trusted integration.
  function unsafeCallerPolicy() {
    return {
      createHTML() {
        return new StringWrapper('<img src=x onerror=alert(1)>');
      },
      createScriptURL(url) {
        return url;
      },
    };
  }

  QUnit.test(
    'a caller TRUSTED_TYPES_POLICY does not survive clearConfig()',
    function (assert) {
      const created = [];
      loadDOMPurify(
        assert,
        '<script src="dist/purify.js"></script>',
        withCountingTrustedTypes(created),
        function onload(window) {
          const DOMPurify = window.DOMPurify;

          // Caller tries to opt an unsafe policy in for a single call.
          const during = String(
            DOMPurify.sanitize('<img src=x onerror=alert(1)>', {
              TRUSTED_TYPES_POLICY: unsafeCallerPolicy(),
              RETURN_TRUSTED_TYPE: true,
            })
          );
          assert.equal(
            during.indexOf('onerror'),
            -1,
            'a caller policy never signs output'
          );

          DOMPurify.clearConfig();

          const afterTrusted = DOMPurify.sanitize(
            '<img src=x onerror=alert(1)>',
            {
              RETURN_TRUSTED_TYPE: true,
            }
          );
          assert.ok(
            afterTrusted instanceof StringWrapper,
            'signed by the internal policy'
          );
          assert.equal(
            String(afterTrusted).indexOf('onerror'),
            -1,
            'stale policy must not sign output after clearConfig()'
          );
          assert.equal(
            String(afterTrusted),
            '<img src="x">',
            'output is the default-sanitized result'
          );
        }
      );
    }
  );

  QUnit.test(
    'TRUSTED_TYPES_POLICY: null does not resurface a previously supplied policy',
    function (assert) {
      const created = [];
      loadDOMPurify(
        assert,
        '<script src="dist/purify.js"></script>',
        withCountingTrustedTypes(created),
        function onload(window) {
          const DOMPurify = window.DOMPurify;

          DOMPurify.sanitize('x', {
            TRUSTED_TYPES_POLICY: unsafeCallerPolicy(),
            RETURN_TRUSTED_TYPE: true,
          });

          const afterNull = String(
            DOMPurify.sanitize('<img src=x onerror=alert(1)>', {
              TRUSTED_TYPES_POLICY: null,
              RETURN_TRUSTED_TYPE: true,
            })
          );
          assert.equal(
            afterNull.indexOf('onerror'),
            -1,
            'no retained caller policy signs the output'
          );
          assert.equal(
            afterNull,
            '<img src="x">',
            'null returns the sanitized result'
          );
        }
      );
    }
  );

  QUnit.test(
    'default RETURN_TRUSTED_TYPE yields a Trusted Type and creates the internal policy once',
    function (assert) {
      const created = [];
      loadDOMPurify(
        assert,
        '<script src="dist/purify.js"></script>',
        withCountingTrustedTypes(created),
        function onload(window) {
          const DOMPurify = window.DOMPurify;

          const out = DOMPurify.sanitize('<b>ok</b><script>alert(2)</script>', {
            RETURN_TRUSTED_TYPE: true,
          });
          assert.ok(
            out instanceof StringWrapper,
            'returns a Trusted Type, not a plain string'
          );
          assert.equal(
            String(out),
            '<b>ok</b>',
            'wraps the sanitized result; script removed'
          );

          // The default path, exercised again across clearConfig(), must not
          // recreate the internal policy — Trusted Types throws on duplicates.
          DOMPurify.clearConfig();
          DOMPurify.sanitize('<b>again</b>', { RETURN_TRUSTED_TYPE: true });
          assert.equal(
            created.filter(function (name) {
              return name === 'dompurify';
            }).length,
            1,
            'internal dompurify policy created exactly once'
          );
        }
      );
    }
  );
};
