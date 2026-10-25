const fs = require('fs');
const path = require('path');
const vm = require('vm');
const nodeCrypto = require('crypto');

function createMockElement(id = '', tagName = 'div') {
  const classes = new Set();
  const listeners = {};
  const attributes = {};
  let _text = '';
  let _html = '';

  const el = {
    id,
    tagName: tagName.toUpperCase(),
    style: {},
    disabled: false,
    value: '',
    checked: false,
    className: '',
    attributes,
    classList: {
      add(...cls) { cls.forEach(c => classes.add(c)); el.className = Array.from(classes).join(' '); },
      remove(...cls) { cls.forEach(c => classes.delete(c)); el.className = Array.from(classes).join(' '); },
      contains(c) { return classes.has(c); },
      toggle(c, force) {
        if (force === undefined) {
          if (classes.has(c)) { classes.delete(c); } else { classes.add(c); }
        } else if (force) {
          classes.add(c);
        } else {
          classes.delete(c);
        }
        el.className = Array.from(classes).join(' ');
      }
    },
    getAttribute(name) { return attributes[name] !== undefined ? attributes[name] : null; },
    setAttribute(name, val) { attributes[name] = String(val); },
    addEventListener(event, fn) {
      if (!listeners[event]) listeners[event] = [];
      listeners[event].push(fn);
    },
    dispatchEvent(event) {
      const fns = listeners[event.type || event] || [];
      fns.forEach(fn => fn(event));
    },
    click() {
      const fns = listeners['click'] || [];
      return Promise.all(fns.map(fn => fn({ type: 'click', target: el })));
    },
    get textContent() { return _text; },
    set textContent(v) { _text = String(v); _html = String(v); },
    get innerHTML() { return _html; },
    set innerHTML(v) { _html = String(v); _text = String(v).replace(/<[^>]+>/g, ''); }
  };
  return el;
}

function createMockDocument() {
  const elementsById = {};
  const elementsByClass = {};

  const doc = {
    readyState: 'complete',
    getElementById(id) {
      if (!elementsById[id]) {
        elementsById[id] = createMockElement(id);
      }
      return elementsById[id];
    },
    querySelectorAll(selector) {
      if (selector.startsWith('.')) {
        const cls = selector.slice(1);
        if (!elementsByClass[cls]) elementsByClass[cls] = [];
        return elementsByClass[cls];
      }
      return [];
    },
    querySelector(sel) {
      const list = doc.querySelectorAll(sel);
      return list[0] || null;
    },
    createElement(tag) {
      return createMockElement('', tag);
    },
    body: createMockElement('body', 'body'),
    addEventListener(event, fn) {
      if (!doc._listeners) doc._listeners = {};
      if (!doc._listeners[event]) doc._listeners[event] = [];
      doc._listeners[event].push(fn);
    },
    fireEvent(eventName, evt = {}) {
      const list = (doc._listeners && doc._listeners[eventName]) || [];
      return Promise.all(list.map(fn => fn(evt)));
    }
  };
  doc.body.appendChild = function() {};
  doc.body.removeChild = function() {};
  return { doc, elementsById, elementsByClass };
}

function runEnvironment(htmlPath, cryptoConfig = {}) {
  const htmlContent = fs.readFileSync(htmlPath, 'utf8');
  const scripts = [...htmlContent.matchAll(/<script(?![^>]*src)[^>]*>([\s\S]*?)<\/script>/gi)];
  if (scripts.length === 0) throw new Error('Could not extract script from ' + htmlPath);
  const scriptCode = scripts[scripts.length - 1][1];

  const { doc, elementsById, elementsByClass } = createMockDocument();

  // Populate common elements
  const commonIds = [
    'cryptoEnvironmentBanner', 'cryptoBannerIcon', 'cryptoBannerTitle', 'cryptoBannerBody',
    'viewFlow', 'viewStatus', 'viewLean', 'navFlowBtn', 'navStatusBtn', 'navLeanBtn',
    'screenStep1', 'screenStep2', 'screenStep3', 'screenStep4',
    'stepTab1', 'stepTab2', 'stepTab3', 'stepTab4',
    'claimDosageInput', 'dosageValidationMsg', 'existingAddressInput', 'addressValidationMsg',
    'startStep1Btn', 'testVectorVerifyBtn', 'selfTestBox', 'selfTestOutput',
    'step2DerivedAddress', 'derivationTimeBadge', 'confirmSavedPhraseChk',
    'proceedToStep3Btn', 'copyPhraseOnceBtn', 'backToStep1Btn',
    'step3AddressDisplay', 'step3DosageDisplay', 'executeClaimBtn', 'claimPreflightBox',
    'claimExplanationText', 'claimDispatchBadge', 'pouwWitnessBadge', 'toastEl', 'toastText',
    'spec04RankInput', 'spec04Output', 'rpcDot', 'rpcConnStatusText', 'rpcLatencyText',
    'statusBlockNumber', 'statusBlockSource', 'liveBalanceValue', 'liveBalanceSourceNote',
    'symptomSummaryTag', 'metaMaskStatusBox'
  ];
  commonIds.forEach(id => doc.getElementById(id));
  
  // Elements that are initially hidden in HTML
  ['step1CryptoErrorBox', 'cryptoEnvironmentBanner', 'screenStep2', 'screenStep3', 'screenStep4', 'selfTestBox', 'toastEl'].forEach(id => {
    const el = doc.getElementById(id);
    el.classList.add('hidden');
  });

  const gridEl = doc.getElementById('oneTimeWordsGrid');
  gridEl.innerHTML = '';
  elementsById['claimDosageInput'].value = '21000000';
  elementsById['existingAddressInput'].value = '';

  // Setup Math.random spy
  let mathRandomCallCount = 0;
  const originalMathRandom = Math.random;
  const mathSpy = function() {
    mathRandomCallCount++;
    return originalMathRandom();
  };

  const windowObj = {
    crypto: cryptoConfig.crypto,
    location: {
      origin: cryptoConfig.origin || 'http://100.77.188.3:8546',
      protocol: cryptoConfig.protocol || 'http:',
      hostname: '100.77.188.3',
      port: '8546'
    },
    addEventListener(event, fn) {
      doc.addEventListener(event, fn);
    },
    performance: {
      now() { return performance.now(); }
    },
    setTimeout: (fn, ms) => setTimeout(fn, ms),
    clearTimeout: (id) => clearTimeout(id),
    TextEncoder,
    TextDecoder,
    Uint8Array,
    Int32Array,
    DataView,
    ArrayBuffer,
    BigInt,
    Math: Object.assign(Object.create(Math), {
      random: mathSpy
    }),
    navigator: {
      clipboard: {
        writeText: async () => {}
      }
    },
    fetch: async () => ({
      json: async () => ({ result: '0x1' })
    })
  };

  const sandbox = {
    window: windowObj,
    document: doc,
    location: windowObj.location,
    performance: windowObj.performance,
    setTimeout: windowObj.setTimeout,
    clearTimeout: windowObj.clearTimeout,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    Int32Array,
    DataView,
    ArrayBuffer,
    BigInt,
    Math: windowObj.Math,
    console,
    BIP39_WORDLIST: undefined
  };
  vm.createContext(sandbox);
  vm.runInContext(scriptCode, sandbox);

  return {
    sandbox,
    doc,
    elementsById,
    getMathRandomCount: () => mathRandomCallCount,
    resetMathRandomCount: () => { mathRandomCallCount = 0; }
  };
}

async function runTests() {
  const htmlPath = process.env.VESTORIN_APP_HTML || path.resolve(__dirname, '../vestorin_app.html');
  console.log('Testing HTML at:', htmlPath);
  let failed = 0;

  function assert(condition, message) {
    if (!condition) {
      console.error('  ✗ FAIL:', message);
      failed++;
    } else {
      console.log('  ✓ PASS:', message);
    }
  }

  // =========================================================================
  // TEST SUITE 1: CSPRNG missing (crypto.getRandomValues = undefined)
  // =========================================================================
  console.log('\n--- TEST 1: CSPRNG missing (crypto.getRandomValues = undefined) ---');
  {
    const env = runEnvironment(htmlPath, {
      crypto: { subtle: undefined } // No getRandomValues
    });
    await env.doc.fireEvent('DOMContentLoaded');

    const startBtn = env.elementsById['startStep1Btn'];
    const errBox = env.elementsById['step1CryptoErrorBox'];

    assert(startBtn.disabled === false, 'Start button initially enabled');
    assert(errBox.classList.contains('hidden'), 'Error box initially hidden');

    env.resetMathRandomCount();
    await startBtn.click();

    assert(env.getMathRandomCount() === 0, 'Math.random() was NEVER called during derivation failure');
    assert(env.elementsById['oneTimeWordsGrid'].innerHTML === '', 'No recovery phrase created in DOM grid');
    assert(!errBox.classList.contains('hidden'), 'Error box is visible to user');
    assert(errBox.textContent.includes('Key derivation error') && errBox.textContent.includes('CSPRNG unavailable'),
      'Error box explicitly displays CSPRNG unavailable: ' + errBox.textContent);
    assert(startBtn.disabled === false, 'Start button re-enabled after failure (freeze prevented)');
    assert(startBtn.textContent === 'Generate Real BIP-39 Phrase →', 'Start button text restored');
    assert(env.elementsById['screenStep2'].classList.contains('hidden'), 'UI remained on Step 1 (Step 2 remains hidden)');
  }

  // =========================================================================
  // TEST SUITE 2: CSPRNG throws exception (simulated entropy depletion / failure)
  // =========================================================================
  console.log('\n--- TEST 2: CSPRNG throws exception (simulated entropy failure) ---');
  {
    const env = runEnvironment(htmlPath, {
      crypto: {
        subtle: undefined,
        getRandomValues: () => {
          throw new Error('Hardware entropy pool exhausted');
        }
      }
    });
    await env.doc.fireEvent('DOMContentLoaded');

    const startBtn = env.elementsById['startStep1Btn'];
    const errBox = env.elementsById['step1CryptoErrorBox'];

    env.resetMathRandomCount();
    await startBtn.click();

    assert(env.getMathRandomCount() === 0, 'Math.random() was NEVER called on CSPRNG exception');
    assert(env.elementsById['oneTimeWordsGrid'].innerHTML === '', 'No recovery phrase created in DOM grid');
    assert(!errBox.classList.contains('hidden'), 'Error box is visible');
    assert(errBox.textContent.includes('Hardware entropy pool exhausted'),
      'Error box displays exact exception message: ' + errBox.textContent);
    assert(startBtn.disabled === false, 'Start button re-enabled after exception');
    assert(startBtn.textContent === 'Generate Real BIP-39 Phrase →', 'Start button text restored');
    assert(env.elementsById['screenStep2'].classList.contains('hidden'), 'UI remained on Step 1');
  }

  // =========================================================================
  // TEST SUITE 3: Insecure HTTP Context (subtle=undefined, CSPRNG available)
  // =========================================================================
  console.log('\n--- TEST 3: Insecure HTTP Context (subtle=undefined, CSPRNG working) ---');
  {
    const env = runEnvironment(htmlPath, {
      crypto: {
        subtle: undefined,
        getRandomValues: (arr) => nodeCrypto.randomFillSync(arr)
      }
    });
    await env.doc.fireEvent('DOMContentLoaded');

    const banner = env.elementsById['cryptoEnvironmentBanner'];
    assert(!banner.classList.contains('hidden'), 'Insecure HTTP context banner is displayed');
    assert(env.elementsById['cryptoBannerTitle'].textContent.includes('window.crypto.subtle unavailable'),
      'Banner title informs user about subtle unavailability');

    // Self-test
    const verifyBtn = env.elementsById['testVectorVerifyBtn'];
    await verifyBtn.click();
    const selfOut = env.elementsById['selfTestOutput'];
    assert(selfOut.innerHTML.includes('ALL 3 ASSERTIONS PASSED'), 'Pure-JS PBKDF2 self-test passed all vectors');
    assert(verifyBtn.disabled === false, 'Self-test button re-enabled after execution');

    // Start derivation
    const startBtn = env.elementsById['startStep1Btn'];
    env.resetMathRandomCount();
    await startBtn.click();

    assert(env.getMathRandomCount() === 0, 'Math.random() was NOT called during secure derivation');
    assert(env.elementsById['oneTimeWordsGrid'].innerHTML.includes('tracking-wide'),
      'Generated 24-word recovery phrase grid populated in DOM');
    assert(/^0x[0-9a-fA-F]{40}$/.test(env.elementsById['step2DerivedAddress'].textContent),
      'Derived valid EVM address: ' + env.elementsById['step2DerivedAddress'].textContent);
    assert(!env.elementsById['screenStep2'].classList.contains('hidden'), 'Navigated to Step 2');
    assert(startBtn.disabled === false, 'Start button is active');
  }

  // =========================================================================
  // TEST SUITE 4: Source code integrity audit
  // =========================================================================
  console.log('\n--- TEST 4: Source Code Security Audit ---');
  {
    const htmlCode = fs.readFileSync(htmlPath, 'utf8');
    assert(!htmlCode.includes('Math.random()'), 'Zero occurrences of Math.random() in codebase');
    assert(htmlCode.includes("throw new Error('CSPRNG unavailable"), 'Explicit CSPRNG unavailable check present');
    assert(htmlCode.includes("throw new Error(`CSPRNG failure:"), 'Explicit CSPRNG failure catch present');
  }

  console.log('\n======================================================');
  if (failed === 0) {
    console.log('✅ ALL TEST SUITES PASSED CLEANLY');
    process.exit(0);
  } else {
    console.error(`❌ ${failed} TEST(S) FAILED`);
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
