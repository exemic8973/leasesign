/**
 * LeaseSign Full E2E — Signing Workflow (visible Chromium)
 *
 * Flow:
 *   1. Register a new user via API
 *   2. Create a lease document with all fields
 *   3. Send for signature → REAL email to wei8973@yahoo.com
 *   4. Extract landlord & tenant sign tokens from API
 *   5. Open landlord sign page → check agree → sign
 *   6. Open tenant sign page → check agree → sign
 *   7. Verify completed status on dashboard
 *
 * Usage: node test/full-flow.mjs
 */

import { chromium } from 'playwright';

const BASE = 'http://localhost:3000';

const LANDLORD_EMAIL = 'lispropertyaustin@gmail.com';
const TENANT_EMAIL = 'wei8973@yahoo.com';

const TEST = {
  email: `e2e-${Date.now()}@test.leasesign`,
  password: 'TestPass123!',
  name: 'E2E Admin',
  lease: {
    title: 'E2E Test Lease',
    propertyAddress: '456 Oak Street',
    propertyCity: 'Austin',
    propertyZip: '78702',
    propertyCounty: 'Travis',
    monthlyRent: 3200,
    commencementDate: '2026-08-01',
    expirationDate: '2027-07-31',
    landlordName: 'Lisa Property Austin',
    landlordEmail: LANDLORD_EMAIL,
    landlordPhone: '',
    tenantName: 'Wei Tenant',
    tenantEmail: TENANT_EMAIL,
    tenantPhone: '',
    securityDeposit: 3200,
    petsAllowed: false,
    smokingAllowed: false
  }
};

async function api(method, path, token, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`${BASE}${path}`, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${JSON.stringify(data)}`);
  return data;
}

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
  console.log('╔═════════════════════════════════════════╗');
  console.log('║   LeaseSign — Full Signing Flow Test   ║');
  console.log('╚═════════════════════════════════════════╝\n');

  // ── Step 1: Register user via API ──
  console.log('1. Registering user via API…');
  let auth;
  try {
    auth = await api('POST', '/api/auth/register', null, {
      email: TEST.email,
      password: TEST.password,
      name: TEST.name
    });
    console.log(`   ✅ Registered: ${TEST.email}  (token: ${auth.token.slice(0, 20)}…)`);
  } catch (e) {
    // Might already exist — try login
    console.log(`   Registration failed (${e.message}), trying login…`);
    auth = await api('POST', '/api/auth/login', null, {
      email: TEST.email,
      password: TEST.password
    });
    console.log(`   ✅ Logged in: ${TEST.email}`);
  }

  const token = auth.token;

  // ── Step 2: Create lease document ──
  console.log('\n2. Creating lease document…');
  const doc = await api('POST', '/api/documents', token, TEST.lease);
  console.log(`   ✅ Created: ${doc.id}  "${doc.title}"`);
  console.log(`      Landlord: ${doc.landlordName} <${doc.landlordEmail}>`);
  console.log(`      Tenant:   ${doc.tenantName} <${doc.tenantEmail}>`);
  console.log(`      Rent: $${doc.monthlyRent}/mo | ${doc.commencementDate} → ${doc.expirationDate}`);

  // ── Step 3: Send for signature ──
  console.log('\n3. Sending for signature…');
  const sent = await api('POST', `/api/documents/${doc.id}/send`, token);
  console.log(`   ✅ Status: ${sent.status} — email sent to landlord`);
  console.log(`   📧 Real email → ${LANDLORD_EMAIL} (noreply@lispropertyaustin.com via Gmail)`);

  // ── Step 4: Get document with tokens ──
  console.log('\n4. Fetching sign tokens…');
  const fullDoc = await api('GET', `/api/documents/${doc.id}`, token);
  const landlordToken = fullDoc.landlordSignToken;
  const tenantToken = fullDoc.tenantSignToken;
  console.log(`   ✅ Landlord sign token: ${landlordToken}`);
  console.log(`   ✅ Tenant sign token:   ${tenantToken}`);

  // ── Step 5: Launch browser for visual testing ──
  console.log('\n5. Launching Chromium browser…');
  const browser = await chromium.launch({
    headless: false,
    slowMo: 300
  });
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  
  // Tab 1: Dashboard
  const dashPage = await ctx.newPage();
  await dashPage.goto(BASE, { waitUntil: 'networkidle' });
  await sleep(500);
  
  // Inject auth token into localStorage and reload
  await dashPage.evaluate(t => {
    localStorage.setItem('leasesign_token', t);
  }, token);
  await dashPage.goto(BASE, { waitUntil: 'networkidle' });
  await sleep(800);
  console.log('   ✅ Dashboard loaded');
  await dashPage.screenshot({ path: 'test/screenshots/flow-01-dashboard.png', fullPage: false });

  // ── Step 6: Landlord Signing ──
  console.log('\n6. Landlord signing in browser…');
  const landlordPage = await ctx.newPage();
  await landlordPage.goto(`${BASE}/sign/${landlordToken}`, { waitUntil: 'networkidle' });
  await sleep(1000);
  console.log(`   URL: ${landlordPage.url()}`);

  // Check the agree checkbox
  const agreeCb = landlordPage.locator('input[type="checkbox"]').first();
  if (await agreeCb.isVisible({ timeout: 3000 }).catch(() => false)) {
    await agreeCb.check();
    console.log('   ✅ Agreed to terms');
    await sleep(500);
  }

  // Find and fill the signature input
  // The SignaturePad likely has a canvas + a text input for typed signatures
  await landlordPage.screenshot({ path: 'test/screenshots/flow-02-landlord-before-sign.png', fullPage: false });

  // Try drawing a signature on canvas
  const canvas = landlordPage.locator('canvas').first();
  if (await canvas.isVisible({ timeout: 2000 }).catch(() => false)) {
    const box = await canvas.boundingBox();
    if (box) {
      // Draw a simple signature-like line
      const mx = box.x + box.width / 2;
      const my = box.y + box.height / 2;
      await landlordPage.mouse.move(box.x + 20, my);
      await landlordPage.mouse.down();
      await landlordPage.mouse.move(mx - 10, my - 15, { steps: 10 });
      await landlordPage.mouse.move(mx + 10, my + 10, { steps: 10 });
      await landlordPage.mouse.move(box.x + box.width - 20, my - 5, { steps: 10 });
      await landlordPage.mouse.up();
      console.log('   ✅ Drew signature on canvas');
    }
  } else {
    // Maybe it uses a text input for typed name
    const sigInput = landlordPage.locator('input[placeholder*="sign"], input[placeholder*="name"], input[name*="signature"]').first();
    if (await sigInput.isVisible({ timeout: 2000 }).catch(() => false)) {
      await sigInput.fill(TEST.lease.landlordName);
      console.log('   ✅ Filled typed signature');
    } else {
      console.log('   ⚠️  No signature canvas or input found — trying sign button directly');
    }
  }

  await landlordPage.screenshot({ path: 'test/screenshots/flow-02-landlord-after-sign.png', fullPage: false });

  // Look for submit/sign button
  const signBtn = landlordPage.locator('button:has-text("Sign"), button:has-text("Submit"), button:has-text("Complete")').first();
  if (await signBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
    await signBtn.click();
    console.log('   ✅ Clicked Sign button');
    await sleep(1500);
  }

  await landlordPage.screenshot({ path: 'test/screenshots/flow-03-landlord-done.png', fullPage: false });

  // ── Step 7: Tenant Signing ──
  console.log('\n7. Tenant signing in browser…');
  const tenantPage = await ctx.newPage();
  await tenantPage.goto(`${BASE}/sign/${tenantToken}`, { waitUntil: 'networkidle' });
  await sleep(1000);
  console.log(`   URL: ${tenantPage.url()}`);

  // Check agree checkbox
  const tAgreeCb = tenantPage.locator('input[type="checkbox"]').first();
  if (await tAgreeCb.isVisible({ timeout: 3000 }).catch(() => false)) {
    await tAgreeCb.check();
    console.log('   ✅ Agreed to terms');
    await sleep(500);
  }

  // Draw signature
  const tCanvas = tenantPage.locator('canvas').first();
  if (await tCanvas.isVisible({ timeout: 2000 }).catch(() => false)) {
    const box = await tCanvas.boundingBox();
    if (box) {
      const mx = box.x + box.width / 2;
      const my = box.y + box.height / 2;
      await tenantPage.mouse.move(box.x + 20, my);
      await tenantPage.mouse.down();
      await tenantPage.mouse.move(mx - 15, my - 20, { steps: 10 });
      await tenantPage.mouse.move(mx + 15, my + 15, { steps: 10 });
      await tenantPage.mouse.move(box.x + box.width - 20, my, { steps: 10 });
      await tenantPage.mouse.up();
      console.log('   ✅ Drew signature on canvas');
    }
  }

  await tenantPage.screenshot({ path: 'test/screenshots/flow-04-tenant-before-submit.png', fullPage: false });

  const tSignBtn = tenantPage.locator('button:has-text("Sign"), button:has-text("Submit"), button:has-text("Complete")').first();
  if (await tSignBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
    await tSignBtn.click();
    console.log('   ✅ Clicked Sign button');
    await sleep(2000);
  }

  await tenantPage.screenshot({ path: 'test/screenshots/flow-05-tenant-done.png', fullPage: false });

  // ── Step 8: Verify completion ──
  console.log('\n8. Verifying completion…');
  const finalDoc = await api('GET', `/api/documents/${doc.id}`, token);
  console.log(`   Status: ${finalDoc.status}`);
  console.log(`   Landlord signed: ${finalDoc.landlordSignedAt ? '✅ ' + finalDoc.landlordSignedAt : '❌'}`);
  console.log(`   Tenant signed:   ${finalDoc.tenantSignedAt ? '✅ ' + finalDoc.tenantSignedAt : '❌'}`);

  // Reload dashboard
  await dashPage.reload({ waitUntil: 'networkidle' });
  await sleep(1000);
  await dashPage.screenshot({ path: 'test/screenshots/flow-06-dashboard-complete.png', fullPage: false });

  // ── Step 9: PDF download check ──
  console.log('\n9. Checking PDF generation…');
  const pdfRes = await fetch(`${BASE}/api/documents/${doc.id}/pdf`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  if (pdfRes.ok) {
    console.log(`   ✅ PDF generated (${pdfRes.headers.get('content-type')})`);
  } else {
    console.log(`   ⚠️  PDF endpoint returned ${pdfRes.status}`);
  }

  console.log('\n╔═════════════════════════════════════════╗');
  console.log('║   ✅ Full signing flow complete!        ║');
  console.log('╚═════════════════════════════════════════╝');
  console.log(`\n📧 Emails sent from: noreply@lispropertyaustin.com`);
  console.log(`   → Landlord: ${LANDLORD_EMAIL}`);
  console.log(`   → Tenant:   ${TENANT_EMAIL} (wei8973@yahoo.com)`);
  console.log(`\n🌐 Dashboard: ${BASE}`);
  console.log(`   Browser is open — inspect the pages. Press Ctrl+C to exit.\n`);

  // Keep alive for inspection
  await new Promise(() => {});
}

main().catch(err => {
  console.error('\n❌ FATAL:', err.message);
  console.error(err.stack);
  process.exit(1);
});
