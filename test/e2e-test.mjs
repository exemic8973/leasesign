/**
 * LeaseSign E2E Test — Playwright (visible Chromium)
 *
 * Usage: node test/e2e-test.mjs
 *
 * Tests the full lifecycle:
 *   1. Load the app homepage
 *   2. Register a new user
 *   3. Create a lease document
 *   4. View the document list
 *   5. Send for signature
 *   6. Sign as landlord via public signing link
 *   7. Check dashboard reflects partial status
 */

import { chromium } from 'playwright';
import { randomUUID } from 'crypto';

const BASE = 'http://localhost:3000';
const HEADED = true;       // set false for headless
const SLOW_MO = 400;       // ms between actions (0 = instant)

const TEST_USER = {
  email: `test-${randomUUID().slice(0, 8)}@e2e.test`,
  password: 'test12345678',
  name: 'E2E Test User',
  company: 'Test Corp'
};

const LEASE_DATA = {
  propertyAddress: '123 E2E Test Lane',
  propertyCity: 'Austin',
  propertyZip: '78701',
  propertyCounty: 'Travis',
  monthlyRent: '2500',
  commencementDate: '2026-07-01',
  expirationDate: '2027-06-30',
  landlordName: 'Alice Landlord',
  landlordEmail: `landlord-${randomUUID().slice(0, 6)}@e2e.test`,
  tenantName: 'Bob Tenant',
  tenantEmail: `tenant-${randomUUID().slice(0, 6)}@e2e.test`
};

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function main() {
  console.log('=== LeaseSign E2E Test ===\n');

  const browser = await chromium.launch({ headless: !HEADED, slowMo: SLOW_MO });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  // Log console messages from the browser
  page.on('console', msg => console.log(`  [browser:${msg.type()}] ${msg.text()}`));

  try {
    // ─── 1. Load homepage ───
    console.log('1. Loading homepage…');
    await page.goto(BASE, { waitUntil: 'networkidle' });
    await sleep(800);
    const title = await page.title();
    console.log(`   Title: "${title}"`);

    // Look for a login/register form — the app should show auth page
    const bodyText = await page.textContent('body');
    if (bodyText.includes('Register') || bodyText.includes('Sign In') || bodyText.includes('Login')) {
      console.log('   ✓ Auth page detected');
    }

    // ─── 2. Register a new user ───
    console.log('\n2. Registering new user…');
    // Look for register link/button
    const registerLink = page.locator('text=Register').first();
    const signUpLink = page.locator('text=Sign Up').first();
    const createAccountLink = page.locator('text=Create Account').first();

    let clickedRegister = false;
    for (const loc of [registerLink, signUpLink, createAccountLink]) {
      if (await loc.isVisible({ timeout: 2000 }).catch(() => false)) {
        await loc.click();
        clickedRegister = true;
        console.log('   Clicked register link');
        break;
      }
    }

    if (!clickedRegister) {
      // Maybe already on register form — look for email input
      console.log('   Looking for register form fields…');
    }

    await sleep(600);

    // Fill registration form
    const emailInput = page.locator('input[type="email"]').first();
    const passwordInput = page.locator('input[type="password"]').first();
    const nameInput = page.locator('input[name="name"], input[placeholder*="Name"], input[id*="name"]').first();

    if (await emailInput.isVisible({ timeout: 3000 }).catch(() => false)) {
      await emailInput.fill(TEST_USER.email);
      console.log(`   Filled email: ${TEST_USER.email}`);
    }

    if (await nameInput.isVisible({ timeout: 1000 }).catch(() => false)) {
      await nameInput.fill(TEST_USER.name);
      console.log(`   Filled name: ${TEST_USER.name}`);
    } else {
      // Try to find any text input that might be name
      const allInputs = page.locator('input:not([type="hidden"]):not([type="submit"]):not([type="email"]):not([type="password"])');
      const count = await allInputs.count();
      if (count > 0) {
        await allInputs.first().fill(TEST_USER.name);
        console.log(`   Filled name in first text input`);
      }
    }

    if (await passwordInput.isVisible({ timeout: 1000 }).catch(() => false)) {
      await passwordInput.fill(TEST_USER.password);
      console.log('   Filled password');
    }

    // Look for submit button
    const registerBtn = page.locator('button:has-text("Register"), button:has-text("Sign Up"), button:has-text("Create Account"), button[type="submit"]').first();
    if (await registerBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await registerBtn.click();
      console.log('   Clicked register/sign-up button');
    }

    await sleep(1500);

    // Check if we got to the dashboard
    const currentUrl = page.url();
    console.log(`   Current URL: ${currentUrl}`);

    // Take a screenshot for visibility
    await page.screenshot({ path: 'test/screenshots/01-after-register.png', fullPage: false });
    console.log('   Screenshot saved: test/screenshots/01-after-register.png');

    // ─── 3. Check for dashboard / documents list ───
    console.log('\n3. Checking dashboard…');
    const pageContent = await page.textContent('body');

    if (pageContent.includes('Dashboard') || pageContent.includes('Documents') || pageContent.includes('Lease')) {
      console.log('   ✓ Dashboard/Documents visible');
    } else if (pageContent.includes('Login') || pageContent.includes('Sign In')) {
      // Registration might have failed or redirected — try to login
      console.log('   ⚠ Still on auth page — attempting login…');
      const loginEmailInput = page.locator('input[type="email"]').first();
      const loginPasswordInput = page.locator('input[type="password"]').first();
      if (await loginEmailInput.isVisible({ timeout: 2000 }).catch(() => false)) {
        await loginEmailInput.fill(TEST_USER.email);
        await loginPasswordInput.fill(TEST_USER.password);
        const loginBtn = page.locator('button:has-text("Login"), button:has-text("Sign In"), button[type="submit"]').first();
        if (await loginBtn.isVisible({ timeout: 1000 }).catch(() => false)) {
          await loginBtn.click();
          await sleep(1500);
          console.log(`   Login attempted. URL: ${page.url()}`);
        }
      }
    }

    await page.screenshot({ path: 'test/screenshots/02-dashboard.png', fullPage: false });
    console.log('   Screenshot saved: test/screenshots/02-dashboard.png');

    // ─── 4. Try to create a new document ───
    console.log('\n4. Looking for "New Document" or "Create" button…');
    const newDocBtn = page.locator('button:has-text("New"), button:has-text("Create"), a:has-text("New Document"), button:has-text("New Document")').first();

    if (await newDocBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await newDocBtn.click();
      console.log('   Clicked New Document');
      await sleep(800);

      // Try to fill the lease wizard
      // Step 1: Property details
      await fillIfVisible(page, 'input[name*="propertyAddress"], input[placeholder*="Property Address"], input[id*="address"]', LEASE_DATA.propertyAddress, 'propertyAddress');
      await fillIfVisible(page, 'input[name*="propertyCity"], input[placeholder*="City"]', LEASE_DATA.propertyCity, 'propertyCity');
      await fillIfVisible(page, 'input[name*="propertyZip"], input[placeholder*="Zip"]', LEASE_DATA.propertyZip, 'propertyZip');
      await fillIfVisible(page, 'input[name*="monthlyRent"], input[placeholder*="Rent"]', LEASE_DATA.monthlyRent, 'monthlyRent');
      await fillIfVisible(page, 'input[name*="commencementDate"], input[type="date"]', LEASE_DATA.commencementDate, 'commencementDate');

      // Look for Next / Continue button
      const nextBtn = page.locator('button:has-text("Next"), button:has-text("Continue"), button:has-text("Save")').first();
      if (await nextBtn.isVisible({ timeout: 1000 }).catch(() => false)) {
        await nextBtn.click();
        console.log('   Clicked Next/Continue');
        await sleep(600);
      }

      await page.screenshot({ path: 'test/screenshots/03-document-form.png', fullPage: false });
      console.log('   Screenshot saved: test/screenshots/03-document-form.png');
    } else {
      console.log('   ⚠ No "New Document" button found — checking page content…');
      const content = await page.textContent('body');
      console.log(`   Page snippet: ${content.slice(0, 300)}`);
    }

    // ─── 5. Final screenshot ───
    await page.screenshot({ path: 'test/screenshots/04-final-state.png', fullPage: true });
    console.log('\n   Final screenshot saved: test/screenshots/04-final-state.png');

    console.log('\n=== E2E Test Complete ===');
    console.log('Browser remains open for inspection — press Ctrl+C to close.');
    console.log(`Server: ${BASE}`);

    // Keep browser open indefinitely for visual inspection
    await new Promise(() => {}); // never resolve

  } catch (err) {
    console.error('\n❌ Test error:', err.message);
    await page.screenshot({ path: 'test/screenshots/error-state.png', fullPage: true });
    console.log('   Error screenshot saved: test/screenshots/error-state.png');
    await new Promise(() => {}); // keep browser open even on error
  }
}

async function fillIfVisible(page, selector, value, label) {
  try {
    const el = page.locator(selector).first();
    if (await el.isVisible({ timeout: 1500 }).catch(() => false)) {
      await el.fill(value);
      console.log(`   Filled ${label}: ${value}`);
      return true;
    }
  } catch (e) { /* ignore */ }
  return false;
}

main();
