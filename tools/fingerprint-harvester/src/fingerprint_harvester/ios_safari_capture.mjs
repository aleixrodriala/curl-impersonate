import {execFileSync} from "node:child_process";
import {writeFile} from "node:fs/promises";
import {parseArgs} from "node:util";

import {getSimulator} from "appium-ios-simulator";
import {createRemoteDebugger} from "appium-remote-debugger";

const {values} = parseArgs({
  options: {
    udid: {type: "string"},
    "platform-version": {type: "string"},
    "device-type": {type: "string", default: "iPhone"},
    "tls-url": {type: "string"},
    "http3-url": {type: "string"},
    output: {type: "string"},
  },
});

for (const name of ["udid", "platform-version", "tls-url", "http3-url", "output"]) {
  if (!values[name]) {
    throw new Error(`Missing required --${name}`);
  }
}

const delay = (milliseconds) =>
  new Promise((resolve) => setTimeout(resolve, milliseconds));

async function retry(attempts, operation) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      if (attempt < attempts) {
        await delay(attempt * 500);
      }
    }
  }
  throw lastError;
}

function pageKeys(page) {
  const parts = String(page.id).split(".").map((part) => Number.parseInt(part, 10));
  if (parts.length !== 2 || parts.some((part) => Number.isNaN(part))) {
    throw new Error(`Unexpected WebKit page identifier: ${page.id}`);
  }
  return parts;
}

async function selectPage(remoteDebugger, url) {
  const pages = await retry(10, async () => {
    const candidates = await remoteDebugger.selectApp(url);
    if (candidates.length === 0) {
      throw new Error(`MobileSafari did not expose ${url}`);
    }
    return candidates;
  });
  const page =
    pages.find((candidate) => candidate.url === url) ??
    pages.find((candidate) => candidate.url.startsWith(url));
  if (!page) {
    throw new Error(`MobileSafari page was not found for ${url}`);
  }
  await remoteDebugger.selectPage(...pageKeys(page));
}

async function readJsonBody(remoteDebugger) {
  return await retry(30, async () => {
    const body = await remoteDebugger.executeAtom("execute_script", [
      "return document.body ? document.body.innerText : '';",
      [],
    ]);
    const payload = JSON.parse(String(body));
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new Error("Collector response was not a JSON object");
    }
    return payload;
  });
}

function mobileSafariBuild(udid) {
  try {
    const payload = execFileSync(
      "xcrun",
      ["simctl", "listapps", udid, "--json"],
      {encoding: "utf8"},
    );
    const result = JSON.parse(payload);
    const apps = result.apps ?? result;
    const safari = apps["com.apple.mobilesafari"] ??
      Object.values(apps).find((app) => app.CFBundleIdentifier === "com.apple.mobilesafari");
    return String(safari?.CFBundleVersion ?? "");
  } catch {
    return "";
  }
}

async function main() {
  const simulator = await getSimulator(values.udid);
  const socketPath = await simulator.getWebInspectorSocket();
  if (!socketPath) {
    throw new Error("The iOS Simulator did not expose a Web Inspector socket");
  }

  try {
    execFileSync("xcrun", [
      "simctl",
      "terminate",
      values.udid,
      "com.apple.mobilesafari",
    ]);
  } catch {
    // MobileSafari may not be running before the first sample.
  }

  await retry(5, async () => await simulator.openUrl(values["tls-url"]));
  const remoteDebugger = createRemoteDebugger(
    {
      bundleId: "com.apple.mobilesafari",
      isSafari: true,
      platformVersion: values["platform-version"],
      socketPath,
      garbageCollectOnExecute: false,
      pageReadyTimeout: 30000,
      pageLoadMs: 60000,
      targetCreationTimeoutMs: 120000,
    },
    false,
  );

  try {
    await retry(10, async () => {
      const applications = await remoteDebugger.connect(60000);
      if (Object.keys(applications).length === 0) {
        await remoteDebugger.disconnect();
        throw new Error("WebKit returned no connected applications");
      }
    });
    await selectPage(remoteDebugger, values["tls-url"]);
    const tlsPayload = await readJsonBody(remoteDebugger);
    const browserData = await remoteDebugger.executeAtom("execute_script", [
      "return {userAgent: navigator.userAgent, platform: navigator.platform, " +
        "language: navigator.language};",
      [],
    ]);

    let http3Payload = null;
    for (let attempt = 0; attempt < 6; attempt += 1) {
      await remoteDebugger.navToUrl(values["http3-url"]);
      const candidate = await readJsonBody(remoteDebugger);
      if (candidate.protocol === "http3") {
        http3Payload = candidate;
        break;
      }
    }

    const versionMatch = String(browserData.userAgent).match(/Version\/([0-9.]+)/);
    const version = versionMatch?.[1] ?? values["platform-version"];
    const sample = {
      captured_at: new Date().toISOString(),
      browser: {
        version,
        browser_version: version,
        build: mobileSafariBuild(values.udid),
        user_agent: browserData.userAgent,
        user_agent_data: null,
        platform: browserData.platform,
        language: browserData.language,
        mode: "headful",
      },
      tls_http2: tlsPayload,
      http3: http3Payload,
      launch: {
        mode: "headful",
        automation: "webkit-remote-debugger",
        simulator_udid: values.udid,
        collector_navigation: "simctl-and-webkit-inspector",
      },
      source_urls: {
        tls_http2: values["tls-url"],
        http3: values["http3-url"],
      },
    };
    await writeFile(values.output, JSON.stringify(sample, null, 2));
  } finally {
    try {
      await remoteDebugger.disconnect();
    } catch {
      // Preserve the original capture error when connection setup was incomplete.
    }
  }
}

await main();
